#include "platform/windows/certificate_store/WindowsCertificateStore.h"
#include "platform/windows/cert_enroll/WindowsCertEnrollBackend.h"

#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QScopeGuard>
#include <QSet>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <dpapi.h>

namespace {

QList<QByteArray> decodeCertificates(const QByteArray &contents)
{
    QList<QByteArray> certificates;
    constexpr auto beginMarker = "-----BEGIN CERTIFICATE-----";
    constexpr auto endMarker = "-----END CERTIFICATE-----";
    qsizetype offset = 0;
    while (true) {
        const qsizetype begin = contents.indexOf(beginMarker, offset);
        if (begin < 0) break;
        const qsizetype bodyStart = begin + QByteArrayView(beginMarker).size();
        const qsizetype end = contents.indexOf(endMarker, bodyStart);
        if (end < 0) return {};
        const QByteArray decoded = QByteArray::fromBase64(contents.mid(bodyStart, end - bodyStart));
        if (decoded.isEmpty()) return {};
        certificates.append(decoded);
        offset = end + QByteArrayView(endMarker).size();
    }
    if (certificates.isEmpty() && !contents.isEmpty()) certificates.append(contents);
    return certificates;
}

int fail(const DWORD error) { return static_cast<int>(error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : error); }

QStringList jsonStrings(const QJsonValue &value)
{
    QStringList result;
    for (const QJsonValue &item : value.toArray()) {
        const QString text = item.toString().trimmed();
        if (!text.isEmpty()) result.append(text);
    }
    return result;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    const QStringList arguments = app.arguments();
    const int commandIndex = arguments.indexOf(QStringLiteral("--command"));
    const int inputIndex = arguments.indexOf(QStringLiteral("--input"));
    const int idIndex = arguments.indexOf(QStringLiteral("--id"));
    const int fingerprintIndex = arguments.indexOf(QStringLiteral("--sha256"));
    const int roleIndex = arguments.indexOf(QStringLiteral("--role"));
    const int secretIndex = arguments.indexOf(QStringLiteral("--secret"));
    const int providerIndex = arguments.indexOf(QStringLiteral("--provider"));
    const int containerIndex = arguments.indexOf(QStringLiteral("--container"));
    const int friendlyIndex = arguments.indexOf(QStringLiteral("--friendly-b64"));
    const int outputIndex = arguments.indexOf(QStringLiteral("--output"));
    if (commandIndex < 0 || commandIndex + 1 >= arguments.size()) return fail(ERROR_INVALID_PARAMETER);
    const QString command = arguments.at(commandIndex + 1);
    certmgr::platform::windows::WindowsCertificateStore store;

    if (command == QStringLiteral("CREATE_MACHINE_CSR")) {
        if (inputIndex < 0 || inputIndex + 1 >= arguments.size() ||
            outputIndex < 0 || outputIndex + 1 >= arguments.size())
            return fail(ERROR_INVALID_PARAMETER);
        const QFileInfo input(arguments.at(inputIndex + 1));
        const QFileInfo output(arguments.at(outputIndex + 1));
        if (!input.exists() || !input.isFile() || input.size() > 256 * 1024 ||
            !output.exists() || !output.isFile())
            return fail(ERROR_INVALID_DATA);
        QFile file(input.absoluteFilePath());
        if (!file.open(QIODevice::ReadOnly)) return fail(ERROR_ACCESS_DENIED);
        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
            return fail(ERROR_INVALID_DATA);
        const QJsonObject value = document.object();
        certmgr::domain::CertificateTemplate certificateTemplate;
        certificateTemplate.id = QStringLiteral("apcm-machine-custom");
        certificateTemplate.name = QStringLiteral("APCM 机器证书申请");
        certificateTemplate.scope = certmgr::domain::StoreScope::Machine;
        certificateTemplate.friendlyName = value.value(QStringLiteral("friendlyName")).toString().trimmed();
        if (certificateTemplate.friendlyName.isEmpty() || certificateTemplate.friendlyName.size() > 256)
            return fail(ERROR_INVALID_DATA);
        const QJsonObject subject = value.value(QStringLiteral("subject")).toObject();
        static const QSet<QString> subjectNames{QStringLiteral("CN"), QStringLiteral("OU"),
            QStringLiteral("O"), QStringLiteral("L"), QStringLiteral("ST"), QStringLiteral("C")};
        for (auto it = subject.constBegin(); it != subject.constEnd(); ++it) {
            const QString text = it.value().toString().trimmed();
            if (!subjectNames.contains(it.key()) || text.isEmpty() || text.size() > 512)
                return fail(ERROR_INVALID_DATA);
            certificateTemplate.subject.insert(it.key(),
                {certmgr::domain::FieldSource::UserInput, text, {}, true});
        }
        if (!certificateTemplate.subject.contains(QStringLiteral("CN"))) return fail(ERROR_INVALID_DATA);
        certificateTemplate.dnsSans = jsonStrings(value.value(QStringLiteral("dnsSans")));
        certificateTemplate.ipSans = jsonStrings(value.value(QStringLiteral("ipSans")));
        certificateTemplate.uriSans = jsonStrings(value.value(QStringLiteral("uriSans")));
        certificateTemplate.upnSans = jsonStrings(value.value(QStringLiteral("upnSans")));
        certificateTemplate.keyUsage = jsonStrings(value.value(QStringLiteral("keyUsage")));
        certificateTemplate.extendedKeyUsage = jsonStrings(value.value(QStringLiteral("extendedKeyUsage")));
        const int totalNames = certificateTemplate.dnsSans.size() + certificateTemplate.ipSans.size() +
            certificateTemplate.uriSans.size() + certificateTemplate.upnSans.size();
        if (totalNames > 128) return fail(ERROR_INVALID_DATA);
        certificateTemplate.key.provider = value.value(QStringLiteral("provider")).toString();
        if (certificateTemplate.key.provider != QStringLiteral("Microsoft Software Key Storage Provider") &&
            certificateTemplate.key.provider != QStringLiteral("Microsoft Platform Crypto Provider"))
            return fail(ERROR_INVALID_PARAMETER);
        certificateTemplate.key.algorithm = QStringLiteral("RSA");
        certificateTemplate.key.bits = value.value(QStringLiteral("bits")).toInt();
        if (certificateTemplate.key.bits != 2048 && certificateTemplate.key.bits != 3072 &&
            certificateTemplate.key.bits != 4096)
            return fail(ERROR_INVALID_PARAMETER);
        certificateTemplate.key.exportable = value.value(QStringLiteral("exportable")).toBool();
        certificateTemplate.key.hardwareRequired = value.value(QStringLiteral("hardwareRequired")).toBool();
        if (certificateTemplate.key.hardwareRequired !=
                (certificateTemplate.key.provider == QStringLiteral("Microsoft Platform Crypto Provider")) ||
            (certificateTemplate.key.hardwareRequired &&
                (certificateTemplate.key.exportable || certificateTemplate.key.bits != 2048)))
            return fail(ERROR_INVALID_PARAMETER);
        certmgr::platform::windows::WindowsCertEnrollBackend enrollment;
        const auto generated = enrollment.createPkcs10(certificateTemplate);
        if (!generated) return fail(static_cast<DWORD>(generated.error().nativeCode));
        const QJsonObject result{
            {QStringLiteral("csr"), generated->csrBase64},
            {QStringLiteral("csrSha256"), generated->csrSha256},
            {QStringLiteral("publicKeySha256"), generated->publicKeySha256},
            {QStringLiteral("provider"), generated->providerName},
            {QStringLiteral("container"), generated->keyContainerName}};
        QSaveFile outputFile(output.absoluteFilePath());
        const QByteArray encoded = QJsonDocument(result).toJson(QJsonDocument::Compact);
        if (!outputFile.open(QIODevice::WriteOnly) || outputFile.write(encoded) != encoded.size() ||
            !outputFile.commit())
            return fail(ERROR_WRITE_FAULT);
        return ERROR_SUCCESS;
    }

    if (command == QStringLiteral("INSTALL_ROOT") || command == QStringLiteral("INSTALL_MACHINE_CERT")) {
        if (inputIndex < 0 || inputIndex + 1 >= arguments.size()) return fail(ERROR_INVALID_PARAMETER);
        const QFileInfo input(arguments.at(inputIndex + 1));
        if (!input.exists() || !input.isFile() || input.size() > 16 * 1024 * 1024) return fail(ERROR_INVALID_DATA);
        QFile file(input.absoluteFilePath());
        if (!file.open(QIODevice::ReadOnly)) return fail(ERROR_ACCESS_DENIED);
        const QList<QByteArray> encodedCertificates = decodeCertificates(file.readAll());
        if (encodedCertificates.isEmpty()) return fail(ERROR_INVALID_DATA);
        int roleValue = static_cast<int>(certmgr::domain::StoreRole::TrustedRoot);
        if (command == QStringLiteral("INSTALL_MACHINE_CERT")) {
            if (roleIndex < 0 || roleIndex + 1 >= arguments.size()) return fail(ERROR_INVALID_PARAMETER);
            bool roleOk = false;
            roleValue = arguments.at(roleIndex + 1).toInt(&roleOk);
            if (!roleOk || roleValue < 0 || roleValue > 3) return fail(ERROR_INVALID_PARAMETER);
        }
        const auto role = static_cast<certmgr::domain::StoreRole>(roleValue);
        if (fingerprintIndex < 0 || fingerprintIndex + 1 >= arguments.size()) return fail(ERROR_INVALID_PARAMETER);
        const QStringList expectedFingerprints = arguments.at(fingerprintIndex + 1).split(QLatin1Char(';'), Qt::SkipEmptyParts);
        if (expectedFingerprints.size() != encodedCertificates.size()) return fail(ERROR_INVALID_DATA);
        for (qsizetype index = 0; index < encodedCertificates.size(); ++index) {
            auto preview = store.decodeCertificate(encodedCertificates.at(index));
            if (!preview || preview->sha256Fingerprint.compare(expectedFingerprints.at(index), Qt::CaseInsensitive) != 0 ||
                (role == certmgr::domain::StoreRole::TrustedRoot && !preview->isCA))
                return fail(ERROR_INVALID_DATA);
        }
        for (const auto &encoded : encodedCertificates) {
            auto result = store.installCertificate(encoded,
                {certmgr::domain::StoreScope::Machine, role, {}});
            if (!result) return fail(static_cast<DWORD>(result.error().nativeCode));
        }
        return ERROR_SUCCESS;
    }

    if (command == QStringLiteral("IMPORT_MACHINE_PFX")) {
        if (inputIndex < 0 || inputIndex + 1 >= arguments.size() ||
            secretIndex < 0 || secretIndex + 1 >= arguments.size() ||
            roleIndex < 0 || roleIndex + 1 >= arguments.size()) return fail(ERROR_INVALID_PARAMETER);
        bool roleOk = false;
        const int roleValue = arguments.at(roleIndex + 1).toInt(&roleOk);
        if (!roleOk || roleValue < 0 || roleValue > 3) return fail(ERROR_INVALID_PARAMETER);
        const QFileInfo input(arguments.at(inputIndex + 1));
        const QFileInfo secret(arguments.at(secretIndex + 1));
        if (!input.exists() || !input.isFile() || input.size() > 16 * 1024 * 1024 ||
            !secret.exists() || !secret.isFile() || secret.size() > 64 * 1024) return fail(ERROR_INVALID_DATA);
        QFile inputFile(input.absoluteFilePath());
        QFile secretFile(secret.absoluteFilePath());
        if (!inputFile.open(QIODevice::ReadOnly) || !secretFile.open(QIODevice::ReadOnly)) return fail(ERROR_ACCESS_DENIED);
        QByteArray protectedBytes = secretFile.readAll();
        const auto protectedBytesCleanup = qScopeGuard([&] { protectedBytes.fill('\0'); });
        DATA_BLOB protectedData{static_cast<DWORD>(protectedBytes.size()),
            reinterpret_cast<BYTE *>(protectedBytes.data())};
        DATA_BLOB plain{};
        if (!CryptUnprotectData(&protectedData, nullptr, nullptr, nullptr, nullptr,
                                CRYPTPROTECT_UI_FORBIDDEN, &plain)) return fail(GetLastError());
        const auto plainCleanup = qScopeGuard([&] {
            if (plain.pbData) {
                SecureZeroMemory(plain.pbData, plain.cbData);
                LocalFree(plain.pbData);
            }
        });
        QString password = QString::fromWCharArray(reinterpret_cast<const wchar_t *>(plain.pbData),
            static_cast<qsizetype>(plain.cbData / sizeof(wchar_t)));
        while (!password.isEmpty() && password.back() == QChar()) password.chop(1);
        const auto result = store.importPkcs12(inputFile.readAll(), password,
            {certmgr::domain::StoreScope::Machine,
             static_cast<certmgr::domain::StoreRole>(roleValue), {}});
        password.fill(QChar());
        return result ? ERROR_SUCCESS : fail(static_cast<DWORD>(result.error().nativeCode));
    }

    if (command == QStringLiteral("INSTALL_MACHINE_RESPONSE")) {
        if (inputIndex < 0 || inputIndex + 1 >= arguments.size() ||
            fingerprintIndex < 0 || fingerprintIndex + 1 >= arguments.size() ||
            providerIndex < 0 || providerIndex + 1 >= arguments.size() ||
            containerIndex < 0 || containerIndex + 1 >= arguments.size() ||
            friendlyIndex < 0 || friendlyIndex + 1 >= arguments.size())
            return fail(ERROR_INVALID_PARAMETER);
        const QFileInfo input(arguments.at(inputIndex + 1));
        if (!input.exists() || !input.isFile() || input.size() > 16 * 1024 * 1024)
            return fail(ERROR_INVALID_DATA);
        QFile file(input.absoluteFilePath());
        if (!file.open(QIODevice::ReadOnly)) return fail(ERROR_ACCESS_DENIED);
        const QList<QByteArray> encodedCertificates = decodeCertificates(file.readAll());
        if (encodedCertificates.size() != 1) return fail(ERROR_INVALID_DATA);
        const QString provider = arguments.at(providerIndex + 1);
        if (provider != QStringLiteral("Microsoft Software Key Storage Provider") &&
            provider != QStringLiteral("Microsoft Platform Crypto Provider"))
            return fail(ERROR_INVALID_PARAMETER);
        const QString container = arguments.at(containerIndex + 1);
        if (container.isEmpty() || container.size() > 512) return fail(ERROR_INVALID_PARAMETER);
        const QByteArray friendlyBytes = QByteArray::fromBase64(
            arguments.at(friendlyIndex + 1).toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
        if (friendlyBytes.isNull() || friendlyBytes.size() > 1024) return fail(ERROR_INVALID_DATA);
        const QString friendlyName = QString::fromUtf8(friendlyBytes);
        auto preview = store.decodeCertificate(encodedCertificates.front());
        if (!preview || preview->sha256Fingerprint.compare(
                arguments.at(fingerprintIndex + 1), Qt::CaseInsensitive) != 0)
            return fail(ERROR_INVALID_DATA);
        certmgr::platform::windows::WindowsCertEnrollBackend enrollment;
        const auto result = enrollment.installResponse(encodedCertificates.front(),
            certmgr::domain::StoreScope::Machine, provider, container, friendlyName);
        return result ? ERROR_SUCCESS : fail(static_cast<DWORD>(result.error().nativeCode));
    }

    if (command == QStringLiteral("REMOVE_ROOT") || command == QStringLiteral("REMOVE_MACHINE_CERT")) {
        if (idIndex < 0 || idIndex + 1 >= arguments.size()) return fail(ERROR_INVALID_PARAMETER);
        const QString id = arguments.at(idIndex + 1);
        if (id.size() > 256) return fail(ERROR_INVALID_DATA);
        auto result = store.removeCertificate(id);
        return result ? ERROR_SUCCESS : fail(static_cast<DWORD>(result.error().nativeCode));
    }

    return fail(ERROR_INVALID_FUNCTION);
}
