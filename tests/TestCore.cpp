#include "services/TemplateService.h"
#include "app/SingleInstanceGuard.h"
#include "persistence/SecureBuffer.h"
#include "persistence/SqlCipherVault.h"
#include "platform/windows/certificate_store/WindowsCertificateStore.h"
#include "platform/windows/cert_enroll/WindowsCertEnrollBackend.h"

#include <QtTest>
#include <QFile>
#include <QSignalSpy>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <QUuid>
#include <sodium.h>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <ncrypt.h>
#include <wincrypt.h>

class TestCore final : public QObject {
    Q_OBJECT

private slots:
    void initTestCase()
    {
        QVERIFY(sodium_init() >= 0);
    }

    void deviceTemplateEnforcesTpmInvariant()
    {
        certmgr::services::TemplateService service;
        const auto templates = service.builtInTemplates();
        const auto found = std::find_if(templates.cbegin(), templates.cend(), [](const auto &value) {
            return value.id == QStringLiteral("windows-device-mtls");
        });
        QVERIFY(found != templates.cend());
        QCOMPARE(found->scope, certmgr::domain::StoreScope::Machine);
        QCOMPARE(found->key.provider, QStringLiteral("Microsoft Platform Crypto Provider"));
        QVERIFY(found->key.hardwareRequired);
        QVERIFY(!found->key.exportable);
        QVERIFY(found->extendedKeyUsage.contains(QStringLiteral("1.3.6.1.5.5.7.3.2")));
    }

    void rejectsExportableHardwareTemplate()
    {
        certmgr::services::TemplateService service;
        auto value = service.builtInTemplates().front();
        value.subject[QStringLiteral("CN")].source = certmgr::domain::FieldSource::Fixed;
        value.subject[QStringLiteral("CN")].value = QStringLiteral("WIN-LAPTOP-001");
        value.key.exportable = true;
        const auto result = service.resolveAndValidate(value);
        QVERIFY(!result.has_value());
        QCOMPARE(result.error().code, QStringLiteral("template.tpm_exportable"));
    }

    void secureBufferMovesWithoutCopying()
    {
        certmgr::persistence::SecureBuffer first(QByteArray("top-secret"));
        const auto *address = first.data();
        certmgr::persistence::SecureBuffer second(std::move(first));
        QCOMPARE(second.data(), address);
        QVERIFY(first.isEmpty());
        QCOMPARE(second.copy(), QByteArray("top-secret"));
    }

    void secondApplicationInstanceActivatesPrimary()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString lockPath = directory.filePath(QStringLiteral("apcm-instance.lock"));
        const QString serverName = QStringLiteral("AltasCI.APCM.Test.%1")
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));

        certmgr::app::SingleInstanceGuard primary(lockPath, serverName);
        QString message;
        QCOMPARE(static_cast<int>(primary.start(&message)),
                 static_cast<int>(certmgr::app::SingleInstanceGuard::Role::Primary));
        QVERIFY2(message.isEmpty(), qPrintable(message));
        QSignalSpy activationSpy(&primary,
            &certmgr::app::SingleInstanceGuard::activationRequested);

        certmgr::app::SingleInstanceGuard secondary(lockPath, serverName);
        QCOMPARE(static_cast<int>(secondary.start(&message)),
                 static_cast<int>(certmgr::app::SingleInstanceGuard::Role::Secondary));
        QTRY_COMPARE_WITH_TIMEOUT(activationSpy.count(), 1, 2000);
    }

    void currentUserStoreCanBeEnumerated()
    {
        certmgr::platform::windows::WindowsCertificateStore store;
        const auto result = store.listCertificates({certmgr::domain::StoreScope::User,
                                                     certmgr::domain::StoreRole::Personal, {}});
        QVERIFY2(result.has_value(), result ? "" : qPrintable(result.error().message));
    }

    void realCngCsrAndResponseAssociationWhenRequested()
    {
        if (qEnvironmentVariable("CERTMGR_TEST_ENROLLMENT") != QStringLiteral("1"))
            QSKIP("Set CERTMGR_TEST_ENROLLMENT=1 to run the Windows CNG enrollment integration test.");

        certmgr::services::TemplateService service;
        auto certificateTemplate = service.builtInTemplates().back();
        if (qEnvironmentVariable("CERTMGR_TEST_TPM") == QStringLiteral("1")) {
            certificateTemplate.key.provider = QStringLiteral("Microsoft Platform Crypto Provider");
            certificateTemplate.key.hardwareRequired = true;
            certificateTemplate.key.exportable = false;
            certificateTemplate.key.bits = 2048;
        }
        certificateTemplate.subject[QStringLiteral("CN")] = {
            certmgr::domain::FieldSource::UserInput,
            QStringLiteral("apcm-enrollment-smoke.local"), {}, true};
        certificateTemplate.dnsSans = {QStringLiteral("apcm-enrollment-smoke.local")};
        certificateTemplate.ipSans = {QStringLiteral("192.0.2.10"), QStringLiteral("2001:db8::10")};
        certificateTemplate.uriSans = {QStringLiteral("spiffe://apcm.test/enrollment")};
        certificateTemplate.upnSans = {QStringLiteral("apcm-smoke@example.test")};
        certificateTemplate.keyUsage = {QStringLiteral("digitalSignature"),
                                        QStringLiteral("keyEncipherment")};
        certificateTemplate.extendedKeyUsage = {QStringLiteral("1.3.6.1.5.5.7.3.2"),
                                                QStringLiteral("1.3.6.1.5.5.7.3.1")};
        certificateTemplate.friendlyName = QStringLiteral("APCM CNG enrollment smoke");
        const auto resolved = service.resolveAndValidate(certificateTemplate);
        QVERIFY2(resolved.has_value(), resolved ? "" : qPrintable(resolved.error().message));

        certmgr::platform::windows::WindowsCertEnrollBackend enrollment;
        const auto generated = enrollment.createPkcs10(*resolved);
        QVERIFY2(generated.has_value(), generated ? "" : qPrintable(generated.error().message));
        QVERIFY(!generated->csrBase64.isEmpty());
        QVERIFY(!generated->csrSha256.isEmpty());
        QVERIFY(!generated->publicKeySha256.isEmpty());
        QVERIFY(!generated->keyContainerName.isEmpty());

        NCRYPT_PROV_HANDLE providerHandle = 0;
        NCRYPT_KEY_HANDLE keyHandle = 0;
        QString installedCertificateId;
        const auto cleanup = qScopeGuard([&] {
            if (!installedCertificateId.isEmpty()) {
                certmgr::platform::windows::WindowsCertificateStore cleanupStore;
                static_cast<void>(cleanupStore.removeCertificate(installedCertificateId));
            }
            if (keyHandle) NCryptDeleteKey(keyHandle, 0);
            if (providerHandle) NCryptFreeObject(providerHandle);
        });
        QCOMPARE(NCryptOpenStorageProvider(&providerHandle,
            reinterpret_cast<LPCWSTR>(generated->providerName.utf16()), 0), ERROR_SUCCESS);
        QCOMPARE(NCryptOpenKey(providerHandle, &keyHandle,
            reinterpret_cast<LPCWSTR>(generated->keyContainerName.utf16()), 0, 0), ERROR_SUCCESS);

        const QString subjectText = QStringLiteral("CN=apcm-enrollment-smoke.local, O=AltasCI");
        DWORD subjectSize = 0;
        QVERIFY(CertStrToNameW(X509_ASN_ENCODING,
            reinterpret_cast<LPCWSTR>(subjectText.utf16()), CERT_X500_NAME_STR,
            nullptr, nullptr, &subjectSize, nullptr));
        QByteArray subjectBytes(static_cast<qsizetype>(subjectSize), Qt::Uninitialized);
        QVERIFY(CertStrToNameW(X509_ASN_ENCODING,
            reinterpret_cast<LPCWSTR>(subjectText.utf16()), CERT_X500_NAME_STR,
            nullptr, reinterpret_cast<BYTE *>(subjectBytes.data()), &subjectSize, nullptr));
        CERT_NAME_BLOB subject{subjectSize,
            reinterpret_cast<BYTE *>(subjectBytes.data())};
        CRYPT_KEY_PROV_INFO providerInfo{};
        providerInfo.pwszContainerName = reinterpret_cast<LPWSTR>(
            const_cast<ushort *>(generated->keyContainerName.utf16()));
        providerInfo.pwszProvName = reinterpret_cast<LPWSTR>(
            const_cast<ushort *>(generated->providerName.utf16()));
        providerInfo.dwProvType = 0;
        providerInfo.dwKeySpec = 0;
        SYSTEMTIME start{};
        SYSTEMTIME end{};
        GetSystemTime(&start);
        end = start;
        ++end.wYear;
        PCCERT_CONTEXT rawCertificate = CertCreateSelfSignCertificate(
            keyHandle, &subject, 0, &providerInfo, nullptr, &start, &end, nullptr);
        QVERIFY2(rawCertificate != nullptr, qPrintable(QStringLiteral("CertCreateSelfSignCertificate: %1")
            .arg(GetLastError())));
        const auto certificateCleanup = qScopeGuard([&] { CertFreeCertificateContext(rawCertificate); });
        const QByteArray certificateDer(reinterpret_cast<const char *>(rawCertificate->pbCertEncoded),
                                        static_cast<qsizetype>(rawCertificate->cbCertEncoded));
        const auto installed = enrollment.installResponse(certificateDer,
            certmgr::domain::StoreScope::User, generated->providerName,
            generated->keyContainerName, certificateTemplate.friendlyName);
        QVERIFY2(installed.has_value(), installed ? "" : qPrintable(installed.error().message));

        certmgr::platform::windows::WindowsCertificateStore store;
        const auto preview = store.decodeCertificate(certificateDer);
        QVERIFY(preview.has_value());
        const auto certificates = store.listCertificates({certmgr::domain::StoreScope::User,
                                                           certmgr::domain::StoreRole::Personal, {}});
        QVERIFY(certificates.has_value());
        const auto found = std::find_if(certificates->cbegin(), certificates->cend(),
            [&](const auto &item) { return item.sha256Fingerprint == preview->sha256Fingerprint; });
        QVERIFY(found != certificates->cend());
        installedCertificateId = found->id;
        QVERIFY2(found->hasPrivateKey, "The installed response is not associated with its CNG private key.");
        QCOMPARE(found->keyProvider, generated->providerName);
        QCOMPARE(found->keyContainer, generated->keyContainerName);
    }

    void pkcs12InspectionWhenFixtureProvided()
    {
        const QString fixturePath = qEnvironmentVariable("CERTMGR_TEST_P12");
        if (fixturePath.isEmpty()) QSKIP("No external P12 fixture configured.");
        QFile fixture(fixturePath);
        QVERIFY(fixture.open(QIODevice::ReadOnly));
        const QByteArray contents = fixture.readAll();
        certmgr::platform::windows::WindowsCertificateStore store;
        QVERIFY(store.isPkcs12(contents));
        const auto wrongPassword = store.inspectPkcs12(contents, QStringLiteral("incorrect-password"));
        QVERIFY(!wrongPassword.has_value());
        const auto inspected = store.inspectPkcs12(contents, qEnvironmentVariable("CERTMGR_TEST_P12_PASSWORD"));
        QVERIFY2(inspected.has_value(), inspected ? "" : qPrintable(inspected.error().message));
        QCOMPARE(inspected->size(), size_t{1});
        QVERIFY(inspected->front().subject.contains(QStringLiteral("APCM P12 Smoke")));
    }

    void vaultRoundTripUsesEnvelopeKey()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        certmgr::persistence::SqlCipherVault vault(directory.path());
        QVERIFY(vault.initialize(QByteArray("correct horse battery staple")).has_value());
        QVERIFY(vault.isUnlocked());
        QVERIFY(vault.append({QDateTime::currentDateTimeUtc(), QStringLiteral("TEST"),
                              QStringLiteral("fixture"), QStringLiteral("User"),
                              QStringLiteral("SUCCESS"), {}}).has_value());
        certmgr::domain::EnrollmentRequest request;
        request.id = QStringLiteral("request-1");
        request.templateId = QStringLiteral("windows-user-client-auth");
        request.createdAt = QDateTime::currentDateTimeUtc();
        request.updatedAt = request.createdAt;
        request.subject = QStringLiteral("CN=test.example.com, O=AltasCI");
        request.csrSha256 = QStringLiteral("ABC123");
        request.state = certmgr::domain::EnrollmentState::CsrCreated;
        request.friendlyName = QStringLiteral("测试证书");
        request.requestedValidityDays = 730;
        request.csrText = QStringLiteral("-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----");
        QVERIFY(vault.saveEnrollmentRequest(request).has_value());
        QVERIFY(vault.saveManagedRoot({QStringLiteral("ROOT123"), QStringLiteral("当前用户"),
                                      QStringLiteral("受信任的根 CA"), QStringLiteral("测试根 CA")}).has_value());
        QVERIFY(vault.saveManagedCertificate({QStringLiteral("CERT123"), QStringLiteral("当前用户"),
                                      QStringLiteral("个人"), QStringLiteral("测试客户端证书")}).has_value());
        QVERIFY(vault.saveConnection({QStringLiteral("connection-1"), QStringLiteral("manual"),
                                      QStringLiteral("手动 CA"), {}, true}).has_value());
        vault.lock();
        QVERIFY(!vault.unlock(QByteArray("wrong password value")).has_value());
        QVERIFY(vault.unlock(QByteArray("correct horse battery staple")).has_value());
        const auto requests = vault.enrollmentRequests();
        QVERIFY(requests.has_value());
        QCOMPARE(requests->size(), size_t{1});
        QCOMPARE(requests->front().friendlyName, QStringLiteral("测试证书"));
        QCOMPARE(requests->front().requestedValidityDays, 730);
        QCOMPARE(requests->front().csrText, request.csrText);
        const auto roots = vault.managedRoots();
        QVERIFY(roots.has_value());
        QCOMPARE(roots->size(), size_t{1});
        const auto managedCertificates = vault.managedCertificates();
        QVERIFY(managedCertificates.has_value());
        QCOMPARE(managedCertificates->size(), size_t{2});
        const auto connections = vault.connections();
        QVERIFY(connections.has_value());
        QCOMPARE(connections->size(), size_t{1});
        const auto auditEvents = vault.auditEvents();
        QVERIFY(auditEvents.has_value());
        QCOMPARE(auditEvents->size(), size_t{1});
        QCOMPARE(auditEvents->front().action, QStringLiteral("TEST"));
        QFile database(vault.databasePath());
        QVERIFY(database.open(QIODevice::ReadOnly));
        const QByteArray encryptedBytes = database.readAll();
        QVERIFY(!encryptedBytes.contains("test.example.com"));
        QVERIFY(!encryptedBytes.contains("BEGIN CERTIFICATE REQUEST"));
    }
};

QTEST_GUILESS_MAIN(TestCore)
#include "TestCore.moc"
