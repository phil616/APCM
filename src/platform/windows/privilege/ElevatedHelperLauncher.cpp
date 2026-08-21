#include "ElevatedHelperLauncher.h"

#include "../common/WinError.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFileInfo>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QScopeGuard>
#include <QTemporaryFile>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <dpapi.h>
#include <shellapi.h>

namespace certmgr::platform::windows {
namespace {

QString quoteWindowsArgument(const QString &argument)
{
    QString quoted;
    quoted.reserve(argument.size() + 2);
    quoted.append(QLatin1Char('"'));
    qsizetype backslashes = 0;
    for (const QChar character : argument) {
        if (character == QLatin1Char('\\')) {
            ++backslashes;
            continue;
        }
        if (character == QLatin1Char('"')) {
            quoted.append(QString(backslashes * 2 + 1, QLatin1Char('\\')));
            quoted.append(character);
        } else {
            quoted.append(QString(backslashes, QLatin1Char('\\')));
            quoted.append(character);
        }
        backslashes = 0;
    }
    quoted.append(QString(backslashes * 2, QLatin1Char('\\')));
    quoted.append(QLatin1Char('"'));
    return quoted;
}

} // namespace

tl::expected<platform::GeneratedEnrollment, domain::AppError>
ElevatedHelperLauncher::createMachinePkcs10(
    const domain::CertificateTemplate &certificateTemplate) const
{
    QJsonObject subject;
    for (auto it = certificateTemplate.subject.cbegin(); it != certificateTemplate.subject.cend(); ++it)
        subject.insert(it.key(), it->value);
    const QJsonObject root{
        {QStringLiteral("subject"), subject},
        {QStringLiteral("dnsSans"), QJsonArray::fromStringList(certificateTemplate.dnsSans)},
        {QStringLiteral("ipSans"), QJsonArray::fromStringList(certificateTemplate.ipSans)},
        {QStringLiteral("uriSans"), QJsonArray::fromStringList(certificateTemplate.uriSans)},
        {QStringLiteral("upnSans"), QJsonArray::fromStringList(certificateTemplate.upnSans)},
        {QStringLiteral("keyUsage"), QJsonArray::fromStringList(certificateTemplate.keyUsage)},
        {QStringLiteral("extendedKeyUsage"), QJsonArray::fromStringList(certificateTemplate.extendedKeyUsage)},
        {QStringLiteral("provider"), certificateTemplate.key.provider},
        {QStringLiteral("bits"), certificateTemplate.key.bits},
        {QStringLiteral("exportable"), certificateTemplate.key.exportable},
        {QStringLiteral("hardwareRequired"), certificateTemplate.key.hardwareRequired},
        {QStringLiteral("friendlyName"), certificateTemplate.friendlyName}};
    QTemporaryFile inputFile(QDir(QDir::tempPath()).filePath(QStringLiteral("apcm-machine-csr-in-XXXXXX.json")));
    QTemporaryFile outputFile(QDir(QDir::tempPath()).filePath(QStringLiteral("apcm-machine-csr-out-XXXXXX.json")));
    inputFile.setAutoRemove(true);
    outputFile.setAutoRemove(true);
    const QByteArray serialized = QJsonDocument(root).toJson(QJsonDocument::Compact);
    if (!inputFile.open() || inputFile.write(serialized) != serialized.size() || !inputFile.flush() ||
        !outputFile.open())
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Permission,
            QStringLiteral("helper.machine_csr_files"), 0,
            QStringLiteral("无法创建机器证书申请的临时交换文件。"), {}});
    const QString inputPath = QDir::toNativeSeparators(inputFile.fileName());
    const QString outputPath = QDir::toNativeSeparators(outputFile.fileName());
    inputFile.close();
    outputFile.close();
    if (auto result = runWhitelisted(QStringLiteral("CREATE_MACHINE_CSR"),
            {QStringLiteral("--input"), inputPath, QStringLiteral("--output"), outputPath}); !result)
        return tl::unexpected(result.error());
    QFile output(outputPath);
    if (!output.open(QIODevice::ReadOnly) || output.size() > 256 * 1024)
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Enrollment,
            QStringLiteral("helper.machine_csr_output"), 0,
            QStringLiteral("提权进程没有返回有效的机器证书申请。"), output.errorString()});
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(output.readAll(), &parseError);
    const QJsonObject value = document.object();
    platform::GeneratedEnrollment generated;
    generated.csrBase64 = value.value(QStringLiteral("csr")).toString();
    generated.csrSha256 = value.value(QStringLiteral("csrSha256")).toString();
    generated.publicKeySha256 = value.value(QStringLiteral("publicKeySha256")).toString();
    generated.providerName = value.value(QStringLiteral("provider")).toString();
    generated.keyContainerName = value.value(QStringLiteral("container")).toString();
    if (parseError.error != QJsonParseError::NoError || generated.csrBase64.isEmpty() ||
        generated.csrSha256.isEmpty() || generated.publicKeySha256.isEmpty() ||
        generated.providerName.isEmpty() || generated.keyContainerName.isEmpty())
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Enrollment,
            QStringLiteral("helper.machine_csr_invalid"), 0,
            QStringLiteral("提权进程返回了不完整的机器证书申请。"), parseError.errorString()});
    return generated;
}

tl::expected<void, domain::AppError>
ElevatedHelperLauncher::installMachineRoot(const QString &certificatePath,
                                           const QString &sha256Fingerprint) const
{
    return runWhitelisted(QStringLiteral("INSTALL_ROOT"),
        {QStringLiteral("--input"), QDir::toNativeSeparators(QFileInfo(certificatePath).absoluteFilePath()),
         QStringLiteral("--sha256"), sha256Fingerprint});
}

tl::expected<void, domain::AppError>
ElevatedHelperLauncher::installMachineCertificate(const QString &certificatePath,
                                                   const QString &sha256Fingerprint,
                                                   const domain::StoreRole role) const
{
    return installMachineCertificatePackage(certificatePath, {sha256Fingerprint}, role);
}

tl::expected<void, domain::AppError>
ElevatedHelperLauncher::installMachineCertificatePackage(const QString &certificatePath,
                                                          const QStringList &sha256Fingerprints,
                                                          const domain::StoreRole role) const
{
    return runWhitelisted(QStringLiteral("INSTALL_MACHINE_CERT"),
        {QStringLiteral("--input"), QDir::toNativeSeparators(QFileInfo(certificatePath).absoluteFilePath()),
         QStringLiteral("--sha256"), sha256Fingerprints.join(QLatin1Char(';')),
         QStringLiteral("--role"), QString::number(static_cast<int>(role))});
}

tl::expected<void, domain::AppError>
ElevatedHelperLauncher::importMachinePkcs12(const QString &certificatePath,
                                             const QString &password,
                                             const domain::StoreRole role) const
{
    DATA_BLOB plain{static_cast<DWORD>((password.size() + 1) * sizeof(wchar_t)),
        reinterpret_cast<BYTE *>(const_cast<ushort *>(password.utf16()))};
    DATA_BLOB protectedData{};
    if (!CryptProtectData(&plain, L"APCM P12 import", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &protectedData))
        return tl::unexpected(winError(domain::ErrorCategory::Permission,
            QStringLiteral("helper.secret_protect"), GetLastError(),
            QStringLiteral("无法保护 P12/PFX 临时密码。")));
    const auto protectedCleanup = qScopeGuard([&] {
        if (protectedData.pbData) {
            SecureZeroMemory(protectedData.pbData, protectedData.cbData);
            LocalFree(protectedData.pbData);
        }
    });
    QTemporaryFile secretFile(QDir(QDir::tempPath()).filePath(QStringLiteral("apcm-p12-secret-XXXXXX.bin")));
    secretFile.setAutoRemove(true);
    if (!secretFile.open() || secretFile.write(reinterpret_cast<const char *>(protectedData.pbData),
                                                protectedData.cbData) != protectedData.cbData) {
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Permission,
            QStringLiteral("helper.secret_file"), 0, QStringLiteral("无法创建 P12/PFX 临时凭据。"),
            secretFile.errorString()});
    }
    const QString secretPath = QDir::toNativeSeparators(secretFile.fileName());
    secretFile.close();
    return runWhitelisted(QStringLiteral("IMPORT_MACHINE_PFX"),
        {QStringLiteral("--input"), QDir::toNativeSeparators(QFileInfo(certificatePath).absoluteFilePath()),
         QStringLiteral("--secret"), secretPath,
         QStringLiteral("--role"), QString::number(static_cast<int>(role))});
}

tl::expected<void, domain::AppError>
ElevatedHelperLauncher::installMachineEnrollmentResponse(
    const QString &certificatePath, const QString &sha256Fingerprint,
    const QString &providerName, const QString &keyContainerName,
    const QString &friendlyName) const
{
    return runWhitelisted(QStringLiteral("INSTALL_MACHINE_RESPONSE"),
        {QStringLiteral("--input"), QDir::toNativeSeparators(QFileInfo(certificatePath).absoluteFilePath()),
         QStringLiteral("--sha256"), sha256Fingerprint,
         QStringLiteral("--provider"), providerName,
         QStringLiteral("--container"), keyContainerName,
         QStringLiteral("--friendly-b64"),
             QString::fromLatin1(friendlyName.toUtf8().toBase64())});
}

tl::expected<void, domain::AppError>
ElevatedHelperLauncher::runWhitelisted(const QString &command, const QStringList &arguments) const
{
    static const QSet<QString> commands{QStringLiteral("INSTALL_ROOT"), QStringLiteral("REMOVE_ROOT"),
        QStringLiteral("INSTALL_MACHINE_CERT"), QStringLiteral("IMPORT_MACHINE_PFX"),
        QStringLiteral("INSTALL_MACHINE_RESPONSE"), QStringLiteral("CREATE_MACHINE_CSR"),
        QStringLiteral("REMOVE_MACHINE_CERT")};
    if (!commands.contains(command))
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Permission,
            QStringLiteral("helper.command_rejected"), 0, QStringLiteral("不允许执行此提权命令。"), command});

    const QString helper = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("CertificateManager.Helper.exe"));
    if (!QFileInfo::exists(helper))
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Permission,
            QStringLiteral("helper.missing"), 0, QStringLiteral("缺少提权辅助程序。"), helper});
    QStringList parameterParts{QStringLiteral("--command"), quoteWindowsArgument(command)};
    for (int i = 0; i < arguments.size(); i += 2) {
        if (i + 1 >= arguments.size())
            return tl::unexpected(domain::AppError{domain::ErrorCategory::Permission,
                QStringLiteral("helper.arguments_invalid"), 0,
                QStringLiteral("提权命令参数不完整。"), command});
        parameterParts.append(arguments.at(i));
        parameterParts.append(quoteWindowsArgument(arguments.at(i + 1)));
    }
    const QString parameters = parameterParts.join(QLatin1Char(' '));
    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = L"runas";
    info.lpFile = reinterpret_cast<LPCWSTR>(helper.utf16());
    info.lpParameters = reinterpret_cast<LPCWSTR>(parameters.utf16());
    info.nShow = SW_HIDE;
    if (!ShellExecuteExW(&info))
        return tl::unexpected(winError(domain::ErrorCategory::Permission,
            QStringLiteral("helper.elevation_failed"), GetLastError(),
            QStringLiteral("管理员授权已取消或提权失败。")));
    const auto processCleanup = qScopeGuard([&] {
        if (info.hProcess) CloseHandle(info.hProcess);
    });
    if (!info.hProcess)
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Permission,
            QStringLiteral("helper.process_missing"), 0,
            QStringLiteral("无法跟踪提权辅助进程。"), {}});

    constexpr qint64 helperTimeoutMs = 5 * 60 * 1000;
    QElapsedTimer elapsed;
    elapsed.start();
    DWORD waitResult = WAIT_TIMEOUT;
    while (waitResult == WAIT_TIMEOUT && elapsed.elapsed() < helperTimeoutMs) {
        waitResult = WaitForSingleObject(info.hProcess, 100);
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 25);
    }
    if (waitResult == WAIT_TIMEOUT)
        waitResult = WaitForSingleObject(info.hProcess, 0);
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(info.hProcess, ERROR_TIMEOUT);
        WaitForSingleObject(info.hProcess, 5000);
        return tl::unexpected(winError(domain::ErrorCategory::Permission,
            QStringLiteral("helper.timeout"), ERROR_TIMEOUT,
            QStringLiteral("提权辅助进程超时，操作已终止。")));
    }
    if (waitResult == WAIT_FAILED)
        return tl::unexpected(winError(domain::ErrorCategory::Permission,
            QStringLiteral("helper.wait_failed"), GetLastError(),
            QStringLiteral("等待提权辅助进程时发生错误。")));

    DWORD exitCode = ERROR_GEN_FAILURE;
    if (!GetExitCodeProcess(info.hProcess, &exitCode))
        return tl::unexpected(winError(domain::ErrorCategory::Permission,
            QStringLiteral("helper.exit_code_failed"), GetLastError(),
            QStringLiteral("无法读取提权辅助进程结果。")));
    if (exitCode != ERROR_SUCCESS)
        return tl::unexpected(winError(domain::ErrorCategory::Permission,
            QStringLiteral("helper.operation_failed"), exitCode,
            QStringLiteral("提权后的 Windows 证书操作失败。")));
    return {};
}

} // namespace certmgr::platform::windows
