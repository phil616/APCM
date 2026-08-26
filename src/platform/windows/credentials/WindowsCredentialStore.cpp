#include "WindowsCredentialStore.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <wincred.h>

namespace certmgr::platform::windows {
namespace {

domain::AppError credentialError(const QString &code, const QString &message, const DWORD nativeCode)
{
    return {domain::ErrorCategory::Vault, code, nativeCode, message,
            QStringLiteral("Windows Credential Manager 错误：%1").arg(nativeCode)};
}

} // namespace

tl::expected<QByteArray, domain::AppError> WindowsCredentialStore::read(const QString &targetName)
{
    PCREDENTIALW credential = nullptr;
    if (!CredReadW(reinterpret_cast<LPCWSTR>(targetName.utf16()), CRED_TYPE_GENERIC, 0,
                   &credential)) {
        const DWORD error = GetLastError();
        if (error == ERROR_NOT_FOUND) return QByteArray{};
        return tl::unexpected(credentialError(QStringLiteral("credential.read"),
            QStringLiteral("无法从 Windows 凭据管理器读取 PKI 登录令牌。"), error));
    }
    const QByteArray result(reinterpret_cast<const char *>(credential->CredentialBlob),
                            static_cast<qsizetype>(credential->CredentialBlobSize));
    CredFree(credential);
    return result;
}

tl::expected<void, domain::AppError> WindowsCredentialStore::write(const QString &targetName,
                                                                    const QByteArray &secret)
{
    if (secret.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE) {
        return tl::unexpected(credentialError(QStringLiteral("credential.too_large"),
            QStringLiteral("PKI 登录令牌超过 Windows 凭据管理器允许的大小。"),
            ERROR_INSUFFICIENT_BUFFER));
    }
    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = const_cast<LPWSTR>(reinterpret_cast<LPCWSTR>(targetName.utf16()));
    credential.CredentialBlobSize = static_cast<DWORD>(secret.size());
    credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char *>(secret.constData()));
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.UserName = const_cast<LPWSTR>(L"APCM PKI-Console OAuth");
    if (!CredWriteW(&credential, 0)) {
        const DWORD error = GetLastError();
        return tl::unexpected(credentialError(QStringLiteral("credential.write"),
            QStringLiteral("无法将 PKI 登录令牌保存到 Windows 凭据管理器。"), error));
    }
    return {};
}

tl::expected<void, domain::AppError> WindowsCredentialStore::remove(const QString &targetName)
{
    if (CredDeleteW(reinterpret_cast<LPCWSTR>(targetName.utf16()), CRED_TYPE_GENERIC, 0)) return {};
    const DWORD error = GetLastError();
    if (error == ERROR_NOT_FOUND) return {};
    return tl::unexpected(credentialError(QStringLiteral("credential.delete"),
        QStringLiteral("无法从 Windows 凭据管理器删除 PKI 登录令牌。"), error));
}

} // namespace certmgr::platform::windows
