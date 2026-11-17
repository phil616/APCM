#include "SigningCredentialStore.h"
#include "../common/WinError.h"
#include <Windows.h>
#include <wincred.h>
#include <QScopeGuard>

namespace certmgr::platform::windows {
tl::expected<QByteArray, domain::AppError> SigningCredentialStore::read(const QString &target)
{
    PCREDENTIALW credential = nullptr;
    if (!CredReadW(reinterpret_cast<LPCWSTR>(target.utf16()), CRED_TYPE_GENERIC, 0, &credential)) {
        const DWORD error = GetLastError();
        if (error == ERROR_NOT_FOUND) return QByteArray{};
        return tl::unexpected(winError(domain::ErrorCategory::Permission, QStringLiteral("signing.secret_read"), error,
            QStringLiteral("无法读取 Windows 凭据管理器中的签发 Token。")));
    }
    const auto cleanup = qScopeGuard([&] {
        if (credential->CredentialBlob) SecureZeroMemory(credential->CredentialBlob, credential->CredentialBlobSize);
        CredFree(credential);
    });
    return QByteArray(reinterpret_cast<const char *>(credential->CredentialBlob), credential->CredentialBlobSize);
}
tl::expected<void, domain::AppError> SigningCredentialStore::write(const QString &target, const QByteArray &token)
{
    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = const_cast<LPWSTR>(reinterpret_cast<LPCWSTR>(target.utf16()));
    credential.UserName = const_cast<LPWSTR>(L"APCM Independent Signing");
    credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char *>(token.constData()));
    credential.CredentialBlobSize = static_cast<DWORD>(token.size());
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    if (!CredWriteW(&credential, 0)) return tl::unexpected(winError(domain::ErrorCategory::Permission,
        QStringLiteral("signing.secret_write"), GetLastError(), QStringLiteral("无法安全保存签发 Token。")));
    return {};
}
tl::expected<void, domain::AppError> SigningCredentialStore::remove(const QString &target)
{
    if (!CredDeleteW(reinterpret_cast<LPCWSTR>(target.utf16()), CRED_TYPE_GENERIC, 0)) {
        const DWORD error = GetLastError();
        if (error != ERROR_NOT_FOUND) return tl::unexpected(winError(domain::ErrorCategory::Permission,
            QStringLiteral("signing.secret_remove"), error, QStringLiteral("无法删除签发 Token。")));
    }
    return {};
}
}
