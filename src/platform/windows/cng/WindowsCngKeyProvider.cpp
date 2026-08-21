#include "WindowsCngKeyProvider.h"

#include "../common/WinError.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <ncrypt.h>

#include <QScopeGuard>

namespace certmgr::platform::windows {
namespace {

QString stringProperty(const NCRYPT_HANDLE handle, LPCWSTR name)
{
    DWORD size = 0;
    if (NCryptGetProperty(handle, name, nullptr, 0, &size, 0) != ERROR_SUCCESS || size < sizeof(wchar_t))
        return {};
    QByteArray storage(static_cast<qsizetype>(size), Qt::Uninitialized);
    if (NCryptGetProperty(handle, name, reinterpret_cast<PBYTE>(storage.data()), size, &size, 0) != ERROR_SUCCESS)
        return {};
    return QString::fromWCharArray(reinterpret_cast<const wchar_t *>(storage.constData()));
}

DWORD dwordProperty(const NCRYPT_HANDLE handle, LPCWSTR name)
{
    DWORD value = 0;
    DWORD size = 0;
    return NCryptGetProperty(handle, name, reinterpret_cast<PBYTE>(&value), sizeof(value), &size, 0) == ERROR_SUCCESS &&
            size == sizeof(value)
        ? value : 0;
}

} // namespace

bool WindowsCngKeyProvider::isTpmAvailable() const
{
    NCRYPT_PROV_HANDLE provider = 0;
    const SECURITY_STATUS status = NCryptOpenStorageProvider(&provider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (status != ERROR_SUCCESS) return false;
    NCryptFreeObject(provider);
    return true;
}

tl::expected<std::vector<domain::PrivateKeyInfo>, domain::AppError>
WindowsCngKeyProvider::listKeys()
{
    DWORD count = 0;
    NCryptProviderName *providers = nullptr;
    const SECURITY_STATUS enumStatus = NCryptEnumStorageProviders(&count, &providers, 0);
    if (enumStatus != ERROR_SUCCESS)
        return tl::unexpected(winError(domain::ErrorCategory::KeyProvider,
            QStringLiteral("cng.providers_failed"), enumStatus, QStringLiteral("无法枚举 Windows 密钥提供程序。")));
    const auto providersCleanup = qScopeGuard([&] { NCryptFreeBuffer(providers); });

    std::vector<domain::PrivateKeyInfo> keys;
    for (DWORD i = 0; i < count; ++i) {
        NCRYPT_PROV_HANDLE provider = 0;
        if (NCryptOpenStorageProvider(&provider, providers[i].pszName, 0) != ERROR_SUCCESS) continue;
        const auto providerCleanup = qScopeGuard([&] { NCryptFreeObject(provider); });

        PVOID enumState = nullptr;
        const auto stateCleanup = qScopeGuard([&] { if (enumState) NCryptFreeBuffer(enumState); });
        for (;;) {
            NCryptKeyName *keyName = nullptr;
            const SECURITY_STATUS status = NCryptEnumKeys(provider, nullptr, &keyName, &enumState, NCRYPT_SILENT_FLAG);
            if (status == NTE_NO_MORE_ITEMS) break;
            if (status != ERROR_SUCCESS) break;
            const auto keyNameCleanup = qScopeGuard([&] { NCryptFreeBuffer(keyName); });

            NCRYPT_KEY_HANDLE key = 0;
            if (NCryptOpenKey(provider, &key, keyName->pszName, keyName->dwLegacyKeySpec,
                             NCRYPT_SILENT_FLAG | (keyName->dwFlags & NCRYPT_MACHINE_KEY_FLAG)) != ERROR_SUCCESS)
                continue;
            const auto keyCleanup = qScopeGuard([&] { NCryptFreeObject(key); });

            domain::PrivateKeyInfo info;
            info.provider = QString::fromWCharArray(providers[i].pszName);
            info.container = QString::fromWCharArray(keyName->pszName);
            info.algorithm = stringProperty(key, NCRYPT_ALGORITHM_PROPERTY);
            info.bits = static_cast<int>(dwordProperty(key, NCRYPT_LENGTH_PROPERTY));
            info.machineKey = (keyName->dwFlags & NCRYPT_MACHINE_KEY_FLAG) != 0;
            const DWORD exportPolicy = dwordProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY);
            info.exportable = (exportPolicy & (NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG)) != 0;
            info.tpmBacked = info.provider.compare(QStringLiteral("Microsoft Platform Crypto Provider"),
                                                   Qt::CaseInsensitive) == 0;
            info.hardwareBacked = info.tpmBacked ||
                (dwordProperty(provider, NCRYPT_IMPL_TYPE_PROPERTY) & NCRYPT_IMPL_HARDWARE_FLAG) != 0;
            keys.emplace_back(std::move(info));
        }
    }
    return keys;
}

} // namespace certmgr::platform::windows
