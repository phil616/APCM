#include "WindowsCertificateStore.h"

#include "../common/WinError.h"
#include "../common/WinRaii.h"

#include <QCryptographicHash>
#include <QScopeGuard>
#include <QTimeZone>

#include <bcrypt.h>
#include <ncrypt.h>

#include <algorithm>
#include <array>

namespace certmgr::platform::windows {
namespace {

DWORD storeFlags(const domain::StoreScope scope, const bool readOnly)
{
    DWORD flags = scope == domain::StoreScope::Machine ? CERT_SYSTEM_STORE_LOCAL_MACHINE
                                                        : CERT_SYSTEM_STORE_CURRENT_USER;
    if (readOnly) flags |= CERT_STORE_READONLY_FLAG;
    return flags | CERT_STORE_OPEN_EXISTING_FLAG;
}

CertStoreHandle openStore(const domain::CertificateStoreLocation &location, const bool readOnly)
{
    const QString nativeName = location.nativeStore.isEmpty()
        ? WindowsCertificateStore::nativeStoreName(location.role)
        : location.nativeStore;
    return CertStoreHandle(CertOpenStore(CERT_STORE_PROV_SYSTEM_W,
                                         X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                         0, storeFlags(location.scope, readOnly),
                                         nativeName.utf16()));
}

QString hex(const QByteArray &bytes, const QChar separator = QChar())
{
    const QByteArray encoded = bytes.toHex(':').toUpper();
    if (separator == QLatin1Char(':')) return QString::fromLatin1(encoded);
    return QString::fromLatin1(QByteArray(encoded).replace(":", ""));
}

QString fingerprint(PCCERT_CONTEXT context, LPCWSTR algorithm)
{
    DWORD size = 0;
    if (!CryptHashCertificate2(algorithm, 0, nullptr, context->pbCertEncoded,
                               context->cbCertEncoded, nullptr, &size)) return {};
    QByteArray digest(static_cast<qsizetype>(size), Qt::Uninitialized);
    if (!CryptHashCertificate2(algorithm, 0, nullptr, context->pbCertEncoded,
                               context->cbCertEncoded,
                               reinterpret_cast<BYTE *>(digest.data()), &size)) return {};
    digest.resize(static_cast<qsizetype>(size));
    return hex(digest, QLatin1Char(':'));
}

QString certificateName(CERT_NAME_BLOB blob)
{
    const DWORD size = CertNameToStrW(X509_ASN_ENCODING, &blob,
                                      CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                                      nullptr, 0);
    if (!size) return {};
    std::wstring value(size, L'\0');
    CertNameToStrW(X509_ASN_ENCODING, &blob,
                   CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG, value.data(), size);
    value.resize(size > 0 ? size - 1 : 0);
    return QString::fromStdWString(value);
}

QString simpleName(PCCERT_CONTEXT context)
{
    const DWORD size = CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                          nullptr, 0);
    if (!size) return {};
    std::wstring value(size, L'\0');
    CertGetNameStringW(context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, value.data(), size);
    value.resize(size > 0 ? size - 1 : 0);
    return QString::fromStdWString(value);
}

QDateTime fromFileTime(const FILETIME &fileTime)
{
    SYSTEMTIME utc{};
    if (!FileTimeToSystemTime(&fileTime, &utc)) return {};
    return QDateTime(QDate(utc.wYear, utc.wMonth, utc.wDay),
                     QTime(utc.wHour, utc.wMinute, utc.wSecond, utc.wMilliseconds), QTimeZone::UTC)
        .toLocalTime();
}

QString serialNumber(PCCERT_CONTEXT context)
{
    const auto &serial = context->pCertInfo->SerialNumber;
    QByteArray bytes(reinterpret_cast<const char *>(serial.pbData), static_cast<qsizetype>(serial.cbData));
    std::reverse(bytes.begin(), bytes.end());
    return hex(bytes);
}

QStringList enhancedKeyUsage(PCCERT_CONTEXT context)
{
    DWORD size = 0;
    if (!CertGetEnhancedKeyUsage(context, 0, nullptr, &size) && GetLastError() != ERROR_MORE_DATA)
        return {};
    if (!size) return {};
    QByteArray storage(static_cast<qsizetype>(size), Qt::Uninitialized);
    auto *usage = reinterpret_cast<PCERT_ENHKEY_USAGE>(storage.data());
    if (!CertGetEnhancedKeyUsage(context, 0, usage, &size)) return {};
    QStringList values;
    for (DWORD i = 0; i < usage->cUsageIdentifier; ++i)
        values.append(QString::fromLatin1(usage->rgpszUsageIdentifier[i]));
    return values;
}

QStringList keyUsage(PCCERT_CONTEXT context)
{
    DWORD usage = 0;
    if (!CertGetIntendedKeyUsage(X509_ASN_ENCODING, context->pCertInfo,
                                 reinterpret_cast<BYTE *>(&usage), sizeof(usage))) return {};
    QStringList values;
    if (usage & CERT_DIGITAL_SIGNATURE_KEY_USAGE) values.append(QStringLiteral("数字签名"));
    if (usage & CERT_NON_REPUDIATION_KEY_USAGE) values.append(QStringLiteral("不可否认性"));
    if (usage & CERT_KEY_ENCIPHERMENT_KEY_USAGE) values.append(QStringLiteral("密钥加密"));
    if (usage & CERT_DATA_ENCIPHERMENT_KEY_USAGE) values.append(QStringLiteral("数据加密"));
    if (usage & CERT_KEY_AGREEMENT_KEY_USAGE) values.append(QStringLiteral("密钥协商"));
    if (usage & CERT_KEY_CERT_SIGN_KEY_USAGE) values.append(QStringLiteral("证书签名"));
    if (usage & CERT_CRL_SIGN_KEY_USAGE) values.append(QStringLiteral("CRL 签名"));
    if (usage & CERT_ENCIPHER_ONLY_KEY_USAGE) values.append(QStringLiteral("仅加密"));
    if (usage & CERT_DECIPHER_ONLY_KEY_USAGE) values.append(QStringLiteral("仅解密"));
    return values;
}

QStringList alternativeNames(PCCERT_CONTEXT context)
{
    const PCERT_EXTENSION extension = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
        context->pCertInfo->cExtension, context->pCertInfo->rgExtension);
    if (!extension) return {};
    CERT_ALT_NAME_INFO *names = nullptr;
    DWORD size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME,
                             extension->Value.pbData, extension->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &names, &size)) return {};
    const auto cleanup = qScopeGuard([&] { LocalFree(names); });
    QStringList values;
    for (DWORD i = 0; i < names->cAltEntry; ++i) {
        const auto &entry = names->rgAltEntry[i];
        switch (entry.dwAltNameChoice) {
        case CERT_ALT_NAME_DNS_NAME:
            values.append(QStringLiteral("DNS: %1").arg(QString::fromWCharArray(entry.pwszDNSName)));
            break;
        case CERT_ALT_NAME_URL:
            values.append(QStringLiteral("URI: %1").arg(QString::fromWCharArray(entry.pwszURL)));
            break;
        case CERT_ALT_NAME_RFC822_NAME:
                values.append(QStringLiteral("电子邮件：%1").arg(QString::fromWCharArray(entry.pwszRfc822Name)));
            break;
        case CERT_ALT_NAME_IP_ADDRESS: {
            const auto *bytes = entry.IPAddress.pbData;
            if (entry.IPAddress.cbData == 4)
                values.append(QStringLiteral("IP: %1.%2.%3.%4").arg(bytes[0]).arg(bytes[1]).arg(bytes[2]).arg(bytes[3]));
            else
                values.append(QStringLiteral("IP: %1").arg(hex(QByteArray(reinterpret_cast<const char *>(bytes),
                    static_cast<qsizetype>(entry.IPAddress.cbData)), QLatin1Char(':'))));
            break;
        }
        default:
            break;
        }
    }
    return values;
}

QString friendlyName(PCCERT_CONTEXT context)
{
    DWORD size = 0;
    if (!CertGetCertificateContextProperty(context, CERT_FRIENDLY_NAME_PROP_ID, nullptr, &size) || !size)
        return {};
    QByteArray storage(static_cast<qsizetype>(size), Qt::Uninitialized);
    if (!CertGetCertificateContextProperty(context, CERT_FRIENDLY_NAME_PROP_ID, storage.data(), &size))
        return {};
    return QString::fromWCharArray(reinterpret_cast<const wchar_t *>(storage.constData()));
}

bool isCertificateAuthority(PCCERT_CONTEXT context, int *pathLength)
{
    const PCERT_EXTENSION extension = CertFindExtension(szOID_BASIC_CONSTRAINTS2,
        context->pCertInfo->cExtension, context->pCertInfo->rgExtension);
    if (!extension) return false;
    CERT_BASIC_CONSTRAINTS2_INFO *constraints = nullptr;
    DWORD size = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                             extension->Value.pbData, extension->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &constraints, &size)) return false;
    const auto cleanup = qScopeGuard([&] { LocalFree(constraints); });
    if (pathLength && constraints->fPathLenConstraint)
        *pathLength = static_cast<int>(constraints->dwPathLenConstraint);
    return constraints->fCA == TRUE;
}

void inspectPrivateKey(PCCERT_CONTEXT context, domain::CertificateInfo &info)
{
    DWORD size = 0;
    if (CertGetCertificateContextProperty(context, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &size)) {
        QByteArray storage(static_cast<qsizetype>(size), Qt::Uninitialized);
        if (CertGetCertificateContextProperty(context, CERT_KEY_PROV_INFO_PROP_ID,
                                              storage.data(), &size)) {
            auto *provider = reinterpret_cast<PCRYPT_KEY_PROV_INFO>(storage.data());
            info.keyProvider = QString::fromWCharArray(provider->pwszProvName);
            info.keyContainer = QString::fromWCharArray(provider->pwszContainerName);
            info.machineKey = (provider->dwFlags & CRYPT_MACHINE_KEYSET) != 0;
            info.tpmBacked = info.keyProvider.compare(QStringLiteral("Microsoft Platform Crypto Provider"),
                                                       Qt::CaseInsensitive) == 0;
            info.hardwareBacked = info.tpmBacked || info.keyProvider.contains(QStringLiteral("Smart Card"),
                                                                               Qt::CaseInsensitive);
        }
    }

    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD keySpec = 0;
    BOOL mustFree = FALSE;
    info.hasPrivateKey = CryptAcquireCertificatePrivateKey(
        context, CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG |
                     CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
        nullptr, &key, &keySpec, &mustFree) == TRUE;
    if (!info.hasPrivateKey) return;
    const auto cleanup = qScopeGuard([&] {
        if (!mustFree) return;
        if (keySpec == CERT_NCRYPT_KEY_SPEC) NCryptFreeObject(key);
        else CryptReleaseContext(static_cast<HCRYPTPROV>(key), 0);
    });
    if (keySpec == CERT_NCRYPT_KEY_SPEC) {
        DWORD policy = 0;
        DWORD resultSize = 0;
        if (NCryptGetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY,
                             reinterpret_cast<PBYTE>(&policy), sizeof(policy), &resultSize, 0) == ERROR_SUCCESS)
            info.exportable = (policy & (NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG)) != 0;
    }
}

domain::ChainStatus verifyChain(PCCERT_CONTEXT context)
{
    domain::ChainStatus result;
    CERT_CHAIN_PARA parameters{};
    parameters.cbSize = sizeof(parameters);
    PCCERT_CHAIN_CONTEXT rawChain = nullptr;
    if (!CertGetCertificateChain(nullptr, context, nullptr, context->hCertStore,
                                 &parameters, 0, nullptr, &rawChain)) {
        result.diagnostics.append(QStringLiteral("Windows 无法构建证书链。"));
        return result;
    }
    const auto cleanup = qScopeGuard([&] { CertFreeCertificateChain(rawChain); });
    result.nativeErrorStatus = rawChain->TrustStatus.dwErrorStatus;
    result.validTime = (result.nativeErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID) == 0;
    result.trustedRoot = (result.nativeErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT) == 0;
    CERT_CHAIN_POLICY_PARA policyParameters{};
    policyParameters.cbSize = sizeof(policyParameters);
    CERT_CHAIN_POLICY_STATUS policyStatus{};
    policyStatus.cbSize = sizeof(policyStatus);
    const bool policyVerified = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, rawChain,
                                                                 &policyParameters, &policyStatus) == TRUE;
    result.correctUsage = !policyVerified || policyStatus.dwError != CERT_E_WRONG_USAGE;
    result.valid = result.nativeErrorStatus == CERT_TRUST_NO_ERROR && policyVerified && policyStatus.dwError == S_OK;
    if (!result.validTime) result.diagnostics.append(QStringLiteral("证书不在有效期内。"));
    if (!result.trustedRoot) result.diagnostics.append(QStringLiteral("证书链终止于不受信任的根证书。"));
    if (!result.correctUsage) result.diagnostics.append(QStringLiteral("证书用途不符合所选 Windows 策略。"));
    if (!policyVerified) result.diagnostics.append(QStringLiteral("Windows 无法评估证书链策略。"));
    if (result.nativeErrorStatus & CERT_TRUST_IS_REVOKED) {
        result.revocation = domain::ChainStatus::Revocation::Revoked;
        result.diagnostics.append(QStringLiteral("证书已被吊销。"));
    } else {
        result.revocation = domain::ChainStatus::Revocation::NotChecked;
    }
    return result;
}

domain::CertificateInfo parseCertificate(PCCERT_CONTEXT context,
                                         const domain::CertificateStoreLocation &location)
{
    domain::CertificateInfo info;
    info.location = location;
    info.subject = certificateName(context->pCertInfo->Subject);
    info.commonName = simpleName(context);
    info.issuer = certificateName(context->pCertInfo->Issuer);
    info.serialNumber = serialNumber(context);
    info.sha256Fingerprint = fingerprint(context, BCRYPT_SHA256_ALGORITHM);
    info.sha1Thumbprint = fingerprint(context, BCRYPT_SHA1_ALGORITHM);
    info.notBefore = fromFileTime(context->pCertInfo->NotBefore);
    info.notAfter = fromFileTime(context->pCertInfo->NotAfter);
    info.subjectAlternativeNames = alternativeNames(context);
    info.keyUsage = keyUsage(context);
    info.extendedKeyUsage = enhancedKeyUsage(context);
    info.isCA = isCertificateAuthority(context, &info.pathLength);
    info.publicKeyAlgorithm = QString::fromLatin1(context->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
    info.publicKeyBits = static_cast<int>(CertGetPublicKeyLength(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                                &context->pCertInfo->SubjectPublicKeyInfo));
    info.signatureAlgorithm = QString::fromLatin1(context->pCertInfo->SignatureAlgorithm.pszObjId);
    info.encodedDer = QByteArray(reinterpret_cast<const char *>(context->pbCertEncoded),
                                 static_cast<qsizetype>(context->cbCertEncoded));
    inspectPrivateKey(context, info);
    info.chain = verifyChain(context);
    info.friendlyName = friendlyName(context);
    info.id = QStringLiteral("%1|%2|%3")
        .arg(static_cast<int>(location.scope))
        .arg(static_cast<int>(location.role))
        .arg(info.sha256Fingerprint.remove(QLatin1Char(':')));
    return info;
}

QList<domain::CertificateStoreLocation> supportedLocations()
{
    QList<domain::CertificateStoreLocation> values;
    for (const auto scope : {domain::StoreScope::User, domain::StoreScope::Machine}) {
        for (const auto role : {domain::StoreRole::Personal, domain::StoreRole::TrustedRoot,
                                domain::StoreRole::IntermediateCA, domain::StoreRole::EnterpriseTrust})
            values.append({scope, role, {}});
    }
    return values;
}

CRYPT_DATA_BLOB cryptoBlob(const QByteArray &bytes)
{
    return {static_cast<DWORD>(bytes.size()),
        reinterpret_cast<BYTE *>(const_cast<char *>(bytes.constData()))};
}

tl::expected<CertStoreHandle, domain::AppError>
openPkcs12(const QByteArray &encodedPkcs12, const QString &password, const DWORD flags)
{
    auto blob = cryptoBlob(encodedPkcs12);
    if (!PFXIsPFXBlob(&blob))
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("pkcs12.invalid"), 0, QStringLiteral("所选文件不是有效的 P12/PFX 包。"), {}});
    if (!PFXVerifyPassword(&blob, reinterpret_cast<LPCWSTR>(password.utf16()), 0))
        return tl::unexpected(winError(domain::ErrorCategory::Validation,
            QStringLiteral("pkcs12.password"), GetLastError(),
            QStringLiteral("P12/PFX 密码错误或文件已损坏。")));
    CertStoreHandle store(PFXImportCertStore(&blob,
        reinterpret_cast<LPCWSTR>(password.utf16()), flags));
    if (!store)
        return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
            QStringLiteral("pkcs12.import"), GetLastError(),
            QStringLiteral("Windows 无法打开 P12/PFX 包。")));
    return std::move(store);
}

} // namespace

QString WindowsCertificateStore::nativeStoreName(const domain::StoreRole role)
{
    switch (role) {
    case domain::StoreRole::Personal: return QStringLiteral("MY");
    case domain::StoreRole::TrustedRoot: return QStringLiteral("Root");
    case domain::StoreRole::IntermediateCA: return QStringLiteral("CA");
    case domain::StoreRole::EnterpriseTrust: return QStringLiteral("Trust");
    case domain::StoreRole::EnrollmentRequest: return QStringLiteral("REQUEST");
    case domain::StoreRole::Other: return {};
    }
    return {};
}

bool WindowsCertificateStore::isPkcs12(const QByteArray &contents)
{
    auto blob = cryptoBlob(contents);
    return PFXIsPFXBlob(&blob) == TRUE;
}

tl::expected<std::vector<domain::CertificateInfo>, domain::AppError>
WindowsCertificateStore::listCertificates(const domain::CertificateStoreLocation &location)
{
    auto store = openStore(location, true);
    if (!store) return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
        QStringLiteral("store.open_failed"), GetLastError(), QStringLiteral("无法打开证书存储。")));

    std::vector<domain::CertificateInfo> values;
    PCCERT_CONTEXT current = nullptr;
    while ((current = CertEnumCertificatesInStore(store.get(), current)) != nullptr)
        values.emplace_back(parseCertificate(current, location));
    const DWORD error = GetLastError();
    if (error != CRYPT_E_NOT_FOUND && error != ERROR_SUCCESS)
        return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
            QStringLiteral("store.enumerate_failed"), error, QStringLiteral("无法枚举证书。")));
    return values;
}

tl::expected<domain::CertificateInfo, domain::AppError>
WindowsCertificateStore::inspect(const QString &id)
{
    for (const auto &location : supportedLocations()) {
        auto certificates = listCertificates(location);
        if (!certificates) continue;
        const auto found = std::find_if(certificates->begin(), certificates->end(),
                                        [&](const auto &value) { return value.id == id; });
        if (found != certificates->end()) return *found;
    }
    return tl::unexpected(domain::AppError{domain::ErrorCategory::CertificateStore,
        QStringLiteral("certificate.not_found"), 0, QStringLiteral("该证书已不存在于 Windows 中。"), id});
}

tl::expected<domain::CertificateInfo, domain::AppError>
WindowsCertificateStore::decodeCertificate(const QByteArray &encodedCertificate)
{
    CertContextPtr context(CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        reinterpret_cast<const BYTE *>(encodedCertificate.constData()),
        static_cast<DWORD>(encodedCertificate.size())));
    if (!context) return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
        QStringLiteral("certificate.decode_failed"), GetLastError(),
        QStringLiteral("所选文件不是有效的 X.509 证书。")));
    return parseCertificate(context.get(), {domain::StoreScope::User, domain::StoreRole::Other, {}});
}

tl::expected<void, domain::AppError>
WindowsCertificateStore::installCertificate(const QByteArray &encodedCertificate,
                                             const domain::CertificateStoreLocation &location)
{
    CertContextPtr context(CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        reinterpret_cast<const BYTE *>(encodedCertificate.constData()),
        static_cast<DWORD>(encodedCertificate.size())));
    if (!context) return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
        QStringLiteral("certificate.decode_failed"), GetLastError(), QStringLiteral("所选文件不是有效证书。")));

    if (location.role == domain::StoreRole::TrustedRoot && !isCertificateAuthority(context.get(), nullptr))
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("root.not_ca"), 0,
            QStringLiteral("只有基本约束为 CA=true 的证书才能安装为受信任的根证书。"), {}});

    auto store = openStore(location, false);
    if (!store) return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
        QStringLiteral("store.open_write_failed"), GetLastError(), QStringLiteral("无法以写入方式打开证书存储。")));
    if (!CertAddCertificateContextToStore(store.get(), context.get(), CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
        return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
            QStringLiteral("certificate.install_failed"), GetLastError(), QStringLiteral("Windows 拒绝安装该证书。")));
    return {};
}

tl::expected<std::vector<domain::CertificateInfo>, domain::AppError>
WindowsCertificateStore::inspectPkcs12(const QByteArray &encodedPkcs12, const QString &password)
{
    auto package = openPkcs12(encodedPkcs12, password,
        PKCS12_NO_PERSIST_KEY | PKCS12_PREFER_CNG_KSP | PKCS12_INCLUDE_EXTENDED_PROPERTIES);
    if (!package) return tl::unexpected(package.error());
    std::vector<domain::CertificateInfo> certificates;
    PCCERT_CONTEXT current = nullptr;
    while ((current = CertEnumCertificatesInStore(package->get(), current)) != nullptr)
        certificates.emplace_back(parseCertificate(current,
            {domain::StoreScope::User, domain::StoreRole::Other, {}}));
    if (certificates.empty())
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("pkcs12.empty"), 0, QStringLiteral("P12/PFX 包中没有证书。"), {}});
    return certificates;
}

tl::expected<std::vector<domain::CertificateInfo>, domain::AppError>
WindowsCertificateStore::importPkcs12(const QByteArray &encodedPkcs12, const QString &password,
                                      const domain::CertificateStoreLocation &location)
{
    auto inspected = inspectPkcs12(encodedPkcs12, password);
    if (!inspected) return tl::unexpected(inspected.error());
    if (location.role == domain::StoreRole::TrustedRoot &&
        std::any_of(inspected->cbegin(), inspected->cend(), [](const auto &certificate) { return !certificate.isCA; }))
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("pkcs12.root_contains_leaf"), 0,
            QStringLiteral("该 P12/PFX 包包含非 CA 证书，不能整体安装到受信任根存储。"), {}});

    DWORD flags = PKCS12_PREFER_CNG_KSP | PKCS12_INCLUDE_EXTENDED_PROPERTIES;
    flags |= location.scope == domain::StoreScope::Machine ? CRYPT_MACHINE_KEYSET : CRYPT_USER_KEYSET;
    auto package = openPkcs12(encodedPkcs12, password, flags);
    if (!package) return tl::unexpected(package.error());
    auto target = openStore(location, false);
    if (!target) return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
        QStringLiteral("store.open_write_failed"), GetLastError(),
        QStringLiteral("无法以写入方式打开目标证书存储。")));

    std::vector<domain::CertificateInfo> installed;
    PCCERT_CONTEXT current = nullptr;
    while ((current = CertEnumCertificatesInStore(package->get(), current)) != nullptr) {
        PCCERT_CONTEXT stored = nullptr;
        if (!CertAddCertificateContextToStore(target.get(), current,
                CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, &stored))
            return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
                QStringLiteral("pkcs12.certificate_install"), GetLastError(),
                QStringLiteral("Windows 拒绝安装 P12/PFX 中的证书。")));
        CertContextPtr storedContext(stored);
        installed.emplace_back(parseCertificate(storedContext.get(), location));
    }
    return installed;
}

tl::expected<void, domain::AppError> WindowsCertificateStore::removeCertificate(const QString &id)
{
    for (const auto &location : supportedLocations()) {
        auto store = openStore(location, false);
        if (!store) continue;
        PCCERT_CONTEXT current = nullptr;
        while ((current = CertEnumCertificatesInStore(store.get(), current)) != nullptr) {
            const auto parsed = parseCertificate(current, location);
            if (parsed.id != id) continue;
            PCCERT_CONTEXT duplicate = CertDuplicateCertificateContext(current);
            if (!duplicate || !CertDeleteCertificateFromStore(duplicate))
                return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
                    QStringLiteral("certificate.remove_failed"), GetLastError(), QStringLiteral("Windows 拒绝移除该证书。")));
            return {};
        }
    }
    return tl::unexpected(domain::AppError{domain::ErrorCategory::CertificateStore,
        QStringLiteral("certificate.not_found"), 0, QStringLiteral("该证书已不存在于 Windows 中。"), id});
}

} // namespace certmgr::platform::windows
