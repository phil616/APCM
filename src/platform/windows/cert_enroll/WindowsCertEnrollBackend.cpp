#include "WindowsCertEnrollBackend.h"
#include "../../../domain/enrollment/EnrollmentRequest.h"
#include "../../../domain/signing/SigningProtocol.h"

#include "../common/WinError.h"
#include "../common/WinRaii.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <certenroll.h>

#include <QCryptographicHash>
#include <QHostAddress>
#include <QScopeGuard>

namespace certmgr::platform::windows {
namespace {

tl::expected<void, domain::AppError> check(const HRESULT result, const QString &code,
                                            const QString &message)
{
    if (SUCCEEDED(result)) return {};
    return tl::unexpected(winError(domain::ErrorCategory::Enrollment, code,
                                    static_cast<quint32>(result), message));
}

QString escapeRdn(QString value)
{
    value.replace(QStringLiteral("\\"), QStringLiteral("\\\\"));
    value.replace(QStringLiteral(","), QStringLiteral("\\,"));
    value.replace(QStringLiteral("+"), QStringLiteral("\\+"));
    value.replace(QStringLiteral("\""), QStringLiteral("\\\""));
    return value;
}

QString subjectString(const domain::CertificateTemplate &certificateTemplate)
{
    QStringList parts;
    for (const QString &name : {QStringLiteral("CN"), QStringLiteral("OU"), QStringLiteral("O"),
                                QStringLiteral("L"), QStringLiteral("ST"), QStringLiteral("C")}) {
        const auto found = certificateTemplate.subject.constFind(name);
        if (found != certificateTemplate.subject.cend() && !found->value.isEmpty())
            parts.append(QStringLiteral("%1=%2").arg(name, escapeRdn(found->value)));
    }
    return parts.join(QStringLiteral(", "));
}

QByteArray decodedBase64(QString value)
{
    value.remove(QStringLiteral("-----BEGIN CERTIFICATE REQUEST-----"));
    value.remove(QStringLiteral("-----END CERTIFICATE REQUEST-----"));
    value.remove(QStringLiteral("-----BEGIN NEW CERTIFICATE REQUEST-----"));
    value.remove(QStringLiteral("-----END NEW CERTIFICATE REQUEST-----"));
    value.remove(QLatin1Char('\r'));
    value.remove(QLatin1Char('\n'));
    value.remove(QLatin1Char(' '));
    return QByteArray::fromBase64(value.toLatin1());
}

X509CertificateEnrollmentContext enrollmentContext(const domain::StoreScope scope)
{
    return scope == domain::StoreScope::Machine ? ContextMachine : ContextUser;
}

template <typename T>
tl::expected<ComPtr<T>, domain::AppError> createCom(const CLSID &classId, const QString &code)
{
    ComPtr<T> object;
    const HRESULT result = CoCreateInstance(classId, nullptr, CLSCTX_INPROC_SERVER,
                                            __uuidof(T), reinterpret_cast<void **>(object.GetAddressOf()));
    if (FAILED(result)) return tl::unexpected(winError(domain::ErrorCategory::Enrollment,
        code, static_cast<quint32>(result), QStringLiteral("Windows 证书申请服务不可用。")));
    return object;
}

tl::expected<void, domain::AppError> addEku(IX509CertificateRequestPkcs10 *request,
                                             const QStringList &oids)
{
    if (oids.isEmpty()) return {};
    auto objectIdsResult = createCom<IObjectIds>(__uuidof(CObjectIds), QStringLiteral("enrollment.object_ids"));
    if (!objectIdsResult) return tl::unexpected(objectIdsResult.error());
    auto objectIds = *objectIdsResult;
    for (const QString &oidValue : oids) {
        auto objectIdResult = createCom<IObjectId>(__uuidof(CObjectId), QStringLiteral("enrollment.object_id"));
        if (!objectIdResult) return tl::unexpected(objectIdResult.error());
        BStr oid(oidValue);
        if (auto result = check((*objectIdResult)->InitializeFromValue(oid.get()),
                                QStringLiteral("enrollment.eku_oid"),
                                QStringLiteral("模板包含无效的 EKU 对象标识符。")); !result)
            return result;
        if (auto result = check(objectIds->Add(objectIdResult->Get()),
                                QStringLiteral("enrollment.eku_add"),
                                QStringLiteral("无法添加请求的 EKU。")); !result)
            return result;
    }

    auto extensionResult = createCom<IX509ExtensionEnhancedKeyUsage>(
        __uuidof(CX509ExtensionEnhancedKeyUsage), QStringLiteral("enrollment.eku_extension"));
    if (!extensionResult) return tl::unexpected(extensionResult.error());
    if (auto result = check((*extensionResult)->InitializeEncode(objectIds.Get()),
                            QStringLiteral("enrollment.eku_encode"),
                            QStringLiteral("无法编码请求的 EKU 扩展。")); !result)
        return result;
    ComPtr<IX509Extensions> extensions;
    if (auto result = check(request->get_X509Extensions(&extensions),
                            QStringLiteral("enrollment.extensions"),
                            QStringLiteral("无法访问证书申请扩展。")); !result)
        return result;
    return check(extensions->Add(extensionResult->Get()), QStringLiteral("enrollment.eku_commit"),
                 QStringLiteral("无法向证书申请添加 EKU。"));
}

tl::expected<void, domain::AppError> addKeyUsage(IX509CertificateRequestPkcs10 *request,
                                                 const QStringList &usages)
{
    if (usages.isEmpty()) return {};
    X509KeyUsageFlags flags = XCN_CERT_NO_KEY_USAGE;
    for (const QString &usage : usages) {
        X509KeyUsageFlags flag = XCN_CERT_NO_KEY_USAGE;
        if (usage == QStringLiteral("digitalSignature")) flag = XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE;
        else if (usage == QStringLiteral("nonRepudiation")) flag = XCN_CERT_NON_REPUDIATION_KEY_USAGE;
        else if (usage == QStringLiteral("keyEncipherment")) flag = XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE;
        else if (usage == QStringLiteral("dataEncipherment")) flag = XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE;
        else if (usage == QStringLiteral("keyAgreement")) flag = XCN_CERT_KEY_AGREEMENT_KEY_USAGE;
        else if (usage == QStringLiteral("keyCertSign")) flag = XCN_CERT_KEY_CERT_SIGN_KEY_USAGE;
        else if (usage == QStringLiteral("crlSign")) flag = XCN_CERT_CRL_SIGN_KEY_USAGE;
        else if (usage == QStringLiteral("encipherOnly")) flag = XCN_CERT_ENCIPHER_ONLY_KEY_USAGE;
        else if (usage == QStringLiteral("decipherOnly")) flag = XCN_CERT_DECIPHER_ONLY_KEY_USAGE;
        else
            return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
                QStringLiteral("enrollment.key_usage_invalid"), 0,
                QStringLiteral("证书申请包含不支持的密钥用途。"), usage});
        flags = static_cast<X509KeyUsageFlags>(static_cast<unsigned int>(flags) |
                                               static_cast<unsigned int>(flag));
    }
    auto extensionResult = createCom<IX509ExtensionKeyUsage>(
        __uuidof(CX509ExtensionKeyUsage), QStringLiteral("enrollment.key_usage_extension"));
    if (!extensionResult) return tl::unexpected(extensionResult.error());
    if (auto result = check((*extensionResult)->InitializeEncode(flags),
                            QStringLiteral("enrollment.key_usage_encode"),
                            QStringLiteral("无法编码证书申请的密钥用途扩展。")); !result)
        return result;
    ComPtr<IX509Extensions> extensions;
    if (auto result = check(request->get_X509Extensions(&extensions),
                            QStringLiteral("enrollment.key_usage_extensions"),
                            QStringLiteral("无法访问证书申请扩展。")); !result)
        return result;
    return check(extensions->Add(extensionResult->Get()),
                 QStringLiteral("enrollment.key_usage_commit"),
                 QStringLiteral("无法向证书申请添加密钥用途。"));
}

tl::expected<void, domain::AppError> appendStringName(IAlternativeNames *names,
                                                       const AlternativeNameType type,
                                                       const QString &value)
{
    auto nameResult = createCom<IAlternativeName>(__uuidof(CAlternativeName),
        QStringLiteral("enrollment.san_name"));
    if (!nameResult) return tl::unexpected(nameResult.error());
    BStr encoded(value.trimmed());
    if (auto result = check((*nameResult)->InitializeFromString(type, encoded.get()),
                            QStringLiteral("enrollment.san_value"),
                            QStringLiteral("证书备用名称无效。")); !result)
        return result;
    return check(names->Add(nameResult->Get()), QStringLiteral("enrollment.san_add"),
                 QStringLiteral("无法添加证书备用名称。"));
}

tl::expected<void, domain::AppError> appendIpName(IAlternativeNames *names, const QString &value)
{
    const QHostAddress address(value.trimmed());
    QByteArray raw;
    if (address.protocol() == QAbstractSocket::IPv4Protocol) {
        const quint32 ipv4 = address.toIPv4Address();
        raw.resize(4);
        raw[0] = static_cast<char>((ipv4 >> 24) & 0xff);
        raw[1] = static_cast<char>((ipv4 >> 16) & 0xff);
        raw[2] = static_cast<char>((ipv4 >> 8) & 0xff);
        raw[3] = static_cast<char>(ipv4 & 0xff);
    } else if (address.protocol() == QAbstractSocket::IPv6Protocol) {
        const Q_IPV6ADDR ipv6 = address.toIPv6Address();
        raw = QByteArray(reinterpret_cast<const char *>(ipv6.c), 16);
    } else {
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("enrollment.ip_san_invalid"), 0,
            QStringLiteral("IP 备用名称格式无效。"), value});
    }
    auto nameResult = createCom<IAlternativeName>(__uuidof(CAlternativeName),
        QStringLiteral("enrollment.san_ip"));
    if (!nameResult) return tl::unexpected(nameResult.error());
    BSTR binary = SysAllocStringByteLen(raw.constData(), static_cast<UINT>(raw.size()));
    if (!binary)
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Enrollment,
            QStringLiteral("enrollment.san_ip_memory"), 0,
            QStringLiteral("无法编码 IP 备用名称。"), {}});
    const auto cleanup = qScopeGuard([&] { SysFreeString(binary); });
    if (auto result = check((*nameResult)->InitializeFromRawData(
                                XCN_CERT_ALT_NAME_IP_ADDRESS, XCN_CRYPT_STRING_BINARY, binary),
                            QStringLiteral("enrollment.san_ip_value"),
                            QStringLiteral("IP 备用名称无效。")); !result)
        return result;
    return check(names->Add(nameResult->Get()), QStringLiteral("enrollment.san_ip_add"),
                 QStringLiteral("无法添加 IP 备用名称。"));
}

tl::expected<void, domain::AppError> addSubjectAlternativeNames(
    IX509CertificateRequestPkcs10 *request, const domain::CertificateTemplate &certificateTemplate)
{
    if (certificateTemplate.dnsSans.isEmpty() && certificateTemplate.ipSans.isEmpty() &&
        certificateTemplate.uriSans.isEmpty() && certificateTemplate.upnSans.isEmpty() && certificateTemplate.emailSans.isEmpty()) return {};
    auto namesResult = createCom<IAlternativeNames>(__uuidof(CAlternativeNames),
        QStringLiteral("enrollment.san_names"));
    if (!namesResult) return tl::unexpected(namesResult.error());
    auto names = *namesResult;
    for (const QString &value : certificateTemplate.dnsSans)
        if (auto result = appendStringName(names.Get(), XCN_CERT_ALT_NAME_DNS_NAME, value); !result)
            return result;
    for (const QString &value : certificateTemplate.uriSans)
        if (auto result = appendStringName(names.Get(), XCN_CERT_ALT_NAME_URL, value); !result)
            return result;
    for (const QString &value : certificateTemplate.emailSans)
        if (auto result = appendStringName(names.Get(), XCN_CERT_ALT_NAME_RFC822_NAME, value); !result)
            return result;
    for (const QString &value : certificateTemplate.upnSans)
        if (auto result = appendStringName(names.Get(), XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME, value); !result)
            return result;
    for (const QString &value : certificateTemplate.ipSans)
        if (auto result = appendIpName(names.Get(), value); !result)
            return result;
    auto extensionResult = createCom<IX509ExtensionAlternativeNames>(
        __uuidof(CX509ExtensionAlternativeNames), QStringLiteral("enrollment.san_extension"));
    if (!extensionResult) return tl::unexpected(extensionResult.error());
    if (auto result = check((*extensionResult)->InitializeEncode(names.Get()),
                            QStringLiteral("enrollment.san_encode"),
                            QStringLiteral("无法编码证书备用名称扩展。")); !result)
        return result;
    ComPtr<IX509Extensions> extensions;
    if (auto result = check(request->get_X509Extensions(&extensions),
                            QStringLiteral("enrollment.san_extensions"),
                            QStringLiteral("无法访问证书申请扩展。")); !result)
        return result;
    return check(extensions->Add(extensionResult->Get()), QStringLiteral("enrollment.san_commit"),
                 QStringLiteral("无法向证书申请添加备用名称。"));
}

} // namespace

tl::expected<GeneratedEnrollment, domain::AppError>
WindowsCertEnrollBackend::createPkcs10(const domain::CertificateTemplate &certificateTemplate)
{
    const bool independent = certificateTemplate.csrProfile == domain::CsrProfile::IndependentSigning;
    if (independent && (!certificateTemplate.keyUsage.isEmpty() || !certificateTemplate.extendedKeyUsage.isEmpty() || !certificateTemplate.upnSans.isEmpty()))
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("enrollment.independent_profile"), 0,
            QStringLiteral("独立签发 CSR 只允许 DNS/IP/email/URI SAN，不能设置 KU、EKU 或 UPN 请求扩展。"), {}});
    const HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(comResult) && comResult != RPC_E_CHANGED_MODE)
        return tl::unexpected(winError(domain::ErrorCategory::Enrollment,
            QStringLiteral("enrollment.com_init"), static_cast<quint32>(comResult),
            QStringLiteral("无法初始化 Windows 证书申请。")));
    const auto comCleanup = qScopeGuard([&] { if (comResult != RPC_E_CHANGED_MODE) CoUninitialize(); });

    auto keyResult = createCom<IX509PrivateKey>(__uuidof(CX509PrivateKey), QStringLiteral("enrollment.private_key"));
    if (!keyResult) return tl::unexpected(keyResult.error());
    auto key = *keyResult;
    BStr provider(certificateTemplate.key.provider);
    if (auto result = check(key->put_ProviderName(provider.get()), QStringLiteral("enrollment.provider"),
                            QStringLiteral("所选 Windows 密钥提供程序不可用。")); !result) return tl::unexpected(result.error());
    if (auto result = check(key->put_MachineContext(certificateTemplate.scope == domain::StoreScope::Machine
                                                        ? VARIANT_TRUE : VARIANT_FALSE),
                            QStringLiteral("enrollment.key_scope"), QStringLiteral("无法设置密钥作用域。")); !result) return tl::unexpected(result.error());
    if (certificateTemplate.key.algorithm.startsWith(QStringLiteral("ECDSA_"))) {
        auto algorithm = createCom<IObjectId>(__uuidof(CObjectId), QStringLiteral("enrollment.algorithm"));
        if (!algorithm) return tl::unexpected(algorithm.error());
        BStr name(certificateTemplate.key.algorithm);
        if (auto result = check((*algorithm)->InitializeFromAlgorithmName(XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID,
                XCN_CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, AlgorithmFlagsNone, name.get()),
                QStringLiteral("enrollment.ec_algorithm"), QStringLiteral("无法配置 ECDSA 密钥算法。")); !result) return tl::unexpected(result.error());
        if (auto result = check(key->put_Algorithm(algorithm->Get()), QStringLiteral("enrollment.ec_key"),
                QStringLiteral("密钥提供程序不支持所选 ECDSA 曲线。")); !result) return tl::unexpected(result.error());
    }
    if (auto result = check(key->put_Length(certificateTemplate.key.bits), QStringLiteral("enrollment.key_length"),
                            QStringLiteral("不支持所选密钥长度。")); !result) return tl::unexpected(result.error());
    if (auto result = check(key->put_KeySpec(certificateTemplate.key.algorithm.startsWith(QStringLiteral("ECDSA_")) ? XCN_AT_NONE : XCN_AT_SIGNATURE), QStringLiteral("enrollment.key_usage"),
                            QStringLiteral("无法将密钥配置为用于签名。")); !result) return tl::unexpected(result.error());
    const auto exportPolicy = certificateTemplate.key.exportable ? XCN_NCRYPT_ALLOW_EXPORT_FLAG
                                                                  : XCN_NCRYPT_ALLOW_EXPORT_NONE;
    if (auto result = check(key->put_ExportPolicy(exportPolicy), QStringLiteral("enrollment.export_policy"),
                            QStringLiteral("无法强制执行私钥导出策略。")); !result) return tl::unexpected(result.error());
    if (auto result = check(key->Create(), QStringLiteral("enrollment.key_create"),
                            certificateTemplate.key.hardwareRequired
                                ? QStringLiteral("无法创建不可导出的 TPM 密钥，请检查 TPM 状态与权限。")
                                : QStringLiteral("无法创建私钥。")); !result) return tl::unexpected(result.error());
    bool retainKey = false;
    const auto failedRequestCleanup = qScopeGuard([&] {
        if (!retainKey) static_cast<void>(key->Delete());
    });

    auto requestResult = createCom<IX509CertificateRequestPkcs10>(
        __uuidof(CX509CertificateRequestPkcs10), QStringLiteral("enrollment.pkcs10"));
    if (!requestResult) return tl::unexpected(requestResult.error());
    auto request = *requestResult;
    BStr emptyTemplate(QString{});
    if (auto result = check(request->InitializeFromPrivateKey(enrollmentContext(certificateTemplate.scope),
                                                               key.Get(), emptyTemplate.get()),
                            QStringLiteral("enrollment.request_initialize"),
                            QStringLiteral("无法初始化 PKCS#10 申请。")); !result) return tl::unexpected(result.error());

    if (independent) {
        if (auto result = check(request->put_SuppressDefaults(VARIANT_TRUE), QStringLiteral("enrollment.suppress_defaults"),
                QStringLiteral("无法关闭 Windows 默认 CSR 扩展。")); !result) return tl::unexpected(result.error());
        ComPtr<IX509Extensions> extensions;
        if (auto result = check(request->get_X509Extensions(&extensions), QStringLiteral("enrollment.default_extensions"),
                QStringLiteral("无法读取 Windows 默认 CSR 扩展。")); !result) return tl::unexpected(result.error());
        if (auto result = check(extensions->Clear(), QStringLiteral("enrollment.clear_extensions"),
                QStringLiteral("无法清除 Windows 默认 CSR 扩展。")); !result) return tl::unexpected(result.error());
    }

    auto hashAlgorithm = createCom<IObjectId>(__uuidof(CObjectId), QStringLiteral("enrollment.hash"));
    if (!hashAlgorithm) return tl::unexpected(hashAlgorithm.error());
    BStr hashName(QStringLiteral("SHA256"));
    if (auto result = check((*hashAlgorithm)->InitializeFromAlgorithmName(XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
            XCN_CRYPT_OID_INFO_PUBKEY_ANY, AlgorithmFlagsNone, hashName.get()),
            QStringLiteral("enrollment.hash_initialize"), QStringLiteral("无法配置 SHA-256 签名。")); !result) return tl::unexpected(result.error());
    if (auto result = check(request->put_HashAlgorithm(hashAlgorithm->Get()), QStringLiteral("enrollment.hash_set"),
            QStringLiteral("无法设置申请签名算法。")); !result) return tl::unexpected(result.error());

    if (!subjectString(certificateTemplate).isEmpty()) {
        auto subjectResult = createCom<IX500DistinguishedName>(
            __uuidof(CX500DistinguishedName), QStringLiteral("enrollment.subject"));
        if (!subjectResult) return tl::unexpected(subjectResult.error());
        BStr subjectValue(subjectString(certificateTemplate));
        if (auto result = check((*subjectResult)->Encode(subjectValue.get(), XCN_CERT_NAME_STR_NONE),
                                QStringLiteral("enrollment.subject_encode"),
                                QStringLiteral("证书主题无效。")); !result) return tl::unexpected(result.error());
        if (auto result = check(request->put_Subject(subjectResult->Get()), QStringLiteral("enrollment.subject_set"),
                                QStringLiteral("无法设置证书主题。")); !result) return tl::unexpected(result.error());
    }
    if (auto result = addEku(request.Get(), certificateTemplate.extendedKeyUsage); !result)
        return tl::unexpected(result.error());
    if (auto result = addKeyUsage(request.Get(), certificateTemplate.keyUsage); !result)
        return tl::unexpected(result.error());
    if (auto result = addSubjectAlternativeNames(request.Get(), certificateTemplate); !result)
        return tl::unexpected(result.error());

    auto enrollmentResult = createCom<IX509Enrollment>(__uuidof(CX509Enrollment),
                                                        QStringLiteral("enrollment.session"));
    if (!enrollmentResult) return tl::unexpected(enrollmentResult.error());
    auto enrollment = *enrollmentResult;
    if (auto result = check(enrollment->InitializeFromRequest(request.Get()),
                            QStringLiteral("enrollment.session_initialize"),
                            QStringLiteral("无法初始化证书申请会话。")); !result) return tl::unexpected(result.error());
    if (!certificateTemplate.friendlyName.isEmpty()) {
        BStr friendlyName(certificateTemplate.friendlyName);
        if (auto result = check(enrollment->put_CertificateFriendlyName(friendlyName.get()),
                                QStringLiteral("enrollment.friendly_name"),
                                QStringLiteral("无法设置证书友好名称。")); !result) return tl::unexpected(result.error());
    }

    BStr csr;
    if (auto result = check(enrollment->CreateRequest(XCN_CRYPT_STRING_BASE64, csr.put()),
                            QStringLiteral("enrollment.csr_create"),
                            QStringLiteral("Windows 无法创建 PKCS#10 申请。")); !result) return tl::unexpected(result.error());
    BStr container;
    key->get_ContainerName(container.put());
    const QByteArray csrDer = decodedBase64(csr.toQString());
    const QString csrText = QString::fromLatin1(domain::encodeCsrPem(csrDer));
    if (independent) {
        auto checked = domain::signing::inspectCsr(csrText.toUtf8());
        if (!checked) return tl::unexpected(checked.error());
    }
    ComPtr<IX509PublicKey> publicKey;
    if (auto result = check(request->get_PublicKey(&publicKey), QStringLiteral("enrollment.public_key"),
                            QStringLiteral("无法读取证书申请公钥。")); !result)
        return tl::unexpected(result.error());
    BStr encodedPublicKey;
    if (auto result = check(publicKey->get_EncodedKey(XCN_CRYPT_STRING_BASE64, encodedPublicKey.put()),
                            QStringLiteral("enrollment.public_key_encode"),
                            QStringLiteral("无法编码证书申请公钥。")); !result)
        return tl::unexpected(result.error());
    const QByteArray publicKeyBytes = decodedBase64(encodedPublicKey.toQString());
    if (csrDer.isEmpty() || publicKeyBytes.isEmpty())
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Enrollment,
            QStringLiteral("enrollment.encoding_empty"), 0,
            QStringLiteral("Windows 返回了无效的证书申请编码。"), {}});
    GeneratedEnrollment generated;
    generated.csrBase64 = csrText;
    generated.csrSha256 = QString::fromLatin1(QCryptographicHash::hash(csrDer, QCryptographicHash::Sha256).toHex().toUpper());
    generated.publicKeySha256 = QString::fromLatin1(QCryptographicHash::hash(publicKeyBytes, QCryptographicHash::Sha256).toHex().toUpper());
    generated.providerName = certificateTemplate.key.provider;
    generated.keyContainerName = container.toQString();
    retainKey = true;
    return generated;
}

tl::expected<void, domain::AppError>
WindowsCertEnrollBackend::installResponse(const QByteArray &certificateDer,
                                          const domain::StoreScope scope,
                                          const QString &providerName,
                                          const QString &keyContainerName,
                                          const QString &friendlyName)
{
    if (certificateDer.isEmpty() || providerName.trimmed().isEmpty() ||
        keyContainerName.trimmed().isEmpty())
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("enrollment.install_context_missing"), 0,
            QStringLiteral("申请缺少 Windows 密钥提供程序或密钥容器信息，无法安全关联私钥。"), {}});

    CertContextPtr certificate(CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        reinterpret_cast<const BYTE *>(certificateDer.constData()),
        static_cast<DWORD>(certificateDer.size())));
    if (!certificate)
        return tl::unexpected(winError(domain::ErrorCategory::Enrollment,
            QStringLiteral("enrollment.response_decode"), GetLastError(),
            QStringLiteral("CA 返回的签发证书编码无效。")));

    CRYPT_KEY_PROV_INFO provider{};
    provider.pwszContainerName = reinterpret_cast<LPWSTR>(
        const_cast<ushort *>(keyContainerName.utf16()));
    provider.pwszProvName = reinterpret_cast<LPWSTR>(
        const_cast<ushort *>(providerName.utf16()));
    provider.dwProvType = 0;
    provider.dwFlags = scope == domain::StoreScope::Machine ? CRYPT_MACHINE_KEYSET : 0;
    // For a CNG KSP, this field is the legacy key-spec argument passed to NCryptOpenKey.
    provider.dwKeySpec = 0;
    if (!CertSetCertificateContextProperty(certificate.get(), CERT_KEY_PROV_INFO_PROP_ID,
                                           0, &provider))
        return tl::unexpected(winError(domain::ErrorCategory::Enrollment,
            QStringLiteral("enrollment.key_reference"), GetLastError(),
            QStringLiteral("无法把签发证书关联到原 CNG 密钥容器。")));

    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD keySpec = 0;
    BOOL mustFree = FALSE;
    if (!CryptAcquireCertificatePrivateKey(
            certificate.get(), CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG |
                                   CRYPT_ACQUIRE_COMPARE_KEY_FLAG |
                                   CRYPT_ACQUIRE_SILENT_FLAG,
            nullptr, &key, &keySpec, &mustFree)) {
        const DWORD error = GetLastError();
        return tl::unexpected(winError(domain::ErrorCategory::Enrollment,
            error == static_cast<DWORD>(NTE_BAD_PUBLIC_KEY)
                ? QStringLiteral("enrollment.public_key_mismatch")
                : QStringLiteral("enrollment.private_key_unavailable"),
            error,
            error == static_cast<DWORD>(NTE_BAD_PUBLIC_KEY)
                ? QStringLiteral("签发证书的公钥与该 CSR 的原私钥不匹配，已拒绝安装。")
                : QStringLiteral("无法打开该 CSR 的原私钥；密钥可能已被删除、TPM 不可用或作用域不正确。")));
    }
    const auto keyCleanup = qScopeGuard([&] {
        if (!mustFree) return;
        if (keySpec == CERT_NCRYPT_KEY_SPEC) NCryptFreeObject(key);
        else CryptReleaseContext(static_cast<HCRYPTPROV>(key), 0);
    });
    if (keySpec != CERT_NCRYPT_KEY_SPEC)
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Enrollment,
            QStringLiteral("enrollment.not_cng_key"), 0,
            QStringLiteral("关联的私钥不是预期的 Windows CNG 密钥。"), {}});

    if (!friendlyName.trimmed().isEmpty()) {
        const QString terminated = friendlyName + QChar();
        CRYPT_DATA_BLOB blob{static_cast<DWORD>(terminated.size() * sizeof(wchar_t)),
            reinterpret_cast<BYTE *>(const_cast<ushort *>(terminated.utf16()))};
        if (!CertSetCertificateContextProperty(certificate.get(), CERT_FRIENDLY_NAME_PROP_ID,
                                               0, &blob))
            return tl::unexpected(winError(domain::ErrorCategory::Enrollment,
                QStringLiteral("enrollment.friendly_name_property"), GetLastError(),
                QStringLiteral("无法设置签发证书的显示名称。")));
    }

    const DWORD flags = (scope == domain::StoreScope::Machine
        ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER) |
        CERT_STORE_OPEN_EXISTING_FLAG;
    CertStoreHandle store(CertOpenStore(CERT_STORE_PROV_SYSTEM_W,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, flags, L"MY"));
    if (!store)
        return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
            QStringLiteral("enrollment.personal_store"), GetLastError(),
            QStringLiteral("无法打开 Windows 个人证书存储。")));
    if (!CertAddCertificateContextToStore(store.get(), certificate.get(),
                                          CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES,
                                          nullptr))
        return tl::unexpected(winError(domain::ErrorCategory::CertificateStore,
            QStringLiteral("enrollment.response_store"), GetLastError(),
            QStringLiteral("签发证书已验证，但无法写入 Windows 个人证书存储。")));
    return {};
}

} // namespace certmgr::platform::windows
