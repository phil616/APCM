#include "SigningProtocol.h"
#include "../enrollment/EnrollmentRequest.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QScopeGuard>
#include <QSslCertificate>
#include <QSslKey>
#include <QSslSocket>
#include <QUuid>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <memory>
#include <vector>
#include <cstring>
#include <ctime>

namespace certmgr::domain::signing {
namespace {
AppError invalid(const QString &message)
{
    return {ErrorCategory::Validation, QStringLiteral("signing.validation"), 0, message, {}};
}
template<class T, auto Free> using Handle = std::unique_ptr<T, decltype(Free)>;
using Cert = Handle<X509, X509_free>;
using Key = Handle<EVP_PKEY, EVP_PKEY_free>;
using Bio = Handle<BIO, BIO_free>;
Bio bio(const QByteArray &data) { return Bio(BIO_new_mem_buf(data.constData(), static_cast<int>(data.size())), BIO_free); }
Cert certificate(const QByteArray &pem)
{
    auto input = bio(pem);
    return Cert(PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr), X509_free);
}
QDateTime timeValue(const ASN1_TIME *value)
{
    tm parsed{};
    if (!value || ASN1_TIME_to_tm(value, &parsed) != 1) return {};
    return QDateTime(QDate(parsed.tm_year + 1900, parsed.tm_mon + 1, parsed.tm_mday),
                     QTime(parsed.tm_hour, parsed.tm_min, parsed.tm_sec), Qt::UTC);
}
QString decimal(const ASN1_INTEGER *value)
{
    Handle<BIGNUM, BN_free> number(ASN1_INTEGER_to_BN(value, nullptr), BN_free);
    if (!number) return {};
    char *encoded = BN_bn2dec(number.get());
    const QString result = QString::fromLatin1(encoded ? encoded : "");
    OPENSSL_free(encoded);
    return result;
}
QString nameText(X509_NAME *name)
{
    Bio output(BIO_new(BIO_s_mem()), BIO_free);
    X509_NAME_print_ex(output.get(), name, 0, XN_FLAG_RFC2253);
    char *data = nullptr;
    const long size = BIO_get_mem_data(output.get(), &data);
    return QString::fromUtf8(data, static_cast<qsizetype>(size));
}
QByteArray certDer(X509 *cert)
{
    const int size = i2d_X509(cert, nullptr);
    if (size <= 0) return {};
    QByteArray bytes(size, Qt::Uninitialized);
    auto *cursor = reinterpret_cast<unsigned char *>(bytes.data());
    i2d_X509(cert, &cursor);
    return bytes;
}
QString asnText(const ASN1_STRING *value)
{
    unsigned char *utf8 = nullptr;
    const int size = ASN1_STRING_to_UTF8(&utf8, value);
    const auto cleanup = qScopeGuard([&] { OPENSSL_free(utf8); });
    return size >= 0 ? QString::fromUtf8(reinterpret_cast<const char *>(utf8), size) : QString{};
}
Result<QVariantMap> names(GENERAL_NAMES *values)
{
    QVariantMap result{{QStringLiteral("dnsSans"), QStringList{}}, {QStringLiteral("ipSans"), QStringList{}},
                       {QStringLiteral("emailSans"), QStringList{}}, {QStringLiteral("uriSans"), QStringList{}}};
    QStringList display, identities;
    if (!values || sk_GENERAL_NAME_num(values) < 1 || sk_GENERAL_NAME_num(values) > 100)
        return tl::unexpected(invalid(QStringLiteral("CSR 必须包含 1～100 个 SAN 身份。")));
    for (int i = 0; i < sk_GENERAL_NAME_num(values); ++i) {
        const GENERAL_NAME *entry = sk_GENERAL_NAME_value(values, i);
        QString value, category, prefix, originalIdentity;
        if (entry->type == GEN_DNS) {
            value = asnText(entry->d.dNSName); originalIdentity = value;
            const QString ascii = QString::fromLatin1(QUrl::toAce(value)).toLower();
            QString domain = ascii;
            if (domain.startsWith(QStringLiteral("*."))) domain.remove(0, 2);
            static const QRegularExpression label(QStringLiteral("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"));
            bool valid = !domain.isEmpty() && domain.size() <= 253 && QHostAddress(domain).isNull();
            for (const QString &part : domain.split('.')) valid = valid && label.match(part).hasMatch();
            if (!valid) return tl::unexpected(invalid(QStringLiteral("DNS SAN 格式不合法：%1").arg(value)));
            value = ascii;
            category = QStringLiteral("dnsSans"); prefix = QStringLiteral("DNS:");
        } else if (entry->type == GEN_IPADD) {
            const QByteArray raw(reinterpret_cast<const char *>(ASN1_STRING_get0_data(entry->d.iPAddress)), ASN1_STRING_length(entry->d.iPAddress));
            QHostAddress address;
            if (raw.size() == 4) {
                const auto *p = reinterpret_cast<const unsigned char *>(raw.constData());
                address.setAddress((quint32(p[0]) << 24) | (quint32(p[1]) << 16) | (quint32(p[2]) << 8) | p[3]);
            } else if (raw.size() == 16) address.setAddress(reinterpret_cast<const quint8 *>(raw.constData()));
            else return tl::unexpected(invalid(QStringLiteral("IP SAN 编码无效。")));
            value = address.toString(); category = QStringLiteral("ipSans"); prefix = QStringLiteral("IP:");
        } else if (entry->type == GEN_EMAIL) {
            value = asnText(entry->d.rfc822Name); originalIdentity = value;
            static const QRegularExpression mail(QStringLiteral("^[!-~]+@[A-Za-z0-9.-]+$"));
            if (!mail.match(value).hasMatch() || value.count('@') != 1 || value.contains('<') || value.contains('>'))
                return tl::unexpected(invalid(QStringLiteral("email SAN 必须是无显示名的 ASCII 邮箱。")));
            value = value.left(value.indexOf('@') + 1) + value.mid(value.indexOf('@') + 1).toLower();
            category = QStringLiteral("emailSans"); prefix = QStringLiteral("email:");
        } else if (entry->type == GEN_URI) {
            value = asnText(entry->d.uniformResourceIdentifier); originalIdentity = value;
            const QUrl uri(value, QUrl::StrictMode);
            const QStringList segments = uri.path().split('/');
            if (!uri.isValid() || (uri.scheme() != QStringLiteral("https") && uri.scheme() != QStringLiteral("spiffe")) ||
                uri.host().isEmpty() || !uri.userInfo().isEmpty() || uri.port() != -1 || uri.hasQuery() || uri.hasFragment() ||
                !uri.path().startsWith('/') || value.contains('%') || value.contains('\\') || segments.contains(QStringLiteral(".")) ||
                segments.contains(QStringLiteral("..")) || value.toLatin1() != value.toUtf8() || value.contains(' '))
                return tl::unexpected(invalid(QStringLiteral("URI SAN 必须是无端口、查询、转义和相对路径的 HTTPS/SPIFFE URI。")));
            value = uri.toString(QUrl::FullyEncoded);
            category = QStringLiteral("uriSans"); prefix = QStringLiteral("URI:");
        } else return tl::unexpected(invalid(QStringLiteral("仅支持 DNS、IP、email、URI SAN；不支持 UPN/otherName。")));
        if (value.contains(QChar(0)) || value.contains(QRegularExpression(QStringLiteral("[\\x00-\\x1f\\x7f]"))))
            return tl::unexpected(invalid(QStringLiteral("SAN 包含控制字符。")));
        auto list = result.value(category).toStringList(); list.append(value); result[category] = list;
        display.append(prefix + value); identities.append(originalIdentity.isEmpty() ? value : originalIdentity);
    }
    result[QStringLiteral("sans")] = display;
    result[QStringLiteral("identities")] = identities;
    return result;
}
QVariantMap certSummary(X509 *cert)
{
    QVariantMap result{{QStringLiteral("subject"), nameText(X509_get_subject_name(cert))},
        {QStringLiteral("issuer"), nameText(X509_get_issuer_name(cert))},
        {QStringLiteral("serial"), decimal(X509_get0_serialNumber(cert))},
        {QStringLiteral("fingerprint"), fingerprint(certDer(cert))},
        {QStringLiteral("notBefore"), timeValue(X509_get0_notBefore(cert))},
        {QStringLiteral("notAfter"), timeValue(X509_get0_notAfter(cert))}};
    Handle<GENERAL_NAMES, GENERAL_NAMES_free> san(static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)), GENERAL_NAMES_free);
    if (auto parsed = names(san.get())) {
        for (auto it = parsed->cbegin(); it != parsed->cend(); ++it) result.insert(it.key(), it.value());
    }
    return result;
}
bool onlyPem(const QByteArray &pem, const QByteArray &label, int maximum)
{
    const QByteArray begin = "-----BEGIN " + label + "-----";
    const QByteArray end = "-----END " + label + "-----";
    QByteArray rest = pem.trimmed();
    int count = 0;
    while (rest.startsWith(begin)) {
        const qsizetype pos = rest.indexOf(end, begin.size());
        if (pos < 0) return false;
        rest = rest.mid(pos + end.size()).trimmed();
        ++count;
    }
    return rest.isEmpty() && count >= 1 && count <= maximum;
}
}

bool isUuid(const QString &text)
{
    static const QRegularExpression uuid(QStringLiteral("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"));
    return uuid.match(text).hasMatch() && !QUuid(text).isNull();
}
Result<QUrl> issueEndpoint(const QString &text)
{
    const QUrl url(text.trimmed(), QUrl::StrictMode);
    static const QRegularExpression path(QStringLiteral("^/signing/([0-9a-fA-F-]{36})/issue$"));
    const auto matched = path.match(url.path(QUrl::FullyEncoded));
    if (!url.isValid() || url.scheme() != QStringLiteral("https") || url.host().isEmpty() ||
        !url.userInfo().isEmpty() || url.hasQuery() || url.hasFragment() || !matched.hasMatch() || !isUuid(matched.captured(1)))
        return tl::unexpected(invalid(QStringLiteral("请输入完整 HTTPS 签发端点：https://主机/signing/<实例 UUID>/issue；不得带用户信息、查询或片段。")));
    return url;
}
Result<QUrl> consoleEndpoint(const QString &text)
{
    const QUrl url(text.trimmed(), QUrl::StrictMode);
    if (!url.isValid() || url.scheme() != QStringLiteral("https") || url.host().isEmpty() ||
        !url.userInfo().isEmpty() || url.hasQuery() || url.hasFragment() || url.path() != QStringLiteral("/api/v1"))
        return tl::unexpected(invalid(QStringLiteral("管理端地址必须是 https://管理主机/api/v1；与公开签发主机分别配置。")));
    return url;
}
bool validToken(const QByteArray &token)
{
    static const QRegularExpression pattern(QStringLiteral("^ist_[A-Za-z0-9_-]{43}$"));
    return token.size() == 47 && pattern.match(QString::fromLatin1(token)).hasMatch();
}
bool validReason(const int reason) { return reason >= 0 && reason <= 10 && reason != 7 && reason != 8; }
QString fingerprint(const QByteArray &bytes) { return QString::fromLatin1(QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex()); }
Result<QByteArray> readFile(const QUrl &url, const qsizetype limit)
{
    QFile input(url.toLocalFile());
    if (!url.isLocalFile() || !input.open(QIODevice::ReadOnly) || input.size() < 1 || input.size() > limit)
        return tl::unexpected(invalid(QStringLiteral("无法读取本地文件，或文件超出允许大小。")));
    QByteArray data = input.read(limit + 1);
    if (input.error() != QFile::NoError || data.size() > limit)
        return tl::unexpected(invalid(QStringLiteral("读取文件失败或文件过大。")));
    return data;
}
Result<QByteArray> canonicalCsrPem(const QByteArray &pem)
{
    if (pem.size() > 65536 || (!onlyPem(pem, "CERTIFICATE REQUEST", 1) && !onlyPem(pem, "NEW CERTIFICATE REQUEST", 1)))
        return tl::unexpected(invalid(QStringLiteral("请提供单个 PKCS#10 CSR，不能包含私钥、证书或多份申请，大小不得超过 64 KiB。")));
    auto input = bio(pem);
    char *type = nullptr, *headers = nullptr;
    unsigned char *data = nullptr;
    long size = 0;
    const auto cleanup = qScopeGuard([&] { OPENSSL_free(type); OPENSSL_free(headers); OPENSSL_free(data); });
    if (PEM_read_bio(input.get(), &type, &headers, &data, &size) != 1 || !type || !headers || *headers != '\0' ||
        (QByteArray(type) != "CERTIFICATE REQUEST" && QByteArray(type) != "NEW CERTIFICATE REQUEST"))
        return tl::unexpected(invalid(QStringLiteral("无法解析 PKCS#10 CSR，或 PEM 包含不支持的元数据头。")));
    const auto *cursor = data;
    Handle<X509_REQ, X509_REQ_free> request(d2i_X509_REQ(nullptr, &cursor, size), X509_REQ_free);
    if (!request || cursor != data + size) return tl::unexpected(invalid(QStringLiteral("CSR DER 编码无效，或包含多余数据。")));
    // Rewrap the original DER bytes. Never edit Subject/SAN/extensions or re-sign imported requests.
    const auto encoded = domain::encodeCsrPem(QByteArray(reinterpret_cast<const char *>(data), static_cast<qsizetype>(size)));
    if (encoded.size() > 65536) return tl::unexpected(invalid(QStringLiteral("标准 PEM 编码后的 CSR 超过 64 KiB。")));
    return encoded;
}

Result<QVariantMap> inspectCsr(const QByteArray &pem)
{
    if (pem.size() > 65536 || !onlyPem(pem, "CERTIFICATE REQUEST", 1))
        return tl::unexpected(invalid(QStringLiteral("CSR 必须是单个标准 CERTIFICATE REQUEST PEM，且不超过 64 KiB。")));
    auto input = bio(pem);
    Handle<X509_REQ, X509_REQ_free> csr(PEM_read_bio_X509_REQ(input.get(), nullptr, nullptr, nullptr), X509_REQ_free);
    if (!csr) return tl::unexpected(invalid(QStringLiteral("无法解析 PKCS#10 CSR。")));
    Key key(X509_REQ_get_pubkey(csr.get()), EVP_PKEY_free);
    if (!key || X509_REQ_verify(csr.get(), key.get()) != 1)
        return tl::unexpected(invalid(QStringLiteral("CSR 签名校验失败。")));
    QString algorithm;
    const int bits = EVP_PKEY_get_bits(key.get());
    if (EVP_PKEY_is_a(key.get(), "RSA") || EVP_PKEY_is_a(key.get(), "RSA-PSS")) {
        BIGNUM *raw = nullptr;
        if ((bits != 2048 && bits != 3072 && bits != 4096) || EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_RSA_E, &raw) != 1)
            return tl::unexpected(invalid(QStringLiteral("仅支持 RSA 2048/3072/4096。")));
        Handle<BIGNUM, BN_free> exponent(raw, BN_free);
        if (BN_num_bits(exponent.get()) < 17 || BN_is_negative(exponent.get()) || !BN_is_odd(exponent.get()) ||
            (BN_num_bits(exponent.get()) == 17 && BN_get_word(exponent.get()) < 65537))
            return tl::unexpected(invalid(QStringLiteral("RSA 公钥指数必须至少为 65537。")));
        algorithm = QStringLiteral("RSA-%1").arg(bits);
    } else if (EVP_PKEY_is_a(key.get(), "EC")) {
        char curve[80]{}; size_t size = 0;
        EVP_PKEY_get_utf8_string_param(key.get(), OSSL_PKEY_PARAM_GROUP_NAME, curve, sizeof(curve), &size);
        if (QByteArray(curve) != "prime256v1" && QByteArray(curve) != "secp384r1")
            return tl::unexpected(invalid(QStringLiteral("仅支持 ECDSA P-256/P-384。")));
        algorithm = QStringLiteral("ECDSA-P%1").arg(bits);
    } else return tl::unexpected(invalid(QStringLiteral("不支持此 CSR 公钥算法。")));
    const int nid = X509_REQ_get_signature_nid(csr.get());
    if (nid == NID_rsassaPss) {
        const X509_ALGOR *alg = nullptr;
        X509_REQ_get0_signature(csr.get(), nullptr, &alg);
        const void *parameter = nullptr; int type = 0;
        X509_ALGOR_get0(nullptr, &type, &parameter, alg);
        if (type != V_ASN1_SEQUENCE) return tl::unexpected(invalid(QStringLiteral("RSA-PSS 签名参数无效。")));
        auto *sequence = static_cast<const ASN1_STRING *>(parameter);
        const auto *cursor = ASN1_STRING_get0_data(sequence);
        Handle<RSA_PSS_PARAMS, RSA_PSS_PARAMS_free> pss(d2i_RSA_PSS_PARAMS(nullptr, &cursor, ASN1_STRING_length(sequence)), RSA_PSS_PARAMS_free);
        const int hash = pss && pss->hashAlgorithm ? OBJ_obj2nid(pss->hashAlgorithm->algorithm) : NID_sha1;
        if (hash != NID_sha256 && hash != NID_sha384 && hash != NID_sha512)
            return tl::unexpected(invalid(QStringLiteral("RSA-PSS 必须使用 SHA-256/384/512。")));
    } else if (nid != NID_sha256WithRSAEncryption && nid != NID_sha384WithRSAEncryption && nid != NID_sha512WithRSAEncryption &&
               nid != NID_ecdsa_with_SHA256 && nid != NID_ecdsa_with_SHA384 && nid != NID_ecdsa_with_SHA512)
        return tl::unexpected(invalid(QStringLiteral("CSR 必须使用 SHA-256/384/512 签名。")));
    auto *extensions = X509_REQ_get_extensions(csr.get());
    const auto cleanup = qScopeGuard([&] { sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free); });
    if (!extensions || sk_X509_EXTENSION_num(extensions) != 1 ||
        OBJ_obj2nid(X509_EXTENSION_get_object(sk_X509_EXTENSION_value(extensions, 0))) != NID_subject_alt_name)
        return tl::unexpected(invalid(QStringLiteral("独立签发 CSR 只能包含 SAN 扩展，不能包含 KU、EKU 或 BasicConstraints。请使用此页面的专用申请构造器。")));
    Handle<GENERAL_NAMES, GENERAL_NAMES_free> san(static_cast<GENERAL_NAMES *>(X509V3_EXT_d2i(sk_X509_EXTENSION_value(extensions, 0))), GENERAL_NAMES_free);
    auto result = names(san.get());
    if (!result) return result;
    X509_NAME *subject = X509_REQ_get_subject_name(csr.get());
    QHash<int, int> counts;
    for (int i = 0; i < X509_NAME_entry_count(subject); ++i) {
        auto *entry = X509_NAME_get_entry(subject, i);
        const int attr = OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry));
        QString field;
        switch (attr) {
        case NID_commonName: field = QStringLiteral("CN"); break;
        case NID_countryName: field = QStringLiteral("C"); break;
        case NID_stateOrProvinceName: field = QStringLiteral("ST"); break;
        case NID_localityName: field = QStringLiteral("L"); break;
        case NID_organizationName: field = QStringLiteral("O"); break;
        case NID_organizationalUnitName: field = QStringLiteral("OU"); break;
        default: return tl::unexpected(invalid(QStringLiteral("Subject 只能包含 CN、C、ST、L、O、OU。")));
        }
        const QString value = asnText(X509_NAME_ENTRY_get_data(entry));
        if (++counts[attr] > (attr == NID_commonName ? 1 : 8) || value.toUtf8().size() > 128 ||
            value.contains(QRegularExpression(QStringLiteral("[\\x00-\\x1f\\x7f]"))))
            return tl::unexpected(invalid(QStringLiteral("Subject 字段过长、重复或含控制字符。")));
        if (attr == NID_countryName && !QRegularExpression(QStringLiteral("^[A-Z]{2}$")).match(value).hasMatch())
            return tl::unexpected(invalid(QStringLiteral("国家 C 必须是两位大写 ASCII 字母。")));
        if (attr == NID_commonName && !value.isEmpty() && !result->value(QStringLiteral("identities")).toStringList().contains(value))
            return tl::unexpected(invalid(QStringLiteral("CN 必须与一个 SAN 身份完全相同；请主动调整，不会自动改写 CN。")));
        result->insert(field, value);
    }
    result->insert(QStringLiteral("subject"), nameText(subject));
    result->insert(QStringLiteral("algorithm"), algorithm);
    return result;
}

Result<QByteArray> issueRequestBody(const QByteArray &csr, const int validitySeconds)
{
    if (validitySeconds != 0 && (validitySeconds < 60 || validitySeconds > 34300800))
        return tl::unexpected(invalid(QStringLiteral("有效期为 0（服务器默认）或 60～34300800 秒。")));
    if (auto checked = inspectCsr(csr); !checked) return tl::unexpected(checked.error());
    return QJsonDocument(QJsonObject{{QStringLiteral("csr_pem"), QString::fromUtf8(csr)},
        {QStringLiteral("validity_seconds"), validitySeconds}}).toJson(QJsonDocument::Compact);
}

Result<QVariantMap> inspectCertificate(const QJsonObject &record, const QByteArray &csrPem,
                                      const QStringList &expectedEkus, const QByteArray &trustedRoots)
{
    for (const QString &field : {QStringLiteral("id"), QStringLiteral("instance_id"), QStringLiteral("credential_id")})
        if (!record.value(field).isString() || !isUuid(record.value(field).toString()))
            return tl::unexpected(invalid(QStringLiteral("证书响应缺少合法 UUID 字段。")));
    const QString status = record.value(QStringLiteral("status")).toString();
    if (status != QStringLiteral("good") && status != QStringLiteral("expired") && status != QStringLiteral("revoked"))
        return tl::unexpected(invalid(QStringLiteral("证书响应包含未知状态。")));
    const bool revoked = status == QStringLiteral("revoked");
    const QDateTime revokedAt = QDateTime::fromString(record.value(QStringLiteral("revoked_at")).toString(), Qt::ISODate);
    if ((revoked && (!revokedAt.isValid() || !record.value(QStringLiteral("revocation_reason")).isDouble() ||
                     !validReason(record.value(QStringLiteral("revocation_reason")).toInt(-1)))) ||
        (!revoked && (!record.value(QStringLiteral("revoked_at")).isNull() || !record.value(QStringLiteral("revocation_reason")).isNull())))
        return tl::unexpected(invalid(QStringLiteral("证书吊销字段与当前状态不一致。")));
    const QByteArray pem = record.value(QStringLiteral("certificate_pem")).toString().toUtf8();
    const QByteArray chainPem = record.value(QStringLiteral("chain_pem")).toString().toUtf8();
    if (!onlyPem(pem, "CERTIFICATE", 1) || !onlyPem(chainPem, "CERTIFICATE", 9))
        return tl::unexpected(invalid(QStringLiteral("叶证书或完整链 PEM 结构无效。")));
    auto leaf = certificate(pem);
    Handle<BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free> constraints(leaf ? static_cast<BASIC_CONSTRAINTS *>(X509_get_ext_d2i(leaf.get(), NID_basic_constraints, nullptr, nullptr)) : nullptr, BASIC_CONSTRAINTS_free);
    if (!leaf || !constraints || constraints->ca || X509_check_ca(leaf.get()) != 0)
        return tl::unexpected(invalid(QStringLiteral("签发结果必须明确为 CA:FALSE 的叶证书。")));
    auto result = certSummary(leaf.get());
    if (result.value(QStringLiteral("serial")).toString().startsWith('-') || result.value(QStringLiteral("serial")).toString() == QStringLiteral("0") ||
        !record.value(QStringLiteral("serial")).isString() ||
        record.value(QStringLiteral("serial")).toString() != result.value(QStringLiteral("serial")).toString() ||
        record.value(QStringLiteral("fingerprint_sha256")).toString() != result.value(QStringLiteral("fingerprint")).toString())
        return tl::unexpected(invalid(QStringLiteral("服务器返回的序列号或 SHA-256 指纹与证书不一致。")));
    for (const auto &pair : {qMakePair(QStringLiteral("not_before"), QStringLiteral("notBefore")),
                             qMakePair(QStringLiteral("not_after"), QStringLiteral("notAfter"))}) {
        const QDateTime time = QDateTime::fromString(record.value(pair.first).toString(), Qt::ISODate);
        if (!time.isValid() || time != result.value(pair.second).toDateTime())
            return tl::unexpected(invalid(QStringLiteral("服务器返回的有效期与证书不一致。")));
    }
    Handle<GENERAL_NAMES, GENERAL_NAMES_free> leafSan(static_cast<GENERAL_NAMES *>(X509_get_ext_d2i(leaf.get(), NID_subject_alt_name, nullptr, nullptr)), GENERAL_NAMES_free);
    auto leafNames = names(leafSan.get());
    if (!leafNames) return tl::unexpected(leafNames.error());
    if (!csrPem.isEmpty()) {
        auto csrInfo = inspectCsr(csrPem);
        if (!csrInfo) return tl::unexpected(csrInfo.error());
        auto input = bio(csrPem);
        Handle<X509_REQ, X509_REQ_free> csr(PEM_read_bio_X509_REQ(input.get(), nullptr, nullptr, nullptr), X509_REQ_free);
        Key requested(X509_REQ_get_pubkey(csr.get()), EVP_PKEY_free);
        Key received(X509_get_pubkey(leaf.get()), EVP_PKEY_free);
        if (EVP_PKEY_eq(requested.get(), received.get()) != 1 ||
            X509_NAME_cmp(X509_REQ_get_subject_name(csr.get()), X509_get_subject_name(leaf.get())) != 0)
            return tl::unexpected(invalid(QStringLiteral("签发证书的公钥或 Subject 与原 CSR 不匹配，禁止安装。")));
        auto original = csrInfo->value(QStringLiteral("sans")).toStringList();
        auto actual = leafNames->value(QStringLiteral("sans")).toStringList();
        original.sort(); actual.sort();
        if (original != actual) return tl::unexpected(invalid(QStringLiteral("签发证书的 SAN 与原 CSR 不匹配。")));
    }
    Handle<EXTENDED_KEY_USAGE, EXTENDED_KEY_USAGE_free> usage(static_cast<EXTENDED_KEY_USAGE *>(X509_get_ext_d2i(leaf.get(), NID_ext_key_usage, nullptr, nullptr)), EXTENDED_KEY_USAGE_free);
    QStringList ekus;
    if (!usage) return tl::unexpected(invalid(QStringLiteral("签发证书缺少 EKU。")));
    for (int i = 0; i < sk_ASN1_OBJECT_num(usage.get()); ++i) {
        const int nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(usage.get(), i));
        if (nid == NID_server_auth) ekus.append(QStringLiteral("server_auth"));
        else if (nid == NID_client_auth) ekus.append(QStringLiteral("client_auth"));
        else return tl::unexpected(invalid(QStringLiteral("签发证书包含协议不支持的 EKU。")));
    }
    ekus.sort(); auto expected = expectedEkus; expected.sort();
    if (ekus.isEmpty() || (!expected.isEmpty() && ekus != expected))
        return tl::unexpected(invalid(QStringLiteral("签发证书 EKU 与预期用途不符；用途由实例和 Token 策略决定，请联系所有者。")));
    Handle<ASN1_BIT_STRING, ASN1_BIT_STRING_free> keyUsage(static_cast<ASN1_BIT_STRING *>(X509_get_ext_d2i(leaf.get(), NID_key_usage, nullptr, nullptr)), ASN1_BIT_STRING_free);
    if (!keyUsage || ASN1_BIT_STRING_get_bit(keyUsage.get(), 0) != 1 || ASN1_BIT_STRING_get_bit(keyUsage.get(), 5) != 0)
        return tl::unexpected(invalid(QStringLiteral("叶证书 Key Usage 无效。")));
    auto chainInput = bio(chainPem);
    std::vector<Cert> chain;
    while (auto *next = PEM_read_bio_X509(chainInput.get(), nullptr, nullptr, nullptr)) chain.emplace_back(next, X509_free);
    if (chain.empty() || X509_cmp(leaf.get(), chain.front().get()) != 0)
        return tl::unexpected(invalid(QStringLiteral("完整链必须以相同叶证书开头。")));
    for (size_t i = 0; i + 1 < chain.size(); ++i) {
        Key issuer(X509_get_pubkey(chain[i + 1].get()), EVP_PKEY_free);
        if (X509_check_issued(chain[i + 1].get(), chain[i].get()) != X509_V_OK || X509_verify(chain[i].get(), issuer.get()) != 1)
            return tl::unexpected(invalid(QStringLiteral("返回的证书链顺序或签名不正确。")));
    }
    Handle<X509_STORE, X509_STORE_free> store(X509_STORE_new(), X509_STORE_free);
    X509_STORE_set_default_paths(store.get());
    QList<QSslCertificate> roots = QSslConfiguration::systemCaCertificates();
    if (!trustedRoots.isEmpty()) {
        const auto configured = QSslCertificate::fromData(trustedRoots, QSsl::Pem);
        if (configured.isEmpty()) return tl::unexpected(invalid(QStringLiteral("业务信任根文件无法解析。")));
        roots.append(configured);
    }
    for (const auto &root : roots) {
        auto native = certificate(root.toPem());
        if (native && X509_check_ca(native.get()) > 0) X509_STORE_add_cert(store.get(), native.get());
    }
    auto *intermediates = sk_X509_new_null();
    const auto stackCleanup = qScopeGuard([&] { sk_X509_free(intermediates); });
    for (size_t i = 1; i < chain.size(); ++i) sk_X509_push(intermediates, chain[i].get());
    Handle<X509_STORE_CTX, X509_STORE_CTX_free> context(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    bool trusted = X509_STORE_CTX_init(context.get(), store.get(), leaf.get(), intermediates) == 1 && X509_verify_cert(context.get()) == 1;
    QString trustError;
    if (!trusted) trustError = QString::fromLatin1(X509_verify_cert_error_string(X509_STORE_CTX_get_error(context.get())));
    // Verify each requested purpose, rather than accepting an EKU intersection implicitly.
    if (trusted) for (const QString &eku : ekus) {
        Handle<X509_STORE_CTX, X509_STORE_CTX_free> purpose(X509_STORE_CTX_new(), X509_STORE_CTX_free);
        X509_STORE_CTX_init(purpose.get(), store.get(), leaf.get(), intermediates);
        X509_STORE_CTX_set_purpose(purpose.get(), eku == QStringLiteral("server_auth") ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT);
        if (X509_verify_cert(purpose.get()) != 1) {
            trusted = false;
            trustError = QString::fromLatin1(X509_verify_cert_error_string(X509_STORE_CTX_get_error(purpose.get())));
            break;
        }
    }
    const auto now = QDateTime::currentDateTimeUtc();
    const bool current = now >= result.value(QStringLiteral("notBefore")).toDateTime() && now < result.value(QStringLiteral("notAfter")).toDateTime();
    result[QStringLiteral("chainTrusted")] = trusted;
    result[QStringLiteral("trustError")] = trustError;
    result[QStringLiteral("current")] = current;
    result[QStringLiteral("matchedCsr")] = !csrPem.isEmpty();
    result[QStringLiteral("ekus")] = ekus;
    result[QStringLiteral("status")] = status;
    result[QStringLiteral("installable")] = trusted && current && !csrPem.isEmpty() && status == QStringLiteral("good");
    return result;
}

Result<QVariantMap> inspectIssuer(const QByteArray &der)
{
    const auto *cursor = reinterpret_cast<const unsigned char *>(der.constData());
    Cert issuer(d2i_X509(nullptr, &cursor, static_cast<long>(der.size())), X509_free);
    if (!issuer || cursor != reinterpret_cast<const unsigned char *>(der.constData()) + der.size() || X509_check_ca(issuer.get()) <= 0)
        return tl::unexpected(invalid(QStringLiteral("签发者下载内容不是单张 DER CA 证书。")));
    auto result = certSummary(issuer.get());
    result[QStringLiteral("note")] = QStringLiteral("这是签发实例公开的 CA 信息；不会自动加入系统或业务信任根。下载成功不代表 Token 有效。");
    return result;
}
Result<QVariantMap> inspectCrl(const QByteArray &der, const QByteArray &issuerDer, const QUrl &issueUrl)
{
    const auto *cursor = reinterpret_cast<const unsigned char *>(der.constData());
    Handle<X509_CRL, X509_CRL_free> crl(d2i_X509_CRL(nullptr, &cursor, static_cast<long>(der.size())), X509_CRL_free);
    if (!crl || cursor != reinterpret_cast<const unsigned char *>(der.constData()) + der.size())
        return tl::unexpected(invalid(QStringLiteral("下载内容不是单份 DER CRL。")));
    const auto *issuerCursor = reinterpret_cast<const unsigned char *>(issuerDer.constData());
    Cert issuer(d2i_X509(nullptr, &issuerCursor, static_cast<long>(issuerDer.size())), X509_free);
    Key key(issuer ? X509_get_pubkey(issuer.get()) : nullptr, EVP_PKEY_free);
    if (!issuer || !key || X509_NAME_cmp(X509_CRL_get_issuer(crl.get()), X509_get_subject_name(issuer.get())) != 0 || X509_CRL_verify(crl.get(), key.get()) != 1)
        return tl::unexpected(invalid(QStringLiteral("CRL 签名无法与当前实例的签发者证书匹配；请先下载该实例的签发者证书。")));
    int critical = -1;
    Handle<ISSUING_DIST_POINT, ISSUING_DIST_POINT_free> idp(static_cast<ISSUING_DIST_POINT *>(X509_CRL_get_ext_d2i(crl.get(), NID_issuing_distribution_point, &critical, nullptr)), ISSUING_DIST_POINT_free);
    QUrl expected = issueUrl; expected.setPath(issueUrl.path().chopped(5) + QStringLiteral("crl"));
    bool scoped = false;
    if (idp && critical == 1 && idp->distpoint && idp->distpoint->type == 0 && idp->onlyuser && !idp->onlyCA && !idp->indirectCRL) {
        auto *names = idp->distpoint->name.fullname;
        for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
            auto *name = sk_GENERAL_NAME_value(names, i);
            if (name->type == GEN_URI && asnText(name->d.uniformResourceIdentifier) == expected.toString()) scoped = true;
        }
    }
    if (!scoped) return tl::unexpected(invalid(QStringLiteral("CRL 缺少匹配当前实例 URL 的 critical IDP 叶证书作用域，不能用于此实例。")));
    const auto thisUpdate = timeValue(X509_CRL_get0_lastUpdate(crl.get()));
    const auto nextUpdate = timeValue(X509_CRL_get0_nextUpdate(crl.get()));
    const auto now = QDateTime::currentDateTimeUtc();
    if (!thisUpdate.isValid() || !nextUpdate.isValid() || thisUpdate > now || nextUpdate <= now)
        return tl::unexpected(invalid(QStringLiteral("CRL 尚未生效、已过期或缺少有效更新时间。")));
    QVariantList revoked;
    auto *entries = X509_CRL_get_REVOKED(crl.get());
    for (int i = 0; i < sk_X509_REVOKED_num(entries); ++i) {
        auto *entry = sk_X509_REVOKED_value(entries, i);
        revoked.append(QVariantMap{{QStringLiteral("serial"), decimal(X509_REVOKED_get0_serialNumber(entry))},
            {QStringLiteral("revokedAt"), timeValue(X509_REVOKED_get0_revocationDate(entry))}});
    }
    return QVariantMap{{QStringLiteral("issuer"), nameText(X509_CRL_get_issuer(crl.get()))},
        {QStringLiteral("thisUpdate"), thisUpdate}, {QStringLiteral("nextUpdate"), nextUpdate},
        {QStringLiteral("count"), revoked.size()}, {QStringLiteral("entries"), revoked},
        {QStringLiteral("note"), QStringLiteral("已核对 CRL 签名、时间和当前实例的 critical IDP 作用域；签发者信任仍需由业务信任根确认。")}};
}

Result<void> validatePolicy(const QJsonObject &p)
{
    const QStringList fields{QStringLiteral("version"), QStringLiteral("allowed_dns_names"), QStringLiteral("allowed_ip_ranges"),
        QStringLiteral("allowed_email_domains"), QStringLiteral("allowed_uri_prefixes"), QStringLiteral("allow_wildcards"),
        QStringLiteral("extended_key_usages"), QStringLiteral("default_validity_seconds"), QStringLiteral("max_validity_seconds"), QStringLiteral("max_sans")};
    for (auto it = p.begin(); it != p.end(); ++it) if (!fields.contains(it.key())) return tl::unexpected(invalid(QStringLiteral("策略包含未知字段。")));
    auto integer = [&](const QString &key, int lo, int hi) {
        const auto value = p.value(key); const double n = value.toDouble(-1);
        return value.isDouble() && n >= lo && n <= hi && n == static_cast<int>(n);
    };
    if (!integer(QStringLiteral("version"), 1, 1) || !p.value(QStringLiteral("allow_wildcards")).isBool() ||
        !integer(QStringLiteral("default_validity_seconds"), 60, 34300800) || !integer(QStringLiteral("max_validity_seconds"), 60, 34300800) ||
        !integer(QStringLiteral("max_sans"), 1, 100) || p.value(QStringLiteral("default_validity_seconds")).toInt() > p.value(QStringLiteral("max_validity_seconds")).toInt())
        return tl::unexpected(invalid(QStringLiteral("策略版本、有效期、SAN 上限或通配符设置无效。")));
    int identities = 0;
    for (const QString &field : fields.mid(1, 4)) {
        const auto value = p.value(field);
        if (value.isUndefined() || value.isNull()) continue;
        if (!value.isArray() || value.toArray().size() > 100) return tl::unexpected(invalid(QStringLiteral("每类白名单最多 100 条。")));
        for (const auto &entry : value.toArray()) if (!entry.isString() || entry.toString().trimmed().isEmpty()) return tl::unexpected(invalid(QStringLiteral("白名单必须是非空字符串数组。")));
        identities += value.toArray().size();
    }
    const auto ekus = p.value(QStringLiteral("extended_key_usages")).toArray();
    if (!identities || ekus.isEmpty() || ekus.size() > 2 || (ekus.size() == 2 && ekus[0] == ekus[1]))
        return tl::unexpected(invalid(QStringLiteral("至少配置一类身份白名单和一个不重复的 EKU。")));
    for (const auto &entry : ekus) if (entry != QJsonValue(QStringLiteral("server_auth")) && entry != QJsonValue(QStringLiteral("client_auth"))) return tl::unexpected(invalid(QStringLiteral("仅支持 server_auth/client_auth。")));
    return {};
}
Result<void> validateCaImport(const QByteArray &pem, const QByteArray &privateKey, const QByteArray &chain)
{
    auto ca = certificate(pem); auto keyInput = bio(privateKey);
    Key key(PEM_read_bio_PrivateKey(keyInput.get(), nullptr, [](char *, int, int, void *) { return 0; }, nullptr), EVP_PKEY_free);
    if (!onlyPem(pem, "CERTIFICATE", 1) || !ca || !key || X509_check_private_key(ca.get(), key.get()) != 1 || X509_check_ca(ca.get()) <= 0)
        return tl::unexpected(invalid(QStringLiteral("CA 证书与未加密 PEM 私钥不匹配，或证书不是有效 CA。")));
    if (!chain.isEmpty() && !onlyPem(chain, "CERTIFICATE", 7)) return tl::unexpected(invalid(QStringLiteral("上级链必须是最多 7 张 CA 证书组成的 PEM。")));
    Handle<ASN1_BIT_STRING, ASN1_BIT_STRING_free> usage(static_cast<ASN1_BIT_STRING *>(X509_get_ext_d2i(ca.get(), NID_key_usage, nullptr, nullptr)), ASN1_BIT_STRING_free);
    if (!usage || !ASN1_BIT_STRING_get_bit(usage.get(), 5) || !ASN1_BIT_STRING_get_bit(usage.get(), 6) || X509_get_ext_by_NID(ca.get(), NID_subject_key_identifier, -1) < 0)
        return tl::unexpected(invalid(QStringLiteral("签发 CA 必须包含 keyCertSign、cRLSign 和 SKI。")));
    return {};
}

Result<QSslConfiguration> transportConfiguration(const QVariantMap &settings, QByteArray password, const bool loadIdentity)
{
    const auto clearPassword = qScopeGuard([&] { if (!password.isEmpty()) OPENSSL_cleanse(password.data(), static_cast<size_t>(password.size())); });
    if (!QSslSocket::supportsSsl()) return tl::unexpected(invalid(QStringLiteral("本机 Qt TLS 后端不可用，请检查 OpenSSL/Qt TLS 运行库。")));
    QSslConfiguration tls = QSslConfiguration::defaultConfiguration();
    tls.setProtocol(QSsl::TlsV1_2OrLater);
    tls.setPeerVerifyMode(QSslSocket::VerifyPeer);
    tls.setLocalCertificateChain({}); tls.setPrivateKey(QSslKey{});
    const QUrl caUrl(settings.value(QStringLiteral("serverCaFile")).toString());
    if (!caUrl.isEmpty()) {
        auto data = readFile(caUrl, 1024 * 1024); if (!data) return tl::unexpected(data.error());
        auto roots = QSslCertificate::fromData(*data, QSsl::Pem);
        if (roots.isEmpty()) roots = QSslCertificate::fromData(*data, QSsl::Der);
        if (roots.isEmpty()) return tl::unexpected(invalid(QStringLiteral("HTTPS 服务器信任根文件无效。")));
        tls.addCaCertificates(roots);
    }
    const QUrl identityUrl(settings.value(QStringLiteral("clientCertificateFile")).toString());
    if (loadIdentity && !identityUrl.isEmpty()) {
        auto data = readFile(identityUrl, 4 * 1024 * 1024); if (!data) return tl::unexpected(data.error());
        const auto clearInput = qScopeGuard([&] { OPENSSL_cleanse(data->data(), static_cast<size_t>(data->size())); });
        QSslKey qtKey; QSslCertificate qtCert; QList<QSslCertificate> chain;
        const QUrl keyUrl(settings.value(QStringLiteral("clientKeyFile")).toString());
        if (keyUrl.isEmpty()) {
            const auto *cursor = reinterpret_cast<const unsigned char *>(data->constData());
            Handle<PKCS12, PKCS12_free> bundle(d2i_PKCS12(nullptr, &cursor, static_cast<long>(data->size())), PKCS12_free);
            EVP_PKEY *rawKey = nullptr; X509 *rawCert = nullptr; STACK_OF(X509) *rawChain = nullptr;
            if (!bundle || PKCS12_parse(bundle.get(), password.constData(), &rawKey, &rawCert, &rawChain) != 1) {
                EVP_PKEY_free(rawKey); X509_free(rawCert); sk_X509_pop_free(rawChain, X509_free);
                return tl::unexpected(invalid(QStringLiteral("无法加载通信 mTLS P12/PFX；请检查文件和密码。")));
            }
            Key key(rawKey, EVP_PKEY_free); Cert cert(rawCert, X509_free);
            const auto chainCleanup = qScopeGuard([&] { sk_X509_pop_free(rawChain, X509_free); });
            if (X509_check_private_key(cert.get(), key.get()) != 1) return tl::unexpected(invalid(QStringLiteral("通信证书与私钥不匹配。")));
            Bio keyOut(BIO_new(BIO_s_mem()), BIO_free);
            PEM_write_bio_PrivateKey(keyOut.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr);
            char *bytes = nullptr; const long size = BIO_get_mem_data(keyOut.get(), &bytes);
            QByteArray encoded(bytes, static_cast<qsizetype>(size));
            qtKey = QSslKey(encoded, EVP_PKEY_is_a(key.get(), "EC") ? QSsl::Ec : QSsl::Rsa);
            OPENSSL_cleanse(encoded.data(), static_cast<size_t>(encoded.size()));
            OPENSSL_cleanse(bytes, static_cast<size_t>(size));
            qtCert = QSslCertificate(certDer(cert.get()), QSsl::Der);
            for (int i = 0; i < sk_X509_num(rawChain); ++i) chain.append(QSslCertificate(certDer(sk_X509_value(rawChain, i)), QSsl::Der));
        } else {
            auto keyData = readFile(keyUrl, 256 * 1024); if (!keyData) return tl::unexpected(keyData.error());
            const auto clearKey = qScopeGuard([&] { OPENSSL_cleanse(keyData->data(), static_cast<size_t>(keyData->size())); });
            auto keyInput = bio(*keyData);
            auto callback = [](char *out, int size, int, void *user) -> int {
                const auto *pass = static_cast<QByteArray *>(user);
                const int copied = qMin(size, static_cast<int>(pass->size()));
                memcpy(out, pass->constData(), static_cast<size_t>(copied)); return copied;
            };
            Key key(PEM_read_bio_PrivateKey(keyInput.get(), nullptr, callback, &password), EVP_PKEY_free);
            auto cert = certificate(*data);
            if (!cert || !key || X509_check_private_key(cert.get(), key.get()) != 1)
                return tl::unexpected(invalid(QStringLiteral("通信 mTLS PEM 证书与私钥不匹配，或私钥密码错误。")));
            auto certificates = QSslCertificate::fromData(*data, QSsl::Pem);
            if (certificates.isEmpty()) return tl::unexpected(invalid(QStringLiteral("通信证书文件无效。")));
            qtCert = certificates.takeFirst(); chain = certificates;
            qtKey = QSslKey(*keyData, EVP_PKEY_is_a(key.get(), "EC") ? QSsl::Ec : QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey, password);
        }
        if (qtKey.isNull() || qtCert.isNull() || qtCert.effectiveDate() > QDateTime::currentDateTimeUtc() || qtCert.expiryDate() <= QDateTime::currentDateTimeUtc())
            return tl::unexpected(invalid(QStringLiteral("通信 mTLS 证书或私钥无效，或证书不在有效期内。")));
        chain.prepend(qtCert); tls.setLocalCertificateChain(chain); tls.setPrivateKey(qtKey);
    }
    return tls;
}
QString transportIdentitySummary(const QSslConfiguration &configuration)
{
    const auto cert = configuration.localCertificate();
    if (cert.isNull()) return QStringLiteral("未加载通信客户端证书");
    return QStringLiteral("%1 · SHA-256 %2 · 到期 %3（仅当前解锁会话）")
        .arg(cert.subjectInfo(QSslCertificate::CommonName).join(QStringLiteral(", ")),
             fingerprint(cert.toDer()), cert.expiryDate().toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm")));
}
QString safeProblem(const int status, const QByteArray &body, const QByteArray &contentType)
{
    QString hint;
    switch (status) {
    case 400: hint = QStringLiteral("请求格式错误。"); break;
    case 401: hint = QStringLiteral("凭据无效、已过期/撤销、scope 不足，或所有者账户不可用。请检查原签发 Token。"); break;
    case 403: hint = QStringLiteral("实例可能已停用、额度耗尽或当前操作被拒绝。"); break;
    case 404: hint = QStringLiteral("实例/证书不可见；请检查 UUID 和原签发凭据。"); break;
    case 409: hint = QStringLiteral("幂等请求内容或吊销原因冲突；请恢复原报文和原原因。"); break;
    case 413: hint = QStringLiteral("请求体过大。"); break;
    case 421: hint = QStringLiteral("主机名与部署不匹配，请检查公开端点和管理端主机。"); break;
    case 422: hint = QStringLiteral("CSR、身份白名单、有效期或 CA 策略校验失败。"); break;
    case 429: hint = QStringLiteral("服务限速，请等待 Retry-After 指定时间后原样重试。"); break;
    default: hint = QStringLiteral("服务器或反向代理返回异常；写操作的结果可能尚未确定。"); break;
    }
    if (contentType.toLower().contains("application/problem+json")) {
        const auto problem = QJsonDocument::fromJson(body).object();
        QString detail = problem.value(QStringLiteral("detail")).toString().left(1200);
        detail.replace(QRegularExpression(QStringLiteral("ist_[A-Za-z0-9_-]+")), QStringLiteral("[Token 已隐藏]"));
        detail.replace(QRegularExpression(QStringLiteral("-----BEGIN[\\s\\S]*")), QStringLiteral("[证书/密钥内容已隐藏]"));
        detail.remove(QRegularExpression(QStringLiteral("[\\x00-\\x08\\x0b-\\x1f\\x7f]")));
        if (!detail.isEmpty()) hint += QStringLiteral("\n") + detail;
    }
    return QStringLiteral("HTTP %1：%2").arg(status).arg(hint);
}
} // namespace certmgr::domain::signing
