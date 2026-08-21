#include "TemplateService.h"

#include <QHostInfo>
#include <QUuid>

namespace certmgr::services {

std::vector<domain::CertificateTemplate> TemplateService::builtInTemplates() const
{
    domain::CertificateTemplate device;
    device.id = QStringLiteral("windows-device-mtls");
    device.name = QStringLiteral("Windows 设备 mTLS");
    device.version = 1;
    device.scope = domain::StoreScope::Machine;
    device.subject.insert(QStringLiteral("CN"), {domain::FieldSource::ComputerName, {},
        QRegularExpression(QStringLiteral("^WIN-LAPTOP-[0-9]{3}$")), false});
    device.subject.insert(QStringLiteral("O"), {domain::FieldSource::Fixed,
        QStringLiteral("Altasci"), {}, false});
    device.subject.insert(QStringLiteral("OU"), {domain::FieldSource::Fixed,
        QStringLiteral("受管设备"), {}, false});
    device.key.provider = QStringLiteral("Microsoft Platform Crypto Provider");
    device.key.algorithm = QStringLiteral("RSA");
    device.key.bits = 2048;
    device.key.exportable = false;
    device.key.hardwareRequired = true;
    device.keyUsage = {QStringLiteral("digitalSignature")};
    device.extendedKeyUsage = {QStringLiteral("1.3.6.1.5.5.7.3.2")};
    device.friendlyName = QStringLiteral("Windows 设备 mTLS");

    domain::CertificateTemplate user;
    user.id = QStringLiteral("windows-user-client-auth");
    user.name = QStringLiteral("Windows 用户客户端认证");
    user.version = 1;
    user.scope = domain::StoreScope::User;
    user.subject.insert(QStringLiteral("CN"), {domain::FieldSource::Username, {}, {}, false});
    user.subject.insert(QStringLiteral("O"), {domain::FieldSource::Fixed,
        QStringLiteral("Altasci"), {}, false});
    user.key.provider = QStringLiteral("Microsoft Software Key Storage Provider");
    user.key.exportable = false;
    user.keyUsage = {QStringLiteral("digitalSignature")};
    user.extendedKeyUsage = {QStringLiteral("1.3.6.1.5.5.7.3.2")};
    user.friendlyName = QStringLiteral("用户客户端认证");
    return {device, user};
}

QString TemplateService::resolveField(const domain::TemplateField &field)
{
    switch (field.source) {
    case domain::FieldSource::Fixed:
    case domain::FieldSource::UserInput: return field.value;
    case domain::FieldSource::ComputerName: return QHostInfo::localHostName().toUpper();
    case domain::FieldSource::Username: return qEnvironmentVariable("USERNAME");
    case domain::FieldSource::Environment: return qEnvironmentVariable(field.value.toUtf8().constData());
    case domain::FieldSource::Generated: return QUuid::createUuid().toString(QUuid::WithoutBraces);
    case domain::FieldSource::ServerAssigned: return {};
    }
    return {};
}

tl::expected<domain::CertificateTemplate, domain::AppError>
TemplateService::resolveAndValidate(const domain::CertificateTemplate &source) const
{
    domain::CertificateTemplate resolved = source;
    for (auto it = resolved.subject.begin(); it != resolved.subject.end(); ++it) {
        it->value = resolveField(*it);
        if (it->value.isEmpty() && it->source != domain::FieldSource::ServerAssigned)
            return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
                QStringLiteral("template.required_field"), 0,
                QStringLiteral("模板无法解析主题字段 %1。").arg(it.key()), {}});
        if (it->pattern.isValid() && !it->pattern.pattern().isEmpty() &&
            !it->pattern.match(it->value).hasMatch())
            return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
                QStringLiteral("template.pattern_mismatch"), 0,
                QStringLiteral("%1 不符合组织命名策略。").arg(it->value),
                it->pattern.pattern()});
    }
    if (resolved.key.hardwareRequired &&
        resolved.key.provider.compare(QStringLiteral("Microsoft Platform Crypto Provider"),
                                      Qt::CaseInsensitive) != 0)
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("template.hardware_provider_required"), 0,
            QStringLiteral("此模板要求使用 Microsoft Platform Crypto Provider。"), {}});
    if (resolved.key.hardwareRequired && resolved.key.exportable)
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("template.tpm_exportable"), 0,
            QStringLiteral("TPM 设备密钥不得设置为可导出。"), {}});
    static const QStringList supportedProviders{
        QStringLiteral("Microsoft Software Key Storage Provider"),
        QStringLiteral("Microsoft Platform Crypto Provider")};
    if (!supportedProviders.contains(resolved.key.provider, Qt::CaseInsensitive))
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("template.unsupported_provider"), 0,
            QStringLiteral("APCM 当前只允许 Microsoft Software KSP 或 Microsoft Platform Crypto Provider。"),
            resolved.key.provider});
    if (resolved.key.algorithm.compare(QStringLiteral("RSA"), Qt::CaseInsensitive) != 0)
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("template.unsupported_algorithm"), 0,
            QStringLiteral("当前证书申请仅支持 RSA CNG 密钥。"), resolved.key.algorithm});
    if (resolved.key.bits != 2048 && resolved.key.bits != 3072 && resolved.key.bits != 4096)
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("template.weak_key"), 0,
            QStringLiteral("RSA 密钥长度只能选择 2048、3072 或 4096 位。"), {}});
    if (resolved.key.hardwareRequired && resolved.key.bits != 2048)
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("template.tpm_key_length"), 0,
            QStringLiteral("为保证 TPM 兼容性，Microsoft Platform Crypto Provider 仅允许 2048 位 RSA。"), {}});
    if (resolved.keyUsage.contains(QStringLiteral("encipherOnly")) &&
        !resolved.keyUsage.contains(QStringLiteral("keyAgreement")))
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("template.encipher_requires_agreement"), 0,
            QStringLiteral("选择“仅加密”时必须同时选择“密钥协商”。"), {}});
    if (resolved.keyUsage.contains(QStringLiteral("decipherOnly")) &&
        !resolved.keyUsage.contains(QStringLiteral("keyAgreement")))
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("template.decipher_requires_agreement"), 0,
            QStringLiteral("选择“仅解密”时必须同时选择“密钥协商”。"), {}});
    const QRegularExpression oidPattern(QStringLiteral("^[0-2](?:\\.[0-9]+)+$"));
    for (const QString &oid : resolved.extendedKeyUsage) {
        if (!oidPattern.match(oid).hasMatch())
            return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
                QStringLiteral("template.eku_invalid"), 0,
                QStringLiteral("增强型密钥用途包含无效 OID。"), oid});
    }
    return resolved;
}

} // namespace certmgr::services
