#include "IndependentSigningController.h"
#include "../domain/signing/SigningProtocol.h"
#include "../platform/windows/signing/SigningCredentialStore.h"
#include <QDateTime>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSaveFile>
#include <QScopeGuard>
#include <QUrlQuery>
#include <QTimer>
#include <QUuid>
#include <openssl/crypto.h>
#include <algorithm>
#include <filesystem>

namespace certmgr::app {
using namespace domain::signing;
using platform::windows::SigningCredentialStore;
namespace {
QString uuid() { return QUuid::createUuid().toString(QUuid::WithoutBraces); }
QString utcNow() { return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs); }
QStringList split(const QVariant &value)
{
    if (value.metaType().id() == QMetaType::QStringList) return value.toStringList();
    return value.toString().split(QRegularExpression(QStringLiteral("[,;\\s]+")), Qt::SkipEmptyParts);
}
QString stateLabel(const QString &state)
{
    static const QHash<QString, QString> labels{{QStringLiteral("PREPARED"), QStringLiteral("已保存待发送")},
        {QStringLiteral("IN_FLIGHT"), QStringLiteral("正在签发")}, {QStringLiteral("UNCERTAIN"), QStringLiteral("结果未知 · 可原样恢复")},
        {QStringLiteral("REJECTED"), QStringLiteral("请求被拒绝")}, {QStringLiteral("RATE_LIMITED"), QStringLiteral("等待限速解除")},
        {QStringLiteral("STORED"), QStringLiteral("已签发并验证")}, {QStringLiteral("NEEDS_TRUST"), QStringLiteral("已签发 · 待确认业务信任根")},
        {QStringLiteral("HISTORICAL"), QStringLiteral("历史或不可用证书 · 不可安装")}, {QStringLiteral("DEPLOYED"), QStringLiteral("已安装")},
        {QStringLiteral("REVOKE_PENDING"), QStringLiteral("吊销结果待确认 · 保留原原因")}, {QStringLiteral("TRACKED"), QStringLiteral("手动跟踪 · 未关联私钥")}};
    return labels.value(state, state);
}
QVariantMap cleanSettings(const QVariantMap &source)
{
    QVariantMap settings;
    const QStringList keys{QStringLiteral("id"), QStringLiteral("name"), QStringLiteral("endpoint"), QStringLiteral("tokenExpiresAt"),
        QStringLiteral("scopes"), QStringLiteral("timeoutSeconds"), QStringLiteral("proxyType"), QStringLiteral("proxyHost"),
        QStringLiteral("proxyPort"), QStringLiteral("mtlsRequired"), QStringLiteral("clientCertificateFile"),
        QStringLiteral("clientKeyFile"), QStringLiteral("serverCaFile"), QStringLiteral("businessRootsFile")};
    for (const auto &key : keys) if (source.contains(key)) settings.insert(key, source.value(key));
    settings[QStringLiteral("timeoutSeconds")] = qBound(5, settings.value(QStringLiteral("timeoutSeconds"), 30).toInt(), 120);
    return settings;
}
QJsonObject certificateFields(const QJsonObject &source)
{
    QJsonObject result;
    const QStringList fields{QStringLiteral("id"), QStringLiteral("instance_id"), QStringLiteral("credential_id"),
        QStringLiteral("serial"), QStringLiteral("certificate_pem"), QStringLiteral("chain_pem"), QStringLiteral("fingerprint_sha256"),
        QStringLiteral("not_before"), QStringLiteral("not_after"), QStringLiteral("revoked_at"), QStringLiteral("revocation_reason"),
        QStringLiteral("created_at"), QStringLiteral("status")};
    for (const auto &field : fields) if (source.contains(field)) result.insert(field, source.value(field));
    return result;
}
QJsonObject objectResponse(const services::SigningHttpResult &result)
{
    if (!result.contentType.toLower().contains("application/json")) return {};
    const auto document = QJsonDocument::fromJson(result.body);
    return document.isObject() ? document.object() : QJsonObject{};
}
}
IndependentSigningController::IndependentSigningController(persistence::SqlCipherVault &vault, Installer installer, QObject *parent)
    : QObject(parent), vault_(vault), installer_(std::move(installer)), holderHttp_(false, this), ownerHttp_(true, this)
{
    auto *reminders = new QTimer(this);
    reminders->setInterval(60000);
    connect(reminders, &QTimer::timeout, this, [this] { if (vault_.isUnlocked()) emit changed(); });
    reminders->start();
}
void IndependentSigningController::fail(const QString &message) { error_ = message; emit changed(); }
void IndependentSigningController::notice(const QString &message) { error_.clear(); status_ = message; emit changed(); }
void IndependentSigningController::clearMessage() { error_.clear(); status_.clear(); emit changed(); }
bool IndependentSigningController::ready()
{
    if (!vault_.isUnlocked()) { fail(QStringLiteral("请先解锁本地保险库。")); return false; }
    if (busy_) { fail(QStringLiteral("请等待当前请求结束。")); return false; }
    return true;
}
bool IndependentSigningController::networkReady()
{
    if (!ready()) return false;
    if (retryAt_.isValid() && retryAt_ > QDateTime::currentDateTimeUtc()) {
        fail(QStringLiteral("服务要求等待至 %1 后再请求。").arg(retryAt_.toLocalTime().toString(QStringLiteral("HH:mm:ss")))); return false;
    }
    return true;
}
void IndependentSigningController::rememberBackoff(const QDateTime &retryAt)
{
    if (!retryAt.isValid()) return;
    retryAt_ = retryAt;
    if (auto saved = vault_.saveSigningRecord(QStringLiteral("backoff"), QStringLiteral("shared"),
        {{QStringLiteral("id"), QStringLiteral("shared")}, {QStringLiteral("retryAt"), retryAt.toString(Qt::ISODateWithMs)}}); !saved) fail(saved.error().message);
}
void IndependentSigningController::resetOwnerSession()
{
    if (!csrf_.isEmpty()) OPENSSL_cleanse(csrf_.data(), static_cast<size_t>(csrf_.size()));
    csrf_.clear(); ownerUser_.clear(); ownerSessionExpiry_.clear(); ownerInstanceId_.clear(); ownerNextCursor_.clear();
    ownerInstances_.clear(); ownerCredentials_.clear(); ownerCertificates_.clear();
}
void IndependentSigningController::clear()
{
    holderHttp_.clear(); ownerHttp_.clear(); resetOwnerSession();
    profiles_.clear(); operations_.clear(); selectedProfileId_.clear(); ownerSettings_.clear();
    issuerDer_.clear(); crlDer_.clear(); issuerInfo_.clear(); crlInfo_.clear(); retryAt_ = {};
    busy_ = false; error_.clear(); status_.clear(); emit changed();
}
void IndependentSigningController::load()
{
    clear();
    for (const auto &kind : {QStringLiteral("profile"), QStringLiteral("operation"), QStringLiteral("owner"), QStringLiteral("backoff")}) {
        auto records = vault_.signingRecords(kind);
        if (!records) { fail(records.error().message); return; }
        for (const auto &record : *records) {
            const auto map = record.toMap(); const QString id = map.value(QStringLiteral("id")).toString();
            if (kind == QStringLiteral("profile")) profiles_.insert(id, map);
            else if (kind == QStringLiteral("owner")) ownerSettings_ = map;
            else if (kind == QStringLiteral("backoff")) retryAt_ = QDateTime::fromString(map.value(QStringLiteral("retryAt")).toString(), Qt::ISODateWithMs);
            else {
                auto operation = QJsonObject::fromVariantMap(map);
                if (operation.value(QStringLiteral("state")).toString() == QStringLiteral("IN_FLIGHT")) {
                    operation[QStringLiteral("state")] = QStringLiteral("UNCERTAIN");
                    if (!vault_.saveSigningRecord(QStringLiteral("operation"), id, operation)) {
                        fail(QStringLiteral("无法恢复签发任务状态；未发送任何请求。")); return;
                    }
                }
                operations_.insert(id, operation);
            }
        }
    }
    if (!profiles_.isEmpty()) selectProfile(profiles().front().toMap().value(QStringLiteral("id")).toString());
    if (!ownerSettings_.isEmpty()) {
        auto endpoint = consoleEndpoint(ownerSettings_.value(QStringLiteral("endpoint")).toString());
        auto tls = transportConfiguration(ownerSettings_, {}, false);
        if (endpoint && tls) static_cast<void>(ownerHttp_.configure(*endpoint, ownerSettings_, *tls));
    }
    emit changed();
}
QVariantList IndependentSigningController::profiles() const
{
    QVariantList result;
    for (const auto &profile : profiles_) result.append(profile);
    std::sort(result.begin(), result.end(), [](const QVariant &a, const QVariant &b) { return a.toMap().value(QStringLiteral("name")).toString() < b.toMap().value(QStringLiteral("name")).toString(); });
    return result;
}
QVariantMap IndependentSigningController::currentProfile() const { return profiles_.value(selectedProfileId_); }
QVariantList IndependentSigningController::operations() const
{
    QVariantList result;
    for (const auto &operation : operations_) {
        auto map = operation.toVariantMap();
        map[QStringLiteral("stateLabel")] = stateLabel(operation.value(QStringLiteral("state")).toString());
        const auto info = map.value(QStringLiteral("validation")).toMap();
        const auto expires = info.value(QStringLiteral("notAfter")).toDateTime();
        if (expires.isValid()) {
            const auto now = QDateTime::currentDateTimeUtc();
            map[QStringLiteral("expiresInDays")] = now.daysTo(expires);
            if (expires <= now) {
                auto expiredInfo = info; expiredInfo[QStringLiteral("current")] = false; expiredInfo[QStringLiteral("installable")] = false;
                map[QStringLiteral("validation")] = expiredInfo;
                if (!map.contains(QStringLiteral("pendingRevokeReason")) && info.value(QStringLiteral("status")).toString() != QStringLiteral("revoked"))
                    map[QStringLiteral("stateLabel")] = QStringLiteral("已过期 · 请创建新签发任务续期");
            }
        }
        result.append(map);
    }
    std::sort(result.begin(), result.end(), [](const QVariant &a, const QVariant &b) { return a.toMap().value(QStringLiteral("createdAt")).toString() > b.toMap().value(QStringLiteral("createdAt")).toString(); });
    return result;
}
QString IndependentSigningController::transportSummary() const { return transportIdentitySummary(holderHttp_.tls()); }
QString IndependentSigningController::ownerTransportSummary() const { return transportIdentitySummary(ownerHttp_.tls()); }
QString IndependentSigningController::secretTarget(const QString &id) const
{
    return QStringLiteral("APCM/IndependentSigning/%1/%2").arg(fingerprint(vault_.databasePath().toUtf8()).left(24), id);
}
Result<QByteArray> IndependentSigningController::businessRoots(const QVariantMap &profile) const
{
    const QUrl file(profile.value(QStringLiteral("businessRootsFile")).toString());
    if (file.isEmpty()) return QByteArray{};
    return readFile(file, 1024 * 1024);
}
bool IndependentSigningController::saveProfile(const QVariantMap &input, const QString &tokenText, const QString &transportPassword)
{
    if (!ready()) return false;
    auto settings = cleanSettings(input);
    auto endpoint = issueEndpoint(settings.value(QStringLiteral("endpoint")).toString());
    const QString name = settings.value(QStringLiteral("name")).toString().trimmed();
    if (!endpoint || name.isEmpty() || name.toUtf8().size() > 128) { fail(endpoint ? QStringLiteral("请输入 1～128 字节的连接名称。") : endpoint.error().message); return false; }
    QString id = settings.value(QStringLiteral("id")).toString();
    if (id.isEmpty()) id = uuid();
    if (!isUuid(id)) { fail(QStringLiteral("配置 ID 无效。")); return false; }
    const auto previous = profiles_.value(id);
    if (!previous.isEmpty() && previous.value(QStringLiteral("endpoint")).toString() != endpoint->toString()) {
        for (const auto &op : operations_) if (op.value(QStringLiteral("profileId")).toString() == id) {
            fail(QStringLiteral("此连接已有任务，不能更换签发端点；请新建连接以保留原任务恢复路径。")); return false;
        }
    }
    auto tls = transportConfiguration(settings, transportPassword.toUtf8(), true);
    if (!tls) { fail(tls.error().message); return false; }
    auto roots = businessRoots(settings);
    if (!roots) { fail(roots.error().message); return false; }
    if (!roots->isEmpty() && QSslCertificate::fromData(*roots, QSsl::Pem).isEmpty()) { fail(QStringLiteral("业务信任根必须是来自可信渠道的 PEM CA 文件。")); return false; }
    QByteArray token = tokenText.trimmed().toLatin1();
    const auto wipe = qScopeGuard([&] { if (!token.isEmpty()) OPENSSL_cleanse(token.data(), static_cast<size_t>(token.size())); });
    if (!token.isEmpty() && !validToken(token)) { fail(QStringLiteral("Token 应为 ist_ 加 43 个 base64url 字符。")); return false; }
    const QString expiry = settings.value(QStringLiteral("tokenExpiresAt")).toString().trimmed();
    if (!expiry.isEmpty() && !QDateTime::fromString(expiry, Qt::ISODate).isValid()) { fail(QStringLiteral("Token 到期时间请填写带时区的 ISO 8601 时间，例如 2026-12-17T12:00:00+08:00。")); return false; }
    if (auto configured = holderHttp_.configure(*endpoint, settings, *tls); !configured) { fail(configured.error().message); return false; }
    settings[QStringLiteral("id")] = id; settings[QStringLiteral("name")] = name;
    settings[QStringLiteral("endpoint")] = endpoint->toString();
    if (!token.isEmpty()) {
        if (auto saved = SigningCredentialStore::write(secretTarget(id), token); !saved) { fail(saved.error().message); return false; }
        settings[QStringLiteral("credentialDigest")] = fingerprint(token);
        settings[QStringLiteral("hasToken")] = true;
    } else {
        settings[QStringLiteral("credentialDigest")] = previous.value(QStringLiteral("credentialDigest"));
        settings[QStringLiteral("hasToken")] = previous.value(QStringLiteral("hasToken"), false);
    }
    if (auto saved = vault_.saveSigningRecord(QStringLiteral("profile"), id, QJsonObject::fromVariantMap(settings)); !saved) { fail(saved.error().message); return false; }
    profiles_.insert(id, settings); selectedProfileId_ = id;
    issuerDer_.clear(); crlDer_.clear(); issuerInfo_.clear(); crlInfo_.clear();
    audit(QStringLiteral("SIGNING_PROFILE_SAVE"), id, QStringLiteral("SUCCESS"));
    notice(QStringLiteral("连接已保存。Token 存在 Windows 凭据管理器；通信证书仅保留在本次解锁会话。")); return true;
}
bool IndependentSigningController::selectProfile(const QString &id)
{
    if (!ready() || !profiles_.contains(id)) return false;
    if (selectedProfileId_ == id) return true;
    const auto profile = profiles_.value(id);
    auto endpoint = issueEndpoint(profile.value(QStringLiteral("endpoint")).toString());
    auto tls = transportConfiguration(profile, {}, false);
    if (!endpoint || !tls) { fail(endpoint ? tls.error().message : endpoint.error().message); return false; }
    if (auto configured = holderHttp_.configure(*endpoint, profile, *tls); !configured) { fail(configured.error().message); return false; }
    selectedProfileId_ = id; issuerDer_.clear(); crlDer_.clear(); issuerInfo_.clear(); crlInfo_.clear();
    notice(QStringLiteral("已切换连接；如需通信 mTLS，请在连接设置中重新加载通信身份。")); return true;
}
bool IndependentSigningController::deleteProfile(const QString &id, const bool confirmed)
{
    if (!ready() || !confirmed) return false;
    for (const auto &op : operations_) if (op.value(QStringLiteral("profileId")).toString() == id) {
        fail(QStringLiteral("此连接仍关联签发历史或恢复任务，请保留连接；可单独删除其 Token。")); return false;
    }
    if (auto result = SigningCredentialStore::remove(secretTarget(id)); !result) { fail(result.error().message); return false; }
    if (auto result = vault_.removeSigningRecord(QStringLiteral("profile"), id); !result) { fail(result.error().message); return false; }
    profiles_.remove(id);
    if (selectedProfileId_ == id) { selectedProfileId_.clear(); holderHttp_.clear(); }
    notice(QStringLiteral("连接与本地 Token 已删除。")); return true;
}
bool IndependentSigningController::forgetToken(const QString &id, const bool confirmed)
{
    if (!ready() || !confirmed || !profiles_.contains(id)) return false;
    if (auto result = SigningCredentialStore::remove(secretTarget(id)); !result) { fail(result.error().message); return false; }
    auto profile = profiles_.value(id); profile[QStringLiteral("hasToken")] = false;
    if (auto result = vault_.saveSigningRecord(QStringLiteral("profile"), id, QJsonObject::fromVariantMap(profile)); !result) { fail(result.error().message); return false; }
    profiles_[id] = profile;
    notice(QStringLiteral("本地 Token 已删除；服务端凭据和已签发证书的状态没有改变。原任务恢复仍需要原 Token。")); return true;
}
Result<QByteArray> IndependentSigningController::tokenFor(const QJsonObject &operation) const
{
    auto token = SigningCredentialStore::read(secretTarget(selectedProfileId_));
    if (!token) return token;
    if (!validToken(*token) || fingerprint(*token) != operation.value(QStringLiteral("credentialDigest")).toString()) {
        if (!token->isEmpty()) OPENSSL_cleanse(token->data(), static_cast<size_t>(token->size()));
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Permission, QStringLiteral("signing.original_token_required"), 0,
            QStringLiteral("此操作必须使用原签发 Token。切换或轮换 Token 不会接管旧证书的查询、吊销及幂等恢复权限。"), {}});
    }
    return token;
}
bool IndependentSigningController::persist(QJsonObject operation)
{
    operation[QStringLiteral("updatedAt")] = utcNow();
    const QString id = operation.value(QStringLiteral("id")).toString();
    if (auto saved = vault_.saveSigningRecord(QStringLiteral("operation"), id, operation); !saved) { fail(saved.error().message); return false; }
    operations_.insert(id, operation); emit changed(); return true;
}
void IndependentSigningController::audit(const QString &action, const QString &id, const QString &result)
{
    static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(), action, id, QStringLiteral("AltasCI 独立签发"), result, {}}));
}
QUrl IndependentSigningController::holderUrl(const QString &suffix) const
{
    QUrl result(currentProfile().value(QStringLiteral("endpoint")).toString());
    result.setPath(result.path().chopped(5) + suffix); return result;
}
QUrl IndependentSigningController::ownerUrl(const QString &suffix) const
{
    QUrl result(ownerSettings_.value(QStringLiteral("endpoint")).toString());
    const int queryStart = suffix.indexOf('?');
    result.setPath(result.path() + (queryStart >= 0 ? suffix.left(queryStart) : suffix));
    if (queryStart >= 0) result.setQuery(suffix.mid(queryStart + 1));
    return result;
}

QString IndependentSigningController::prepareIssue(const QVariantMap &options)
{
    if (!ready() || selectedProfileId_.isEmpty()) { if (selectedProfileId_.isEmpty()) fail(QStringLiteral("请先创建并选择签发连接。")); return {}; }
    const QString renewal = options.value(QStringLiteral("renewFrom")).toString();
    if (!renewal.isEmpty() && operations_.contains(renewal)) {
        const auto source = operations_.value(renewal);
        const QString state = source.value(QStringLiteral("state")).toString();
        if (state == QStringLiteral("UNCERTAIN") || state == QStringLiteral("IN_FLIGHT") || state == QStringLiteral("PREPARED") || state == QStringLiteral("RATE_LIMITED") || source.contains(QStringLiteral("pendingRevokeReason"))) {
            fail(QStringLiteral("原任务结果尚未确认，请先恢复原请求或确认吊销结果，再创建续期任务。")); return {};
        }
    }
    const auto profile = currentProfile();
    QJsonObject operation{{QStringLiteral("credentialDigest"), profile.value(QStringLiteral("credentialDigest")).toString()}};
    auto token = tokenFor(operation);
    if (!token) { fail(token.error().message); return {}; }
    OPENSSL_cleanse(token->data(), static_cast<size_t>(token->size()));
    const int validity = options.value(QStringLiteral("validitySeconds"), 0).toInt();
    if (validity != 0 && (validity < 60 || validity > 34300800)) { fail(QStringLiteral("有效期为 0（服务器默认）或 60～34300800 秒。")); return {}; }
    QStringList expected = options.value(QStringLiteral("expectedEkus")).toStringList();
    if (expected.isEmpty()) { fail(QStringLiteral("请勾选预期的证书用途；此项用于返回结果校验，不改变服务端签发策略。")); return {}; }
    expected.removeDuplicates();
    for (const auto &usage : expected) if (usage != QStringLiteral("server_auth") && usage != QStringLiteral("client_auth")) { fail(QStringLiteral("预期 EKU 无效。")); return {}; }
    QByteArray csr = options.value(QStringLiteral("csr")).toString().toUtf8();
    const QString csrFile = options.value(QStringLiteral("csrFile")).toString();
    if (!csrFile.isEmpty()) {
        auto contents = readFile(QUrl(csrFile), 65536);
        if (!contents) { fail(contents.error().message); return {}; }
        csr = *contents;
    }
    QString localRequestId = options.value(QStringLiteral("localRequestId")).toString();
    domain::EnrollmentRequest enrollmentRecord;
    if (!localRequestId.isEmpty()) {
        auto records = vault_.enrollmentRequests();
        if (!records) { fail(records.error().message); return {}; }
        const auto record = std::find_if(records->begin(), records->end(), [&](const auto &entry) { return entry.id == localRequestId; });
        if (record == records->end()) { fail(QStringLiteral("本地申请不存在。")); return {}; }
        enrollmentRecord = *record; csr = record->csrText.toUtf8();
    }
    const QString name = options.value(QStringLiteral("name"), QStringLiteral("AltasCI 业务证书")).toString().trimmed();
    if (name.isEmpty() || name.toUtf8().size() > 128) { fail(QStringLiteral("证书名称应为 1～128 字节。")); return {}; }
    if (csr.isEmpty()) {
        domain::CertificateTemplate request;
        request.id = QStringLiteral("altasci-independent-san-only");
        request.csrProfile = domain::CsrProfile::IndependentSigning;
        request.name = name; request.friendlyName = name; request.scope = domain::StoreScope::User;
        request.key.provider = QStringLiteral("Microsoft Software Key Storage Provider");
        const QString algorithm = options.value(QStringLiteral("algorithm"), QStringLiteral("ECDSA_P256")).toString();
        if (algorithm == QStringLiteral("ECDSA_P256") || algorithm == QStringLiteral("ECDSA_P384")) {
            request.key.algorithm = algorithm; request.key.bits = algorithm.endsWith(QStringLiteral("256")) ? 256 : 384;
        } else if (algorithm == QStringLiteral("RSA2048") || algorithm == QStringLiteral("RSA3072") || algorithm == QStringLiteral("RSA4096")) {
            request.key.algorithm = QStringLiteral("RSA"); request.key.bits = algorithm.mid(3).toInt();
        } else { fail(QStringLiteral("请选择受支持的 RSA/ECDSA 算法。")); return {}; }
        request.key.exportable = false;
        request.dnsSans = split(options.value(QStringLiteral("dnsSans")));
        request.ipSans = split(options.value(QStringLiteral("ipSans")));
        request.emailSans = split(options.value(QStringLiteral("emailSans")));
        request.uriSans = split(options.value(QStringLiteral("uriSans")));
        if (request.dnsSans.size() + request.ipSans.size() + request.emailSans.size() + request.uriSans.size() < 1) { fail(QStringLiteral("至少填写一个 SAN 身份。")); return {}; }
        for (const auto &field : {QStringLiteral("CN"), QStringLiteral("C"), QStringLiteral("ST"), QStringLiteral("L"), QStringLiteral("O"), QStringLiteral("OU")}) {
            const QString value = options.value(field).toString().trimmed();
            if (!value.isEmpty()) request.subject.insert(field, {domain::FieldSource::Fixed, value, {}, false});
        }
        auto generated = enrollment_.createPkcs10(request);
        if (!generated) { fail(generated.error().message); return {}; }
        csr = generated->csrBase64.toUtf8();
        enrollmentRecord.id = uuid(); enrollmentRecord.templateId = request.id;
        enrollmentRecord.createdAt = QDateTime::currentDateTimeUtc(); enrollmentRecord.updatedAt = enrollmentRecord.createdAt;
        enrollmentRecord.providerName = generated->providerName; enrollmentRecord.keyContainerName = generated->keyContainerName;
        enrollmentRecord.publicKeySha256 = generated->publicKeySha256; enrollmentRecord.csrSha256 = generated->csrSha256;
        enrollmentRecord.csrText = QString::fromUtf8(csr); enrollmentRecord.friendlyName = name;
        enrollmentRecord.subject = options.value(QStringLiteral("CN")).toString();
        enrollmentRecord.state = domain::EnrollmentState::CsrCreated;
        localRequestId = enrollmentRecord.id;
        if (auto saved = vault_.saveEnrollmentRequest(enrollmentRecord); !saved) { fail(saved.error().message); return {}; }
        emit enrollmentChanged();
    }
    auto canonical = canonicalCsrPem(csr);
    if (!canonical) { fail(canonical.error().message); return {}; }
    csr = *canonical;
    auto csrInfo = inspectCsr(csr);
    if (!csrInfo) { fail(csrInfo.error().message); return {}; }
    // A CSR imported from outside the app may optionally be paired with an existing CNG key.
    const QString provider = options.value(QStringLiteral("provider")).toString();
    const QString container = options.value(QStringLiteral("keyContainer")).toString();
    if (localRequestId.isEmpty() && !provider.isEmpty() && !container.isEmpty()) {
        enrollmentRecord.id = uuid(); enrollmentRecord.templateId = QStringLiteral("altasci-imported-csr");
        enrollmentRecord.createdAt = QDateTime::currentDateTimeUtc(); enrollmentRecord.updatedAt = enrollmentRecord.createdAt;
        enrollmentRecord.providerName = provider; enrollmentRecord.keyContainerName = container;
        enrollmentRecord.csrText = QString::fromUtf8(csr); enrollmentRecord.friendlyName = name;
        enrollmentRecord.subject = csrInfo->value(QStringLiteral("subject")).toString();
        enrollmentRecord.state = domain::EnrollmentState::CsrCreated;
        localRequestId = enrollmentRecord.id;
        if (auto saved = vault_.saveEnrollmentRequest(enrollmentRecord); !saved) { fail(saved.error().message); return {}; }
        emit enrollmentChanged();
    }
    auto preparedBody = issueRequestBody(csr, validity);
    if (!preparedBody) { fail(preparedBody.error().message); return {}; }
    const QByteArray body = *preparedBody;
    const QString id = uuid();
    operation[QStringLiteral("id")] = id;
    operation[QStringLiteral("profileId")] = selectedProfileId_;
    operation[QStringLiteral("profileName")] = profile.value(QStringLiteral("name")).toString();
    operation[QStringLiteral("endpoint")] = profile.value(QStringLiteral("endpoint")).toString();
    operation[QStringLiteral("name")] = name;
    operation[QStringLiteral("createdAt")] = utcNow();
    operation[QStringLiteral("state")] = QStringLiteral("PREPARED");
    operation[QStringLiteral("idempotencyKey")] = uuid();
    operation[QStringLiteral("requestBodyBase64")] = QString::fromLatin1(body.toBase64());
    operation[QStringLiteral("requestDigest")] = fingerprint(body);
    operation[QStringLiteral("csr")] = QString::fromUtf8(csr);
    operation[QStringLiteral("csrFile")] = csrFile;
    operation[QStringLiteral("csrInfo")] = QJsonObject::fromVariantMap(*csrInfo);
    operation[QStringLiteral("localRequestId")] = localRequestId;
    operation[QStringLiteral("validitySeconds")] = validity;
    operation[QStringLiteral("expectedEkus")] = QJsonArray::fromStringList(expected);
    if (!persist(operation)) return {};
    audit(QStringLiteral("SIGNING_PREPARE"), id, QStringLiteral("SUCCESS"));
    notice(QStringLiteral("签发任务已持久化。发送和恢复都会使用相同端点、原 Token、原始 JSON 字节及幂等键。"));
    return id;
}
void IndependentSigningController::retryOperation(const QString &id) { holderRequest(id, QStringLiteral("issue")); }
void IndependentSigningController::refreshCertificate(const QString &id) { holderRequest(id, QStringLiteral("query")); }
void IndependentSigningController::holderRequest(const QString &id, const QString &action)
{
    if (!networkReady() || !operations_.contains(id)) return;
    auto op = operations_.value(id);
    if (op.value(QStringLiteral("profileId")).toString() != selectedProfileId_ || op.value(QStringLiteral("endpoint")).toString() != currentProfile().value(QStringLiteral("endpoint")).toString()) {
        fail(QStringLiteral("请先选择该任务原来的签发连接。")); return;
    }
    auto token = tokenFor(op);
    if (!token) { fail(token.error().message); return; }
    const auto wipe = qScopeGuard([&] { OPENSSL_cleanse(token->data(), static_cast<size_t>(token->size())); });
    const auto retry = QDateTime::fromString(op.value(QStringLiteral("retryAt")).toString(), Qt::ISODateWithMs);
    if (retry.isValid() && retry > QDateTime::currentDateTimeUtc()) { fail(QStringLiteral("请等待该任务的 Retry-After 时间后再恢复。")); return; }
    QByteArray method = "GET", body, key;
    QUrl url;
    int expected = 200;
    if (action == QStringLiteral("issue")) {
        body = QByteArray::fromBase64(op.value(QStringLiteral("requestBodyBase64")).toString().toLatin1());
        key = op.value(QStringLiteral("idempotencyKey")).toString().toLatin1();
        if (body.isEmpty() || fingerprint(body) != op.value(QStringLiteral("requestDigest")).toString() || key.size() < 8) {
            fail(QStringLiteral("原始请求字节或幂等键缺失/损坏，不能安全恢复；请先联系实例所有者核对历史。")); return;
        }
        url = QUrl(op.value(QStringLiteral("endpoint")).toString()); method = "POST"; expected = 201;
        op[QStringLiteral("state")] = QStringLiteral("IN_FLIGHT");
    } else {
        const QString certificateId = op.value(QStringLiteral("certificateId")).toString();
        if (!isUuid(certificateId)) { fail(QStringLiteral("此任务尚无可查询的证书 UUID。")); return; }
        url = holderUrl(QStringLiteral("certificates/") + certificateId + (action == QStringLiteral("revoke") ? QStringLiteral("/revoke") : QString{}));
        if (action == QStringLiteral("revoke")) {
            method = "POST";
            body = QJsonDocument(QJsonObject{{QStringLiteral("reason"), op.value(QStringLiteral("pendingRevokeReason")).toInt()}}).toJson(QJsonDocument::Compact);
            op[QStringLiteral("state")] = QStringLiteral("REVOKE_PENDING");
        }
    }
    if (!persist(op)) return;
    busy_ = true; error_.clear(); status_ = QStringLiteral("正在请求 AltasCI…"); emit changed();
    holderHttp_.send(method, url, body, *token, {}, key, expected,
        [this, id, action](services::SigningHttpResult result) { completeOperation(id, result, action); });
}
void IndependentSigningController::completeOperation(const QString &id, const services::SigningHttpResult &result, const QString &action)
{
    busy_ = false;
    if (!vault_.isUnlocked() || !operations_.contains(id)) return;
    auto op = operations_.value(id);
    op[QStringLiteral("lastHttpStatus")] = result.status;
    op[QStringLiteral("lastRequestId")] = result.requestId;
    op[QStringLiteral("lastProblemCode")] = result.problemCode;
    op[QStringLiteral("replayed")] = result.replayed;
    op[QStringLiteral("retryAt")] = result.retryAt.toString(Qt::ISODateWithMs);
    rememberBackoff(result.retryAt);
    QString error = result.error;
    bool success = result.ok;
    if (success) {
        const auto record = certificateFields(objectResponse(result));
        auto roots = businessRoots(profiles_.value(op.value(QStringLiteral("profileId")).toString()));
        QStringList expected; for (const auto &entry : op.value(QStringLiteral("expectedEkus")).toArray()) expected.append(entry.toString());
        auto validation = roots ? inspectCertificate(record, op.value(QStringLiteral("csr")).toString().toUtf8(), expected, *roots)
                                : Result<QVariantMap>(tl::unexpected(roots.error()));
        const QString existingId = op.value(QStringLiteral("certificateId")).toString();
        const QString instanceId = QUrl(op.value(QStringLiteral("endpoint")).toString()).path().split('/').value(2);
        if (!validation || record.value(QStringLiteral("instance_id")).toString().compare(instanceId, Qt::CaseInsensitive) != 0 ||
            (!existingId.isEmpty() && record.value(QStringLiteral("id")).toString() != existingId) ||
            (action == QStringLiteral("revoke") && (record.value(QStringLiteral("status")).toString() != QStringLiteral("revoked") ||
             record.value(QStringLiteral("revocation_reason")).toInt(-1) != op.value(QStringLiteral("pendingRevokeReason")).toInt()))) {
            success = false;
            error = validation ? QStringLiteral("证书响应与目标实例、证书 UUID 或原吊销原因不一致。") : validation.error().message;
        } else {
            op[QStringLiteral("certificate")] = record;
            op[QStringLiteral("certificateId")] = record.value(QStringLiteral("id"));
            op[QStringLiteral("validation")] = QJsonObject::fromVariantMap(*validation);
            const bool historical = record.value(QStringLiteral("status")).toString() != QStringLiteral("good") || !validation->value(QStringLiteral("current")).toBool();
            op[QStringLiteral("state")] = historical ? QStringLiteral("HISTORICAL") :
                (validation->value(QStringLiteral("chainTrusted")).toBool() ? QStringLiteral("STORED") : QStringLiteral("NEEDS_TRUST"));
            if (action == QStringLiteral("revoke") || record.value(QStringLiteral("status")).toString() == QStringLiteral("revoked")) op.remove(QStringLiteral("pendingRevokeReason"));
            else if (op.contains(QStringLiteral("pendingRevokeReason"))) op[QStringLiteral("state")] = QStringLiteral("REVOKE_PENDING");
        }
    }
    if (!success) {
        if (action == QStringLiteral("issue")) {
            op[QStringLiteral("state")] = result.status == 429 ? QStringLiteral("RATE_LIMITED") :
                (result.status >= 400 && result.status < 500 && result.status != 408 ? QStringLiteral("REJECTED") : QStringLiteral("UNCERTAIN"));
        }
        op[QStringLiteral("lastError")] = error;
    } else op[QStringLiteral("lastError")] = QString{};
    if (!persist(op)) return;
    audit(QStringLiteral("SIGNING_") + action.toUpper(), id, success ? QStringLiteral("SUCCESS") : QStringLiteral("FAILED"));
    if (!success) fail(error);
    else notice(action == QStringLiteral("revoke") ? QStringLiteral("证书已不可逆吊销。可下载最新 CRL 核对。") :
        (result.replayed ? QStringLiteral("已恢复原签发结果，未创建新的签发操作。请核对当前状态和业务信任验证。") : QStringLiteral("证书记录已保存；签发、业务信任验证和安装状态分别显示。")));
}
void IndependentSigningController::trackCertificate(const QString &certificateId)
{
    if (!ready() || !isUuid(certificateId) || selectedProfileId_.isEmpty()) { fail(QStringLiteral("请先选择连接并输入合法证书 UUID。")); return; }
    const auto profile = currentProfile(); const QString id = uuid();
    QJsonObject operation{{QStringLiteral("id"), id}, {QStringLiteral("profileId"), selectedProfileId_},
        {QStringLiteral("profileName"), profile.value(QStringLiteral("name")).toString()}, {QStringLiteral("endpoint"), profile.value(QStringLiteral("endpoint")).toString()},
        {QStringLiteral("credentialDigest"), profile.value(QStringLiteral("credentialDigest")).toString()}, {QStringLiteral("certificateId"), certificateId},
        {QStringLiteral("name"), QStringLiteral("手动跟踪 ") + certificateId}, {QStringLiteral("state"), QStringLiteral("TRACKED")}, {QStringLiteral("createdAt"), utcNow()}};
    if (persist(operation)) refreshCertificate(id);
}
void IndependentSigningController::revokeCertificate(const QString &id, const int reason, const bool confirmed)
{
    if (!ready() || !confirmed || !validReason(reason) || !operations_.contains(id)) return;
    auto op = operations_.value(id);
    if (op.value(QStringLiteral("certificate")).toObject().isEmpty() || op.value(QStringLiteral("validation")).toObject().value(QStringLiteral("fingerprint")).toString().isEmpty()) {
        fail(QStringLiteral("请先查询并核对证书主体、SAN、序列号和指纹，再确认吊销。")); return;
    }
    if (op.contains(QStringLiteral("pendingRevokeReason")) && op.value(QStringLiteral("pendingRevokeReason")).toInt() != reason) {
        fail(QStringLiteral("原吊销结果尚未确认，必须保留相同原因码恢复。")); return;
    }
    op[QStringLiteral("pendingRevokeReason")] = reason;
    op[QStringLiteral("state")] = QStringLiteral("REVOKE_PENDING");
    if (persist(op)) holderRequest(id, QStringLiteral("revoke"));
}
void IndependentSigningController::revalidateOperation(const QString &id)
{
    if (!ready() || !operations_.contains(id)) return;
    auto op = operations_.value(id); auto roots = businessRoots(profiles_.value(op.value(QStringLiteral("profileId")).toString()));
    if (!roots) { fail(roots.error().message); return; }
    QStringList expected; for (const auto &entry : op.value(QStringLiteral("expectedEkus")).toArray()) expected.append(entry.toString());
    auto validation = inspectCertificate(op.value(QStringLiteral("certificate")).toObject(), op.value(QStringLiteral("csr")).toString().toUtf8(), expected, *roots);
    if (!validation) { fail(validation.error().message); return; }
    op[QStringLiteral("validation")] = QJsonObject::fromVariantMap(*validation);
    const QString state = !validation->value(QStringLiteral("current")).toBool() || validation->value(QStringLiteral("status")).toString() != QStringLiteral("good")
        ? QStringLiteral("HISTORICAL") : (validation->value(QStringLiteral("chainTrusted")).toBool() ? QStringLiteral("STORED") : QStringLiteral("NEEDS_TRUST"));
    // Revalidation must not erase an unresolved revocation intent.
    if (!op.contains(QStringLiteral("pendingRevokeReason"))) op[QStringLiteral("state")] = state;
    if (persist(op)) notice(validation->value(QStringLiteral("chainTrusted")).toBool() ? QStringLiteral("业务证书链已通过可信根验证。") : QStringLiteral("尚未通过业务信任验证：") + validation->value(QStringLiteral("trustError")).toString());
}
void IndependentSigningController::installOperation(const QString &id)
{
    revalidateOperation(id);
    if (!error_.isEmpty() || !operations_.contains(id)) return;
    auto op = operations_.value(id);
    if (!op.value(QStringLiteral("validation")).toObject().value(QStringLiteral("installable")).toBool() ||
        op.value(QStringLiteral("localRequestId")).toString().isEmpty() || op.contains(QStringLiteral("pendingRevokeReason"))) {
        fail(QStringLiteral("只能安装当前有效、未吊销、业务链可信且已关联本地 CNG 私钥的证书。外部 CSR 可导出后交给其私钥持有者安装。")); return;
    }
    if (installer_(op.value(QStringLiteral("localRequestId")).toString(), op.value(QStringLiteral("certificate")).toObject().value(QStringLiteral("certificate_pem")).toString().toUtf8())) {
        op[QStringLiteral("state")] = QStringLiteral("DEPLOYED");
        if (persist(op)) notice(QStringLiteral("业务叶证书已安装到 Windows 个人存储并通过 CNG 公钥匹配；未安装或信任下载的 CA。"));
        emit enrollmentChanged();
    } else fail(QStringLiteral("安装未完成，请查看应用的证书安装错误。"));
}
bool IndependentSigningController::saveFile(const QUrl &url, const QByteArray &data)
{
    if (!vault_.isUnlocked() || !url.isLocalFile() || data.isEmpty()) { fail(QStringLiteral("请选择本地导出路径。")); return false; }
    QStringList protectedPaths{vault_.databasePath(), vault_.metadataPath()};
    for (const auto &profile : profiles_) for (const auto &field : {QStringLiteral("clientCertificateFile"), QStringLiteral("clientKeyFile"), QStringLiteral("serverCaFile"), QStringLiteral("businessRootsFile")}) {
        const QString path = QUrl(profile.value(field).toString()).toLocalFile(); if (!path.isEmpty()) protectedPaths.append(path);
    }
    for (const auto &field : {QStringLiteral("clientCertificateFile"), QStringLiteral("clientKeyFile"), QStringLiteral("serverCaFile")}) {
        const QString path = QUrl(ownerSettings_.value(field).toString()).toLocalFile(); if (!path.isEmpty()) protectedPaths.append(path);
    }
    for (const auto &op : operations_) {
        const QString path = QUrl(op.value(QStringLiteral("csrFile")).toString()).toLocalFile(); if (!path.isEmpty()) protectedPaths.append(path);
    }
    const auto nativePath = [](const QString &path) {
#ifdef Q_OS_WIN
        return std::filesystem::path(path.toStdWString());
#else
        return std::filesystem::path(path.toStdString());
#endif
    };
    const QFileInfo destination(url.toLocalFile());
    for (const auto &path : protectedPaths) {
        std::error_code error;
        if (destination.absoluteFilePath() == QFileInfo(path).absoluteFilePath() ||
            (destination.exists() && std::filesystem::equivalent(nativePath(destination.absoluteFilePath()), nativePath(path), error))) {
            fail(QStringLiteral("导出目标与保险库、通信密钥、信任根或 CSR 文件相同/互为链接，已阻止覆盖。")); return false;
        }
    }
    QSaveFile file(url.toLocalFile());
    if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size() || !file.commit()) { fail(QStringLiteral("导出失败，原文件保持完整。")); return false; }
    notice(QStringLiteral("已原子保存证书文件。完整链包含叶证书及上级 CA；导出不代表安装或信任。")); return true;
}
bool IndependentSigningController::exportOperation(const QString &id, const QString &part, const QUrl &destination)
{
    if (!ready() || !operations_.contains(id)) return false;
    const auto op = operations_.value(id);
    const QString field = part == QStringLiteral("leaf") ? QStringLiteral("certificate_pem") : part == QStringLiteral("chain") ? QStringLiteral("chain_pem") : QString{};
    if (field.isEmpty()) return false;
    return saveFile(destination, op.value(QStringLiteral("certificate")).toObject().value(field).toString().toUtf8());
}
void IndependentSigningController::fetchArtifact(const QString &kind)
{
    if (!networkReady() || selectedProfileId_.isEmpty() || (kind != QStringLiteral("issuer") && kind != QStringLiteral("crl"))) return;
    if (kind == QStringLiteral("crl") && issuerDer_.isEmpty()) { fail(QStringLiteral("请先下载当前实例的签发者证书，再校验 CRL。")); return; }
    busy_ = true; error_.clear(); emit changed();
    holderHttp_.send("GET", holderUrl(kind == QStringLiteral("issuer") ? QStringLiteral("issuer.cer") : QStringLiteral("crl")), {}, {}, {}, {}, 200,
        [this, kind](services::SigningHttpResult result) {
        busy_ = false;
        rememberBackoff(result.retryAt);
        if (!result.ok) { fail(result.error); return; }
        const QByteArray type = result.contentType.split(';').value(0).trimmed().toLower();
        if (type != (kind == QStringLiteral("issuer") ? QByteArray("application/pkix-cert") : QByteArray("application/pkix-crl"))) { fail(QStringLiteral("公开下载的 Content-Type 与 DER 文件类型不符。")); return; }
        auto info = kind == QStringLiteral("issuer") ? inspectIssuer(result.body) : inspectCrl(result.body, issuerDer_, QUrl(currentProfile().value(QStringLiteral("endpoint")).toString()));
        if (!info) { fail(info.error().message); return; }
        if (kind == QStringLiteral("issuer")) { issuerDer_ = result.body; issuerInfo_ = *info; }
        else { crlDer_ = result.body; crlInfo_ = *info; }
        notice(kind == QStringLiteral("issuer") ? QStringLiteral("服务器可达，已解析签发者 CA；Token 尚未经过此操作验证。") : QStringLiteral("CRL 已核对签名、时间及本实例的 critical IDP 作用域。"));
    });
}
bool IndependentSigningController::exportArtifact(const QString &kind, const QUrl &destination)
{
    if (!ready()) return false;
    if (kind == QStringLiteral("issuer-pem")) return saveFile(destination, QSslCertificate(issuerDer_, QSsl::Der).toPem());
    return saveFile(destination, kind == QStringLiteral("issuer") ? issuerDer_ : kind == QStringLiteral("crl") ? crlDer_ : QByteArray{});
}

bool IndependentSigningController::saveOwnerSettings(const QVariantMap &input, const QString &transportPassword)
{
    if (!ready()) return false;
    auto settings = cleanSettings(input);
    auto endpoint = consoleEndpoint(settings.value(QStringLiteral("endpoint")).toString());
    if (!endpoint) { fail(endpoint.error().message); return false; }
    if (ownerSettings_.value(QStringLiteral("endpoint")).toString() == endpoint->toString()) {
        for (const auto &field : {QStringLiteral("pendingCreate"), QStringLiteral("pendingRevocations")})
            if (ownerSettings_.contains(field)) settings[field] = ownerSettings_.value(field);
    } else if (!ownerSettings_.value(QStringLiteral("pendingCreate")).toString().isEmpty() || !ownerSettings_.value(QStringLiteral("pendingRevocations")).toMap().isEmpty()) {
        fail(QStringLiteral("管理端有待核对的创建/吊销操作，请先在原管理端确认结果后再切换。")); return false;
    }
    auto tls = transportConfiguration(settings, transportPassword.toUtf8(), true);
    if (!tls) { fail(tls.error().message); return false; }
    if (auto configured = ownerHttp_.configure(*endpoint, settings, *tls); !configured) { fail(configured.error().message); return false; }
    resetOwnerSession(); settings[QStringLiteral("id")] = QStringLiteral("owner");
    if (auto saved = vault_.saveSigningRecord(QStringLiteral("owner"), QStringLiteral("owner"), QJsonObject::fromVariantMap(settings)); !saved) { fail(saved.error().message); return false; }
    ownerSettings_ = settings;
    notice(QStringLiteral("所有者管理连接已保存。其通信身份、Cookie 会话与签发 Token 完全独立；请重新登录。")); return true;
}
void IndependentSigningController::ownerRequest(const QByteArray &method, const QString &path, QByteArray body, const int expected,
                                               std::function<void(const services::SigningHttpResult &)> completed)
{
    if (!networkReady()) { if (!body.isEmpty()) OPENSSL_cleanse(body.data(), static_cast<size_t>(body.size())); return; }
    if (ownerSettings_.isEmpty() || (path != QStringLiteral("/auth/login") && !ownerAuthenticated())) {
        if (!body.isEmpty()) OPENSSL_cleanse(body.data(), static_cast<size_t>(body.size()));
        fail(QStringLiteral("请先配置管理端通信连接并登录所有者账户。")); return;
    }
    busy_ = true; error_.clear(); status_ = QStringLiteral("正在请求实例所有者管理 API…"); emit changed();
    ownerHttp_.send(method, ownerUrl(path), body, {}, csrf_, {}, expected,
        [this, completed = std::move(completed)](services::SigningHttpResult result) mutable {
            busy_ = false;
            rememberBackoff(result.retryAt);
            if (result.status == 401) resetOwnerSession();
            if (!result.ok) { fail(result.error); emit changed(); return; }
            completed(result);
            if (!result.body.isEmpty()) OPENSSL_cleanse(result.body.data(), static_cast<size_t>(result.body.size()));
            emit changed();
        });
    if (!body.isEmpty()) OPENSSL_cleanse(body.data(), static_cast<size_t>(body.size()));
}
void IndependentSigningController::ownerLogin(const QString &login, const QString &password)
{
    if (login.trimmed().isEmpty() || password.isEmpty()) { fail(QStringLiteral("请输入所有者用户名/邮箱及密码。")); return; }
    auto body = QJsonDocument(QJsonObject{{QStringLiteral("login"), login.trimmed()}, {QStringLiteral("password"), password}}).toJson(QJsonDocument::Compact);
    ownerRequest("POST", QStringLiteral("/auth/login"), body, 200, [this](const auto &result) {
        const auto object = objectResponse(result);
        const auto csrf = object.value(QStringLiteral("csrf_token")).toString().toUtf8();
        const auto user = object.value(QStringLiteral("user")).toObject();
        const auto expiry = QDateTime::fromString(object.value(QStringLiteral("expires_at")).toString(), Qt::ISODate);
        if (csrf.isEmpty() || !ownerHttp_.hasOwnerCookie() || user.value(QStringLiteral("status")).toString() != QStringLiteral("active") || !expiry.isValid() || expiry <= QDateTime::currentDateTimeUtc()) {
            resetOwnerSession(); fail(QStringLiteral("登录响应缺少有效的安全会话 Cookie、CSRF、账户或过期时间。")); return;
        }
        csrf_ = csrf; ownerUser_ = user.value(QStringLiteral("username")).toString();
        ownerSessionExpiry_ = object.value(QStringLiteral("expires_at")).toString();
        notice(QStringLiteral("已建立独立所有者会话。密码、Cookie 和 CSRF 不会持久化。"));
        ownerRefreshInstances();
    });
    OPENSSL_cleanse(body.data(), static_cast<size_t>(body.size()));
}
void IndependentSigningController::ownerLogout()
{
    if (!vault_.isUnlocked() || busy_) return;
    if (!ownerAuthenticated()) { resetOwnerSession(); emit changed(); return; }
    // Clear the local session even if remote logout fails or is rate limited.
    const auto csrf = csrf_; const auto tls = ownerHttp_.tls(); const auto settings = ownerSettings_;
    busy_ = true; emit changed();
    ownerHttp_.send("POST", ownerUrl(QStringLiteral("/auth/logout")), QByteArray("{}"), {}, csrf, {}, 204,
        [this, tls, settings](services::SigningHttpResult result) {
            busy_ = false; resetOwnerSession();
            auto endpoint = consoleEndpoint(settings.value(QStringLiteral("endpoint")).toString());
            if (endpoint) static_cast<void>(ownerHttp_.configure(*endpoint, settings, tls));
            notice(result.ok ? QStringLiteral("所有者会话已退出。") : QStringLiteral("本机会话已清除；服务器退出未确认，会话将按服务器有效期失效。"));
        });
}
void IndependentSigningController::ownerCheckSession()
{
    ownerRequest("GET", QStringLiteral("/auth/session"), {}, 200, [this](const auto &result) {
        const auto object = objectResponse(result);
        if (object.value(QStringLiteral("user")).toObject().value(QStringLiteral("status")).toString() != QStringLiteral("active")) { resetOwnerSession(); fail(QStringLiteral("所有者会话或账户不可用。")); return; }
        notice(QStringLiteral("所有者会话当前有效。"));
    });
}
void IndependentSigningController::ownerAcknowledgePending(const bool confirmed)
{
    if (!ready() || !confirmed) return;
    ownerSettings_.remove(QStringLiteral("pendingCreate"));
    if (auto saved = vault_.saveSigningRecord(QStringLiteral("owner"), QStringLiteral("owner"), QJsonObject::fromVariantMap(ownerSettings_)); !saved) { fail(saved.error().message); return; }
    notice(QStringLiteral("已确认核对历史。无法找回明文的 Token 应先撤销，再创建新的凭据。"));
}
void IndependentSigningController::ownerRefreshInstances()
{
    ownerRequest("GET", QStringLiteral("/signing-instances"), {}, 200, [this](const auto &result) {
        const auto object = objectResponse(result);
        if (!object.value(QStringLiteral("items")).isArray()) { fail(QStringLiteral("实例列表响应格式无效。")); return; }
        ownerInstances_.clear();
        for (const auto &entry : object.value(QStringLiteral("items")).toArray()) {
            if (!entry.isObject() || !isUuid(entry.toObject().value(QStringLiteral("id")).toString())) { fail(QStringLiteral("实例列表含无效记录。")); return; }
            auto instance = entry.toObject(); instance.remove(QStringLiteral("private_key_pem"));
            ownerInstances_.append(instance.toVariantMap());
        }
        const QString previous = ownerInstanceId_;
        ownerInstanceId_.clear();
        for (const auto &entry : ownerInstances_) if (entry.toMap().value(QStringLiteral("id")).toString() == previous) ownerInstanceId_ = previous;
        if (ownerInstanceId_.isEmpty() && !ownerInstances_.isEmpty()) ownerInstanceId_ = ownerInstances_.front().toMap().value(QStringLiteral("id")).toString();
        ownerCredentials_.clear(); ownerCertificates_.clear(); ownerNextCursor_.clear();
        notice(QStringLiteral("已读取当前账户拥有的独立实例。"));
    });
}
void IndependentSigningController::ownerSelectInstance(const QString &id)
{
    if (!ready()) return;
    const auto found = std::find_if(ownerInstances_.begin(), ownerInstances_.end(), [&](const QVariant &v) { return v.toMap().value(QStringLiteral("id")).toString() == id; });
    if (found == ownerInstances_.end()) { fail(QStringLiteral("请选择当前账户可见的实例。")); return; }
    ownerInstanceId_ = id; ownerCredentials_.clear(); ownerCertificates_.clear(); ownerNextCursor_.clear(); emit changed();
    ownerRefreshInstance();
}
void IndependentSigningController::ownerRefreshInstance()
{
    if (!isUuid(ownerInstanceId_)) return;
    const QString id = ownerInstanceId_;
    ownerRequest("GET", QStringLiteral("/signing-instances/") + id, {}, 200, [this, id](const auto &result) {
        auto instance = objectResponse(result);
        if (instance.value(QStringLiteral("id")).toString() != id) { fail(QStringLiteral("实例详情响应与所选实例不一致。")); return; }
        instance.remove(QStringLiteral("private_key_pem"));
        for (auto &entry : ownerInstances_) if (entry.toMap().value(QStringLiteral("id")).toString() == id) entry = instance.toVariantMap();
        notice(QStringLiteral("已刷新所选实例的完整策略和启用状态。"));
    });
}
void IndependentSigningController::ownerSaveInstance(const QVariantMap &options, const bool uploadConfirmed)
{
    if (!networkReady() || !ownerAuthenticated()) return;
    const QString id = options.value(QStringLiteral("id")).toString();
    const QString name = options.value(QStringLiteral("name")).toString().trimmed();
    const auto policy = QJsonObject::fromVariantMap(options.value(QStringLiteral("policy")).toMap());
    if (auto valid = validatePolicy(policy); !valid) { fail(valid.error().message); return; }
    if (name.isEmpty() || name.toUtf8().size() > 128) { fail(QStringLiteral("实例名称应为 1～128 字节。")); return; }
    QJsonObject object{{QStringLiteral("name"), name}, {QStringLiteral("policy"), policy}};
    if (!id.isEmpty()) {
        if (!isUuid(id) || id != ownerInstanceId_ || !options.contains(QStringLiteral("enabled"))) { fail(QStringLiteral("实例或启用状态无效。")); return; }
        object[QStringLiteral("enabled")] = options.value(QStringLiteral("enabled")).toBool();
    } else {
        if (!uploadConfirmed) { fail(QStringLiteral("请明确确认上传 CA 私钥并由服务器保存。")); return; }
        if (!ownerSettings_.value(QStringLiteral("pendingCreate")).toString().isEmpty()) { fail(QStringLiteral("此前创建结果待确认，请先刷新实例/凭据历史并确认，避免重复导入。")); return; }
        auto cert = readFile(QUrl(options.value(QStringLiteral("certificateFile")).toString()), 65536);
        auto key = readFile(QUrl(options.value(QStringLiteral("privateKeyFile")).toString()), 32768);
        if (!cert || !key) { fail(QStringLiteral("无法读取 CA 证书或未加密私钥文件（证书 ≤64 KiB，私钥 ≤32 KiB）。")); return; }
        const auto wipe = qScopeGuard([&] { OPENSSL_cleanse(key->data(), static_cast<size_t>(key->size())); });
        QByteArray chain;
        if (!options.value(QStringLiteral("chainFile")).toString().isEmpty()) {
            auto data = readFile(QUrl(options.value(QStringLiteral("chainFile")).toString()), 256 * 1024);
            if (!data) { fail(data.error().message); return; } chain = *data;
        }
        if (auto valid = validateCaImport(*cert, *key, chain); !valid) { fail(valid.error().message); return; }
        object[QStringLiteral("certificate_pem")] = QString::fromUtf8(*cert);
        object[QStringLiteral("private_key_pem")] = QString::fromUtf8(*key);
        object[QStringLiteral("chain_pem")] = QString::fromUtf8(chain);
        ownerSettings_[QStringLiteral("pendingCreate")] = QStringLiteral("实例导入：") + name + QStringLiteral(" · ") + utcNow();
        if (auto saved = vault_.saveSigningRecord(QStringLiteral("owner"), QStringLiteral("owner"), QJsonObject::fromVariantMap(ownerSettings_)); !saved) { fail(saved.error().message); return; }
    }
    auto body = QJsonDocument(object).toJson(QJsonDocument::Compact);
    ownerRequest(id.isEmpty() ? QByteArray("POST") : QByteArray("PUT"), QStringLiteral("/signing-instances") + (id.isEmpty() ? QString{} : QStringLiteral("/") + id), body, id.isEmpty() ? 201 : 200,
        [this](const auto &result) {
            const auto instance = objectResponse(result);
            if (!isUuid(instance.value(QStringLiteral("id")).toString())) { fail(QStringLiteral("实例创建/更新响应损坏；请刷新实例列表确认结果，不要盲目重建。")); return; }
            ownerSettings_.remove(QStringLiteral("pendingCreate"));
            if (auto saved = vault_.saveSigningRecord(QStringLiteral("owner"), QStringLiteral("owner"), QJsonObject::fromVariantMap(ownerSettings_)); !saved) { fail(saved.error().message); return; }
            audit(QStringLiteral("SIGNING_OWNER_SAVE_INSTANCE"), instance.value(QStringLiteral("id")).toString(), QStringLiteral("SUCCESS"));
            ownerRefreshInstances();
        });
    OPENSSL_cleanse(body.data(), static_cast<size_t>(body.size()));
}
void IndependentSigningController::ownerRefreshCredentials()
{
    if (!isUuid(ownerInstanceId_)) { fail(QStringLiteral("请先选择独立实例。")); return; }
    ownerRequest("GET", QStringLiteral("/signing-instances/") + ownerInstanceId_ + QStringLiteral("/credentials"), {}, 200, [this](const auto &result) {
        const auto object = objectResponse(result);
        if (!object.value(QStringLiteral("items")).isArray()) { fail(QStringLiteral("凭据列表响应格式无效。")); return; }
        ownerCredentials_.clear();
        for (const auto &entry : object.value(QStringLiteral("items")).toArray()) {
            auto credential = entry.toObject(); credential.remove(QStringLiteral("token")); credential.remove(QStringLiteral("token_hash"));
            if (!isUuid(credential.value(QStringLiteral("id")).toString())) { fail(QStringLiteral("凭据列表含无效记录。")); return; }
            ownerCredentials_.append(credential.toVariantMap());
        }
        notice(QStringLiteral("已刷新凭据元数据。已有 Token 的明文无法从列表找回。"));
    });
}
void IndependentSigningController::ownerCreateCredential(const QVariantMap &options)
{
    if (!networkReady() || !isUuid(ownerInstanceId_)) return;
    if (!ownerSettings_.value(QStringLiteral("pendingCreate")).toString().isEmpty()) { fail(QStringLiteral("此前创建结果待确认，请先刷新历史；丢失明文的 Token 应撤销后重建。")); return; }
    const QString name = options.value(QStringLiteral("name")).toString().trimmed();
    auto scopes = options.value(QStringLiteral("scopes")).toStringList(); scopes.removeDuplicates();
    if (name.isEmpty() || name.toUtf8().size() > 128 || scopes.isEmpty()) { fail(QStringLiteral("请输入凭据名称并选择至少一个 scope。")); return; }
    for (const auto &scope : scopes) if (scope != QStringLiteral("issue") && scope != QStringLiteral("read") && scope != QStringLiteral("revoke")) { fail(QStringLiteral("凭据 scope 无效。")); return; }
    const int lifetime = options.value(QStringLiteral("lifetimeSeconds"), 2592000).toInt();
    const int total = options.value(QStringLiteral("maxIssuances"), 1000).toInt();
    const int rate = options.value(QStringLiteral("ratePerMinute"), 10).toInt();
    if (lifetime < 3600 || lifetime > 7776000 || total < 1 || total > 1000000 || rate < 1 || rate > 120) { fail(QStringLiteral("Token 有效期为 1 小时～90 天，签发总量为 1～1000000，每分钟为 1～120。")); return; }
    QJsonObject object{{QStringLiteral("name"), name}, {QStringLiteral("scopes"), QJsonArray::fromStringList(scopes)},
        {QStringLiteral("lifetime_seconds"), lifetime}, {QStringLiteral("max_issuances"), total}, {QStringLiteral("rate_per_minute"), rate},
        {QStringLiteral("policy"), QJsonValue::Null}};
    if (options.value(QStringLiteral("restrictPolicy")).toBool()) {
        const auto policy = QJsonObject::fromVariantMap(options.value(QStringLiteral("policy")).toMap());
        if (auto valid = validatePolicy(policy); !valid) { fail(valid.error().message); return; }
        object[QStringLiteral("policy")] = policy;
    }
    ownerSettings_[QStringLiteral("pendingCreate")] = QStringLiteral("创建签发凭据：") + name + QStringLiteral(" · ") + utcNow();
    if (auto saved = vault_.saveSigningRecord(QStringLiteral("owner"), QStringLiteral("owner"), QJsonObject::fromVariantMap(ownerSettings_)); !saved) { fail(saved.error().message); return; }
    ownerRequest("POST", QStringLiteral("/signing-instances/") + ownerInstanceId_ + QStringLiteral("/credentials"), QJsonDocument(object).toJson(QJsonDocument::Compact), 201,
        [this](const auto &result) {
            const auto created = objectResponse(result);
            QByteArray token = created.value(QStringLiteral("token")).toString().toLatin1();
            const auto wipe = qScopeGuard([&] { if (!token.isEmpty()) OPENSSL_cleanse(token.data(), static_cast<size_t>(token.size())); });
            if (!validToken(token) || !isUuid(created.value(QStringLiteral("credential")).toObject().value(QStringLiteral("id")).toString())) {
                fail(QStringLiteral("创建响应损坏；先刷新凭据列表确认，再撤销无法恢复明文的凭据。")); return;
            }
            ownerSettings_.remove(QStringLiteral("pendingCreate"));
            if (auto saved = vault_.saveSigningRecord(QStringLiteral("owner"), QStringLiteral("owner"), QJsonObject::fromVariantMap(ownerSettings_)); !saved) { fail(saved.error().message); return; }
            emit credentialCreated(QString::fromLatin1(token));
            ownerRefreshCredentials();
        });
}
void IndependentSigningController::ownerRevokeCredential(const QString &credentialId, const bool confirmed)
{
    if (!confirmed || !isUuid(credentialId) || !isUuid(ownerInstanceId_)) return;
    ownerRequest("POST", QStringLiteral("/signing-instances/") + ownerInstanceId_ + QStringLiteral("/credentials/") + credentialId + QStringLiteral("/revoke"), QByteArray("{}"), 204,
        [this, credentialId](const auto &) {
            audit(QStringLiteral("SIGNING_OWNER_REVOKE_TOKEN"), credentialId, QStringLiteral("SUCCESS"));
            ownerRefreshCredentials();
        });
}
void IndependentSigningController::ownerLoadCertificates(const bool nextPage)
{
    if (!isUuid(ownerInstanceId_)) return;
    if (nextPage && ownerNextCursor_.isEmpty()) return;
    QString path = QStringLiteral("/signing-instances/") + ownerInstanceId_ + QStringLiteral("/certificates?limit=100");
    if (nextPage) {
        if (!isUuid(ownerNextCursor_)) { fail(QStringLiteral("历史分页游标无效。")); return; }
        path += QStringLiteral("&before=") + ownerNextCursor_;
    }
    ownerRequest("GET", path, {}, 200, [this, nextPage](const auto &result) {
        const auto object = objectResponse(result);
        if (!object.value(QStringLiteral("items")).isArray()) { fail(QStringLiteral("证书历史响应格式无效。")); return; }
        QVariantList entries;
        for (const auto &entry : object.value(QStringLiteral("items")).toArray()) {
            auto record = certificateFields(entry.toObject());
            auto validation = inspectCertificate(record, {}, {}, {});
            if (!validation || record.value(QStringLiteral("instance_id")).toString() != ownerInstanceId_) { fail(validation ? QStringLiteral("历史证书不属于所选实例。") : validation.error().message); return; }
            record[QStringLiteral("details")] = QJsonObject::fromVariantMap(*validation);
            entries.append(record.toVariantMap());
        }
        const QString cursor = object.value(QStringLiteral("next_cursor")).toString();
        if (!cursor.isEmpty() && !isUuid(cursor)) { fail(QStringLiteral("证书历史分页游标无效。")); return; }
        if (!nextPage) ownerCertificates_.clear();
        ownerCertificates_.append(entries); ownerNextCursor_ = cursor;
        notice(QStringLiteral("已读取当前所有者实例的证书历史；此列表不代表已关联本地私钥或已安装。"));
    });
}
void IndependentSigningController::ownerRevokeCertificate(const QString &certificateId, const int reason, const bool confirmed)
{
    if (!networkReady() || !confirmed || !validReason(reason) || !isUuid(certificateId) || !isUuid(ownerInstanceId_)) return;
    const auto known = std::find_if(ownerCertificates_.cbegin(), ownerCertificates_.cend(), [&](const QVariant &entry) {
        return entry.toMap().value(QStringLiteral("id")).toString() == certificateId && !entry.toMap().value(QStringLiteral("details")).toMap().value(QStringLiteral("fingerprint")).toString().isEmpty();
    });
    if (known == ownerCertificates_.cend()) { fail(QStringLiteral("请先加载证书历史，核对证书身份后再确认吊销。")); return; }
    auto pending = ownerSettings_.value(QStringLiteral("pendingRevocations")).toMap();
    const QString key = ownerInstanceId_ + QStringLiteral("/") + certificateId;
    if (pending.contains(key) && pending.value(key).toInt() != reason) { fail(QStringLiteral("先前吊销结果待确认，请保留原原因码恢复。")); return; }
    pending[key] = reason; ownerSettings_[QStringLiteral("pendingRevocations")] = pending;
    if (auto saved = vault_.saveSigningRecord(QStringLiteral("owner"), QStringLiteral("owner"), QJsonObject::fromVariantMap(ownerSettings_)); !saved) { fail(saved.error().message); return; }
    ownerRequest("POST", QStringLiteral("/signing-instances/") + ownerInstanceId_ + QStringLiteral("/certificates/") + certificateId + QStringLiteral("/revoke"),
        QJsonDocument(QJsonObject{{QStringLiteral("reason"), reason}}).toJson(QJsonDocument::Compact), 200,
        [this, key, reason, certificateId](const auto &result) {
            const auto record = certificateFields(objectResponse(result));
            if (record.value(QStringLiteral("id")).toString() != certificateId || record.value(QStringLiteral("status")).toString() != QStringLiteral("revoked") || record.value(QStringLiteral("revocation_reason")).toInt(-1) != reason) {
                fail(QStringLiteral("吊销响应无法确认，请刷新历史并保留原原因恢复。")); return;
            }
            auto pending = ownerSettings_.value(QStringLiteral("pendingRevocations")).toMap(); pending.remove(key);
            ownerSettings_[QStringLiteral("pendingRevocations")] = pending;
            if (auto saved = vault_.saveSigningRecord(QStringLiteral("owner"), QStringLiteral("owner"), QJsonObject::fromVariantMap(ownerSettings_)); !saved) { fail(saved.error().message); return; }
            audit(QStringLiteral("SIGNING_OWNER_REVOKE_CERTIFICATE"), certificateId, QStringLiteral("SUCCESS"));
            ownerLoadCertificates(false);
        });
}
} // namespace certmgr::app
