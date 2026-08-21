#include "AppController.h"

#include <QFile>
#include <QCoreApplication>
#include <QEventLoop>
#include <QJsonDocument>
#include <QHash>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTimer>
#include <QUrl>
#include <QUuid>
#include <QClipboard>
#include <QGuiApplication>
#include <sodium.h>

#include <algorithm>

namespace certmgr::app {
namespace {

QString dataDirectory()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
}

QByteArray pemBody(QByteArray data)
{
    data.replace("-----BEGIN CERTIFICATE-----", "");
    data.replace("-----END CERTIFICATE-----", "");
    data.replace("\r", "");
    data.replace("\n", "");
    data.replace(" ", "");
    return QByteArray::fromBase64(data);
}

tl::expected<QList<QByteArray>, domain::AppError> certificateBundle(const QByteArray &contents)
{
    QList<QByteArray> certificates;
    constexpr auto beginMarker = "-----BEGIN CERTIFICATE-----";
    constexpr auto endMarker = "-----END CERTIFICATE-----";
    qsizetype offset = 0;
    while (true) {
        const qsizetype begin = contents.indexOf(beginMarker, offset);
        if (begin < 0) break;
        const qsizetype bodyStart = begin + QByteArrayView(beginMarker).size();
        const qsizetype end = contents.indexOf(endMarker, bodyStart);
        if (end < 0)
            return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
                QStringLiteral("certificate.pem_end"), 0,
                QStringLiteral("PEM 证书缺少结束标记。"), {}});
        const QByteArray decoded = QByteArray::fromBase64(contents.mid(bodyStart, end - bodyStart));
        if (decoded.isEmpty())
            return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
                QStringLiteral("certificate.pem_base64"), 0,
                QStringLiteral("PEM 证书包含无效的 Base64 数据。"), {}});
        certificates.append(decoded);
        offset = end + QByteArrayView(endMarker).size();
    }
    if (certificates.isEmpty() && !contents.isEmpty()) certificates.append(contents);
    if (certificates.isEmpty())
        return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
            QStringLiteral("certificate.empty"), 0, QStringLiteral("证书文件为空。"), {}});
    return certificates;
}

QString enrollmentStateLabel(const domain::EnrollmentState state)
{
    using enum domain::EnrollmentState;
    switch (state) {
    case Draft: return QStringLiteral("草稿");
    case KeyCreated: return QStringLiteral("已创建密钥");
    case CsrCreated: return QStringLiteral("已生成 CSR");
    case Submitted: return QStringLiteral("已提交");
    case Pending: return QStringLiteral("等待签发");
    case Issued: return QStringLiteral("已签发");
    case Installed: return QStringLiteral("已安装");
    case Denied: return QStringLiteral("已拒绝");
    case Failed: return QStringLiteral("失败");
    case Revoked: return QStringLiteral("已吊销");
    }
    return QStringLiteral("未知");
}

QString auditActionLabel(const QString &action)
{
    static const QHash<QString, QString> labels{
        {QStringLiteral("CREATE_CSR"), QStringLiteral("创建 CSR")},
        {QStringLiteral("EXPORT_CSR"), QStringLiteral("导出 CSR")},
        {QStringLiteral("SUBMIT_CSR"), QStringLiteral("提交 CSR")},
        {QStringLiteral("PREPARE_MANUAL_SUBMISSION"), QStringLiteral("准备手动提交")},
        {QStringLiteral("INSTALL_RESPONSE"), QStringLiteral("安装签发证书")},
        {QStringLiteral("INSTALL_PKCS12"), QStringLiteral("安装 P12/PFX")},
        {QStringLiteral("INSTALL_CERTIFICATE_PACKAGE"), QStringLiteral("安装证书包")},
        {QStringLiteral("INSTALL_ROOT"), QStringLiteral("安装根证书")},
        {QStringLiteral("INSTALL_CERTIFICATE"), QStringLiteral("安装证书")},
        {QStringLiteral("REMOVE_CERTIFICATE"), QStringLiteral("删除证书")},
        {QStringLiteral("EXPORT_CERTIFICATE"), QStringLiteral("导出证书")},
        {QStringLiteral("MANAGE_ROOT"), QStringLiteral("加入根证书管理")},
        {QStringLiteral("UNMANAGE_ROOT"), QStringLiteral("移出根证书管理")},
        {QStringLiteral("SAVE_CONNECTION"), QStringLiteral("保存 PKI 连接")},
        {QStringLiteral("REMOVE_CONNECTION"), QStringLiteral("删除 PKI 连接")},
        {QStringLiteral("LOCK_VAULT"), QStringLiteral("锁定保险库")},
        {QStringLiteral("CLOSE_APPLICATION"), QStringLiteral("安全退出")}
    };
    return labels.value(action, action);
}

QString resolvedSubject(const domain::CertificateTemplate &value)
{
    QStringList parts;
    for (const QString &key : {QStringLiteral("CN"), QStringLiteral("OU"), QStringLiteral("O"),
                               QStringLiteral("L"), QStringLiteral("ST"), QStringLiteral("C")}) {
        const auto field = value.subject.constFind(key);
        if (field != value.subject.cend() && !field->value.isEmpty())
            parts.append(QStringLiteral("%1=%2").arg(key, field->value));
    }
    return parts.join(QStringLiteral(", "));
}

QStringList optionStrings(const QVariant &value)
{
    if (value.canConvert<QStringList>()) return value.toStringList();
    QStringList result;
    for (const QVariant &item : value.toList()) {
        const QString text = item.toString().trimmed();
        if (!text.isEmpty()) result.append(text);
    }
    return result;
}

QStringList splitNames(const QVariant &value)
{
    return value.toString().split(QRegularExpression(QStringLiteral("[,;\\s]+")),
                                  Qt::SkipEmptyParts);
}

struct NetworkResult {
    int status{0};
    QByteArray body;
    QString location;
    QString error;
    bool timedOut{false};
};

NetworkResult runNetworkRequest(const QUrl &url, const QByteArray &method, const QByteArray &body = {})
{
    QNetworkAccessManager manager;
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("APCM/0.1"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/pkcs10"));
    QNetworkReply *reply = method == QByteArrayLiteral("POST")
        ? manager.post(request, body) : manager.get(request);
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, [&] { reply->abort(); loop.quit(); });
    timer.start(5000);
    loop.exec();
    NetworkResult result;
    result.timedOut = !timer.isActive();
    timer.stop();
    result.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    result.body = reply->readAll();
    result.location = reply->header(QNetworkRequest::LocationHeader).toString();
    result.error = result.timedOut ? QStringLiteral("连接超时。") : reply->errorString();
    reply->deleteLater();
    return result;
}

} // namespace

AppController::AppController(QObject *parent)
    : QObject(parent), vault_(dataDirectory())
{
}

QVariantList AppController::templates() const
{
    QVariantList values;
    for (const auto &item : templateService_.builtInTemplates()) {
        QVariantMap value;
        value.insert(QStringLiteral("id"), item.id);
        value.insert(QStringLiteral("name"), item.name);
        value.insert(QStringLiteral("version"), item.version);
        value.insert(QStringLiteral("scope"), domain::storeScopeName(item.scope));
        value.insert(QStringLiteral("provider"), item.key.provider);
        value.insert(QStringLiteral("bits"), item.key.bits);
        value.insert(QStringLiteral("exportable"), item.key.exportable);
        value.insert(QStringLiteral("hardwareRequired"), item.key.hardwareRequired);
        const auto cn = item.subject.constFind(QStringLiteral("CN"));
        value.insert(QStringLiteral("cnPattern"), cn == item.subject.cend() ? QString{} : cn->pattern.pattern());
        values.append(value);
    }
    return values;
}

void AppController::setBusy(const bool value)
{
    if (busy_ == value) return;
    busy_ = value;
    emit busyChanged();
}

void AppController::setError(const domain::AppError &error)
{
    errorMessage_ = error.message;
    if (!error.details.isEmpty()) errorMessage_ += QStringLiteral("\n") + error.details;
    emit errorMessageChanged();
}

void AppController::setStatus(QString message)
{
    statusMessage_ = std::move(message);
    emit statusMessageChanged();
}

void AppController::clearMessage()
{
    errorMessage_.clear();
    statusMessage_.clear();
    emit errorMessageChanged();
    emit statusMessageChanged();
}

bool AppController::initializeVault(const QString &masterPassword)
{
    QByteArray bytes = masterPassword.toUtf8();
    const auto result = vault_.initialize(bytes);
    sodium_memzero(bytes.data(), static_cast<size_t>(bytes.size()));
    if (!result) { setError(result.error()); return false; }
    emit vaultStateChanged();
    refresh();
    return true;
}

bool AppController::unlockVault(const QString &masterPassword)
{
    QByteArray bytes = masterPassword.toUtf8();
    const auto result = vault_.unlock(bytes);
    sodium_memzero(bytes.data(), static_cast<size_t>(bytes.size()));
    if (!result) { setError(result.error()); return false; }
    emit vaultStateChanged();
    refresh();
    return true;
}

void AppController::lockVault()
{
    closeVault(QStringLiteral("LOCK_VAULT"));
}

void AppController::closeVault(const QString &auditAction)
{
    if (vault_.isUnlocked()) {
        // Best-effort final audit write; lock must always proceed even if logging fails.
        static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(), auditAction,
            QStringLiteral("application"), QStringLiteral("本地加密保险库"),
            QStringLiteral("SUCCESS"), {}}));
    }
    vault_.lock();
    certificates_.replace({});
    enrollmentRequests_.clear();
    privateKeys_.clear();
    managedRoots_.clear();
    managedCertificates_.clear();
    pkiConnections_.clear();
    auditEvents_.clear();
    emit vaultStateChanged();
}

void AppController::prepareForExit()
{
    closeVault(QStringLiteral("CLOSE_APPLICATION"));
}

void AppController::exitApplication()
{
    prepareForExit();
    QCoreApplication::quit();
}

void AppController::refresh()
{
    if (!unlocked()) return;
    setBusy(true);
    std::vector<domain::CertificateInfo> all;
    for (const auto scope : {domain::StoreScope::User, domain::StoreScope::Machine}) {
        for (const auto role : {domain::StoreRole::Personal, domain::StoreRole::TrustedRoot,
                                domain::StoreRole::IntermediateCA, domain::StoreRole::EnterpriseTrust}) {
            auto result = certificateStore_.listCertificates({scope, role, {}});
            if (result) all.insert(all.end(), std::make_move_iterator(result->begin()),
                                   std::make_move_iterator(result->end()));
        }
    }
    expiringSoon_ = 0;
    for (const auto &certificate : all) {
        const qint64 days = QDateTime::currentDateTime().daysTo(certificate.notAfter);
        if (days >= 0 && days <= 30) ++expiringSoon_;
    }
    privateKeys_.clear();
    auto keyResult = keyProvider_.listKeys();
    if (keyResult) {
        for (const auto &key : *keyResult) {
            privateKeys_.append(QVariantMap{{QStringLiteral("provider"), key.provider},
                {QStringLiteral("container"), key.container}, {QStringLiteral("algorithm"), key.algorithm},
                {QStringLiteral("bits"), key.bits}, {QStringLiteral("machineKey"), key.machineKey},
                {QStringLiteral("exportable"), key.exportable}, {QStringLiteral("hardwareBacked"), key.hardwareBacked},
                {QStringLiteral("tpmBacked"), key.tpmBacked}});
        }
    }
    privateKeyCount_ = privateKeys_.size();
    tpmReady_ = keyProvider_.isTpmAvailable();
    certificates_.replace(std::move(all));
    loadVaultData();
    setBusy(false);
    emit dataChanged();
}

void AppController::loadVaultData()
{
    enrollmentRequests_.clear();
    if (auto requests = vault_.enrollmentRequests()) {
        for (const auto &request : *requests) {
            enrollmentRequests_.append(QVariantMap{{QStringLiteral("id"), request.id},
                {QStringLiteral("name"), request.friendlyName}, {QStringLiteral("subject"), request.subject},
                {QStringLiteral("templateId"), request.templateId},
                {QStringLiteral("createdAt"), request.createdAt},
                {QStringLiteral("state"), enrollmentStateLabel(request.state)},
                {QStringLiteral("provider"), request.providerName},
                {QStringLiteral("validityDays"), request.requestedValidityDays},
                {QStringLiteral("remoteCA"), request.remoteCA},
                {QStringLiteral("hasCsr"), !request.csrText.isEmpty()}});
        }
    }

    managedRoots_.clear();
    if (auto roots = vault_.managedRoots()) {
        for (const auto &root : *roots) {
            bool installed = false;
            QDateTime expires;
            for (const auto &certificate : certificates_.values()) {
                if (certificate.sha256Fingerprint == root.fingerprint) {
                    installed = true;
                    expires = certificate.notAfter;
                    break;
                }
            }
            managedRoots_.append(QVariantMap{{QStringLiteral("fingerprint"), root.fingerprint},
                {QStringLiteral("name"), root.friendlyName}, {QStringLiteral("scope"), root.scope},
                {QStringLiteral("installed"), installed}, {QStringLiteral("expires"), expires}});
        }
    }

    managedCertificates_.clear();
    if (auto managed = vault_.managedCertificates()) {
        for (const auto &record : *managed) {
            bool installed = false;
            for (const auto &certificate : certificates_.values()) {
                if (certificate.sha256Fingerprint == record.fingerprint) {
                    installed = true;
                    break;
                }
            }
            managedCertificates_.append(QVariantMap{{QStringLiteral("fingerprint"), record.fingerprint},
                {QStringLiteral("name"), record.friendlyName}, {QStringLiteral("scope"), record.scope},
                {QStringLiteral("storeRole"), record.storeRole}, {QStringLiteral("installed"), installed}});
        }
    }

    pkiConnections_.clear();
    if (auto connections = vault_.connections()) {
        for (const auto &connection : *connections) {
            pkiConnections_.append(QVariantMap{{QStringLiteral("id"), connection.id},
                {QStringLiteral("name"), connection.name}, {QStringLiteral("type"), connection.type},
                {QStringLiteral("endpoint"), connection.endpoint}, {QStringLiteral("enabled"), connection.enabled}});
        }
    }

    auditEvents_.clear();
    if (auto events = vault_.auditEvents()) {
        for (const auto &event : *events) {
            auditEvents_.append(QVariantMap{{QStringLiteral("timestamp"), event.timestamp.toLocalTime()},
                {QStringLiteral("action"), auditActionLabel(event.action)},
                {QStringLiteral("target"), event.target}, {QStringLiteral("scope"), event.scope},
                {QStringLiteral("result"), event.result == QStringLiteral("SUCCESS") ? QStringLiteral("成功") : QStringLiteral("失败")},
                {QStringLiteral("error"), event.error}});
        }
    }
}

QVariantMap AppController::certificateDetails(const QString &id) const
{
    const auto *value = certificates_.find(id);
    if (!value) return {};
    return {{QStringLiteral("id"), value->id}, {QStringLiteral("name"), value->commonName},
        {QStringLiteral("subject"), value->subject}, {QStringLiteral("issuer"), value->issuer},
        {QStringLiteral("serial"), value->serialNumber}, {QStringLiteral("sha256"), value->sha256Fingerprint},
        {QStringLiteral("sha1"), value->sha1Thumbprint}, {QStringLiteral("notBefore"), value->notBefore},
        {QStringLiteral("notAfter"), value->notAfter}, {QStringLiteral("scope"), domain::storeScopeName(value->location.scope)},
        {QStringLiteral("store"), domain::storeRoleName(value->location.role)},
        {QStringLiteral("hasPrivateKey"), value->hasPrivateKey}, {QStringLiteral("provider"), value->keyProvider},
        {QStringLiteral("container"), value->keyContainer}, {QStringLiteral("hardwareBacked"), value->hardwareBacked},
        {QStringLiteral("tpmBacked"), value->tpmBacked}, {QStringLiteral("exportable"), value->exportable},
        {QStringLiteral("isCA"), value->isCA},
        {QStringLiteral("isRoot"), value->location.role == domain::StoreRole::TrustedRoot},
        {QStringLiteral("isManaged"), std::any_of(managedCertificates_.cbegin(), managedCertificates_.cend(), [&](const QVariant &root) {
            return root.toMap().value(QStringLiteral("fingerprint")).toString() == value->sha256Fingerprint;
        })},
        {QStringLiteral("valid"), value->chain.valid},
        {QStringLiteral("diagnostics"), value->chain.diagnostics},
        {QStringLiteral("publicKeyAlgorithm"), value->publicKeyAlgorithm},
        {QStringLiteral("signatureAlgorithm"), value->signatureAlgorithm},
        {QStringLiteral("eku"), value->extendedKeyUsage}};
}

QVariantMap AppController::previewCertificate(const QUrl &source)
{
    QFile file(source.toLocalFile());
    if (!file.open(QIODevice::ReadOnly)) {
        setError({domain::ErrorCategory::General, QStringLiteral("preview.read"), 0,
                  QStringLiteral("无法读取所选证书。"), file.errorString()});
        return {};
    }
    auto result = certificateStore_.decodeCertificate(decodeCertificateFile(file.readAll()));
    if (!result) { setError(result.error()); return {}; }
    return {{QStringLiteral("subject"), result->subject}, {QStringLiteral("issuer"), result->issuer},
        {QStringLiteral("sha256"), result->sha256Fingerprint}, {QStringLiteral("notBefore"), result->notBefore},
        {QStringLiteral("notAfter"), result->notAfter}, {QStringLiteral("isCA"), result->isCA},
        {QStringLiteral("publicKeyAlgorithm"), result->publicKeyAlgorithm},
        {QStringLiteral("publicKeyBits"), result->publicKeyBits}};
}

bool AppController::exportCertificate(const QString &id, const QUrl &destination)
{
    const auto *value = certificates_.find(id);
    if (!value) return false;
    QSaveFile file(destination.toLocalFile());
    if (!file.open(QIODevice::WriteOnly) || file.write(value->encodedDer) != value->encodedDer.size() || !file.commit()) {
        setError({domain::ErrorCategory::General, QStringLiteral("export.write"), 0,
                  QStringLiteral("无法导出证书。"), file.errorString()});
        return false;
    }
    static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(), QStringLiteral("EXPORT_CERTIFICATE"),
        value->sha256Fingerprint, domain::storeScopeName(value->location.scope), QStringLiteral("SUCCESS"), {}}));
    setStatus(QStringLiteral("证书已导出，未包含私钥。"));
    loadVaultData();
    emit dataChanged();
    return true;
}

QByteArray AppController::decodeCertificateFile(const QByteArray &contents)
{
    return contents.contains("-----BEGIN CERTIFICATE-----") ? pemBody(contents) : contents;
}

bool AppController::importCertificate(const QUrl &source, const int scope, const int role,
                                      const bool rootTrustConfirmed)
{
    return installCertificatePackage(source, {}, scope, role, rootTrustConfirmed)
        .value(QStringLiteral("success")).toBool();
}

QVariantMap AppController::previewCertificatePackage(const QUrl &source, const QString &password)
{
    QFile file(source.toLocalFile());
    if (!file.open(QIODevice::ReadOnly) || file.size() > 32 * 1024 * 1024) {
        setError({domain::ErrorCategory::General, QStringLiteral("certificate.package_read"), 0,
                  QStringLiteral("无法读取证书安装包，或文件超过 32 MiB。"), file.errorString()});
        return {};
    }
    const QByteArray contents = file.readAll();
    std::vector<domain::CertificateInfo> certificates;
    const bool pkcs12 = platform::windows::WindowsCertificateStore::isPkcs12(contents);
    if (pkcs12) {
        auto result = certificateStore_.inspectPkcs12(contents, password);
        if (!result) { setError(result.error()); return {}; }
        certificates = std::move(*result);
    } else {
        auto bundle = certificateBundle(contents);
        if (!bundle) { setError(bundle.error()); return {}; }
        for (const auto &encoded : *bundle) {
            auto decoded = certificateStore_.decodeCertificate(encoded);
            if (!decoded) { setError(decoded.error()); return {}; }
            certificates.emplace_back(std::move(*decoded));
        }
    }
    const auto &first = certificates.front();
    return {{QStringLiteral("format"), pkcs12 ? QStringLiteral("P12 / PFX") :
                (contents.contains("-----BEGIN CERTIFICATE-----") ? QStringLiteral("PEM") : QStringLiteral("DER / CRT"))},
        {QStringLiteral("count"), static_cast<int>(certificates.size())},
        {QStringLiteral("name"), first.commonName.isEmpty() ? first.subject : first.commonName},
        {QStringLiteral("subject"), first.subject}, {QStringLiteral("issuer"), first.issuer},
        {QStringLiteral("isCA"), first.isCA}, {QStringLiteral("hasPrivateKey"), first.hasPrivateKey},
        {QStringLiteral("sha256"), first.sha256Fingerprint}};
}

QVariantMap AppController::installCertificatePackage(const QUrl &source, const QString &password,
                                                      const int scope, const int role,
                                                      const bool rootTrustConfirmed)
{
    if (scope < static_cast<int>(domain::StoreScope::User) ||
        scope > static_cast<int>(domain::StoreScope::Machine) ||
        role < static_cast<int>(domain::StoreRole::Personal) ||
        role > static_cast<int>(domain::StoreRole::EnterpriseTrust)) {
        setError({domain::ErrorCategory::Validation, QStringLiteral("certificate.target"), 0,
                  QStringLiteral("证书安装位置无效。"), {}});
        return {};
    }
    const auto targetScope = static_cast<domain::StoreScope>(scope);
    const auto targetRole = static_cast<domain::StoreRole>(role);
    if (targetRole == domain::StoreRole::TrustedRoot && !rootTrustConfirmed) {
        setError({domain::ErrorCategory::Validation, QStringLiteral("root.confirmation_required"), 0,
                  QStringLiteral("安装受信任的根证书需要明确确认。"), {}});
        return {};
    }
    QFile file(source.toLocalFile());
    if (!file.open(QIODevice::ReadOnly) || file.size() > 32 * 1024 * 1024) {
        setError({domain::ErrorCategory::General, QStringLiteral("certificate.package_read"), 0,
                  QStringLiteral("无法读取证书安装包，或文件超过 32 MiB。"), file.errorString()});
        return {};
    }
    const QByteArray contents = file.readAll();
    const domain::CertificateStoreLocation target{targetScope, targetRole, {}};
    std::vector<domain::CertificateInfo> installed;
    const bool pkcs12 = platform::windows::WindowsCertificateStore::isPkcs12(contents);
    if (pkcs12) {
        auto inspected = certificateStore_.inspectPkcs12(contents, password);
        if (!inspected) { setError(inspected.error()); return {}; }
        if (targetRole == domain::StoreRole::TrustedRoot &&
            std::any_of(inspected->cbegin(), inspected->cend(), [](const auto &item) { return !item.isCA; })) {
            setError({domain::ErrorCategory::Validation, QStringLiteral("pkcs12.root_contains_leaf"), 0,
                      QStringLiteral("该 P12/PFX 包包含非 CA 证书，不能整体安装到受信任根存储。"), {}});
            return {};
        }
        if (targetScope == domain::StoreScope::Machine) {
            if (auto result = elevatedHelper_.importMachinePkcs12(source.toLocalFile(), password, targetRole); !result) {
                setError(result.error()); return {};
            }
            installed = std::move(*inspected);
        } else {
            auto result = certificateStore_.importPkcs12(contents, password, target);
            if (!result) { setError(result.error()); return {}; }
            installed = std::move(*result);
        }
    } else {
        auto bundle = certificateBundle(contents);
        if (!bundle) { setError(bundle.error()); return {}; }
        QStringList fingerprints;
        for (const auto &encoded : *bundle) {
            auto preview = certificateStore_.decodeCertificate(encoded);
            if (!preview) { setError(preview.error()); return {}; }
            if (targetRole == domain::StoreRole::TrustedRoot && !preview->isCA) {
                setError({domain::ErrorCategory::Validation, QStringLiteral("root.not_ca"), 0,
                          QStringLiteral("只有 CA 证书才能安装到受信任根存储。"), {}});
                return {};
            }
            fingerprints.append(preview->sha256Fingerprint);
            installed.emplace_back(std::move(*preview));
        }
        if (targetScope == domain::StoreScope::Machine) {
            if (auto result = elevatedHelper_.installMachineCertificatePackage(source.toLocalFile(), fingerprints, targetRole); !result) {
                setError(result.error()); return {};
            }
        } else {
            for (const auto &encoded : *bundle) {
                if (auto result = certificateStore_.installCertificate(encoded, target); !result) {
                    setError(result.error()); return {};
                }
            }
        }
    }

    for (const auto &certificate : installed) {
        const persistence::SqlCipherVault::ManagedRootRecord record{certificate.sha256Fingerprint,
            domain::storeScopeName(targetScope), domain::storeRoleName(targetRole),
            certificate.commonName.isEmpty() ? certificate.subject : certificate.commonName};
        const auto saved = targetRole == domain::StoreRole::TrustedRoot
            ? vault_.saveManagedRoot(record) : vault_.saveManagedCertificate(record);
        if (!saved) { setError(saved.error()); return {}; }
    }
    static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(),
        pkcs12 ? QStringLiteral("INSTALL_PKCS12") : QStringLiteral("INSTALL_CERTIFICATE_PACKAGE"),
        source.fileName(), domain::storeScopeName(targetScope), QStringLiteral("SUCCESS"), {}}));
    setStatus(QStringLiteral("已安装 %1 张证书，并自动加入 APCM 管理。").arg(installed.size()));
    refresh();
    return {{QStringLiteral("success"), true}, {QStringLiteral("count"), static_cast<int>(installed.size())}};
}

bool AppController::deleteCertificate(const QString &id, const bool confirmed)
{
    if (!confirmed) return false;
    const auto result = certificateStore_.removeCertificate(id);
    if (!result) { setError(result.error()); return false; }
    const auto auditResult = vault_.append({QDateTime::currentDateTimeUtc(), QStringLiteral("REMOVE_CERTIFICATE"), id,
                   QStringLiteral("Windows 证书存储"), QStringLiteral("SUCCESS"), {}});
    if (!auditResult) setError(auditResult.error());
    setStatus(QStringLiteral("证书已删除，关联私钥未被删除。"));
    refresh();
    return true;
}

bool AppController::copyToClipboard(const QString &text, const QString &description)
{
    if (text.trimmed().isEmpty()) {
        setError({domain::ErrorCategory::Validation, QStringLiteral("clipboard.empty"), 0,
                  QStringLiteral("没有可复制的内容。"), {}});
        return false;
    }
    QGuiApplication::clipboard()->setText(text);
    setStatus(QStringLiteral("%1已复制到剪贴板。").arg(description.trimmed().isEmpty()
        ? QStringLiteral("内容") : description.trimmed()));
    return true;
}

QVariantMap AppController::generateRequest(const QString &templateId, const QVariantMap &options)
{
    const auto templates = templateService_.builtInTemplates();
    const auto found = std::find_if(templates.cbegin(), templates.cend(),
                                    [&](const auto &value) { return value.id == templateId; });
    if (found == templates.cend()) {
        setError({domain::ErrorCategory::Validation, QStringLiteral("request.template_missing"), 0,
                  QStringLiteral("所选证书模板不存在。"), {}});
        return {};
    }
    const QString commonName = options.value(QStringLiteral("commonName")).toString().trimmed();
    const QString friendlyName = options.value(QStringLiteral("friendlyName")).toString().trimmed();
    if (commonName.isEmpty() || friendlyName.isEmpty()) {
        setError({domain::ErrorCategory::Validation, QStringLiteral("request.fields_required"), 0,
                  QStringLiteral("证书名称和通用名称（CN）不能为空。"), {}});
        return {};
    }
    domain::CertificateTemplate customized = *found;
    customized.friendlyName = friendlyName;
    customized.subject.insert(QStringLiteral("CN"),
        {domain::FieldSource::UserInput, commonName, {}, true});
    const QString organization = options.value(QStringLiteral("organization")).toString().trimmed();
    const QString organizationUnit = options.value(QStringLiteral("organizationUnit")).toString().trimmed();
    if (organization.isEmpty()) customized.subject.remove(QStringLiteral("O"));
    else customized.subject.insert(QStringLiteral("O"),
        {domain::FieldSource::UserInput, organization, {}, true});
    if (organizationUnit.isEmpty()) customized.subject.remove(QStringLiteral("OU"));
    else customized.subject.insert(QStringLiteral("OU"),
        {domain::FieldSource::UserInput, organizationUnit, {}, true});
    const auto setOptionalSubject = [&](const QString &name, const QString &option) {
        const QString value = options.value(option).toString().trimmed();
        if (value.isEmpty()) customized.subject.remove(name);
        else customized.subject.insert(name,
            {domain::FieldSource::UserInput, value, {}, true});
    };
    setOptionalSubject(QStringLiteral("L"), QStringLiteral("locality"));
    setOptionalSubject(QStringLiteral("ST"), QStringLiteral("state"));
    setOptionalSubject(QStringLiteral("C"), QStringLiteral("country"));

    const int scopeValue = options.value(QStringLiteral("scope"), 0).toInt();
    if (scopeValue != 0 && scopeValue != 1) {
        setError({domain::ErrorCategory::Validation, QStringLiteral("request.scope_invalid"), 0,
                  QStringLiteral("密钥作用域无效。"), {}});
        return {};
    }
    customized.scope = scopeValue == 1 ? domain::StoreScope::Machine : domain::StoreScope::User;
    customized.key.provider = options.value(QStringLiteral("provider"),
        QStringLiteral("Microsoft Software Key Storage Provider")).toString().trimmed();
    customized.key.algorithm = QStringLiteral("RSA");
    customized.key.bits = options.value(QStringLiteral("keyBits"), 2048).toInt();
    customized.key.hardwareRequired = customized.key.provider.compare(
        QStringLiteral("Microsoft Platform Crypto Provider"), Qt::CaseInsensitive) == 0;
    customized.key.exportable = options.value(QStringLiteral("exportable"), false).toBool();
    customized.dnsSans = splitNames(options.value(QStringLiteral("dnsSans")));
    customized.ipSans = splitNames(options.value(QStringLiteral("ipSans")));
    customized.uriSans = splitNames(options.value(QStringLiteral("uriSans")));
    customized.upnSans = splitNames(options.value(QStringLiteral("upnSans")));
    customized.keyUsage = optionStrings(options.value(QStringLiteral("keyUsage")));
    customized.extendedKeyUsage = optionStrings(options.value(QStringLiteral("extendedKeyUsage")));
    const int validityDays = std::clamp(options.value(QStringLiteral("validityDays"), 365).toInt(), 1, 3650);

    auto resolved = templateService_.resolveAndValidate(customized);
    if (!resolved) { setError(resolved.error()); return {}; }
    auto generated = resolved->scope == domain::StoreScope::Machine
        ? elevatedHelper_.createMachinePkcs10(*resolved)
        : enrollmentBackend_.createPkcs10(*resolved);
    if (!generated) { setError(generated.error()); return {}; }
    domain::EnrollmentRequest request;
    request.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    request.templateId = resolved->id;
    request.templateVersion = resolved->version;
    request.scope = resolved->scope;
    request.createdAt = QDateTime::currentDateTimeUtc();
    request.updatedAt = request.createdAt;
    request.subject = resolvedSubject(*resolved);
    request.csrSha256 = generated->csrSha256;
    request.publicKeySha256 = generated->publicKeySha256;
    request.providerName = generated->providerName;
    request.keyContainerName = generated->keyContainerName;
    request.state = domain::EnrollmentState::CsrCreated;
    request.friendlyName = friendlyName;
    request.requestedValidityDays = validityDays;
    request.csrText = generated->csrBase64;
    if (auto saved = vault_.saveEnrollmentRequest(request); !saved) {
        setError(saved.error());
        return {};
    }
    const auto auditResult = vault_.append({QDateTime::currentDateTimeUtc(), QStringLiteral("CREATE_CSR"), generated->csrSha256,
                   domain::storeScopeName(resolved->scope), QStringLiteral("SUCCESS"), {}});
    if (!auditResult) setError(auditResult.error());
    setStatus(QStringLiteral("CSR 已生成。私钥保留在 %1 中（%2，%3）。")
                  .arg(generated->providerName,
                       resolved->scope == domain::StoreScope::Machine
                           ? QStringLiteral("本地计算机") : QStringLiteral("当前用户"),
                       resolved->key.exportable ? QStringLiteral("允许导出") : QStringLiteral("不可导出")));
    loadVaultData();
    emit dataChanged();
    return {{QStringLiteral("requestId"), request.id}, {QStringLiteral("csr"), generated->csrBase64}};
}

QString AppController::requestCsr(const QString &requestId) const
{
    if (auto requests = vault_.enrollmentRequests()) {
        const auto found = std::find_if(requests->cbegin(), requests->cend(),
            [&](const auto &request) { return request.id == requestId; });
        if (found != requests->cend()) return found->csrText;
    }
    return {};
}

bool AppController::exportRequestCsr(const QString &requestId, const QUrl &destination)
{
    const QString csr = requestCsr(requestId);
    if (csr.isEmpty()) {
        setError({domain::ErrorCategory::Validation, QStringLiteral("request.csr_missing"), 0,
                  QStringLiteral("所选申请没有可导出的 CSR。"), {}});
        return false;
    }
    QSaveFile file(destination.toLocalFile());
    const QByteArray encoded = csr.toUtf8();
    if (!file.open(QIODevice::WriteOnly) || file.write(encoded) != encoded.size() || !file.commit()) {
        setError({domain::ErrorCategory::General, QStringLiteral("request.csr_export"), 0,
                  QStringLiteral("无法导出 CSR。"), file.errorString()});
        return false;
    }
    static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(), QStringLiteral("EXPORT_CSR"),
        requestId, QStringLiteral("本地文件"), QStringLiteral("SUCCESS"), {}}));
    setStatus(QStringLiteral("CSR 已导出。"));
    loadVaultData();
    emit dataChanged();
    return true;
}

bool AppController::installEnrollmentResponse(const QString &requestId, const QUrl &source)
{
    auto requests = vault_.enrollmentRequests();
    if (!requests) { setError(requests.error()); return false; }
    auto request = std::find_if(requests->begin(), requests->end(),
        [&](const auto &value) { return value.id == requestId; });
    if (request == requests->end()) {
        setError({domain::ErrorCategory::Validation, QStringLiteral("request.install_missing"), 0,
                  QStringLiteral("所选证书申请不存在。"), {}});
        return false;
    }
    QFile file(source.toLocalFile());
    if (!file.open(QIODevice::ReadOnly)) {
        setError({domain::ErrorCategory::General, QStringLiteral("request.install_read"), 0,
                  QStringLiteral("无法读取签发证书。"), file.errorString()});
        return false;
    }
    const QByteArray contents = file.readAll();
    auto certificate = certificateStore_.decodeCertificate(decodeCertificateFile(contents));
    if (!certificate) { setError(certificate.error()); return false; }
    const QByteArray certificateDer = decodeCertificateFile(contents);
    if (request->scope == domain::StoreScope::Machine) {
        if (auto installed = elevatedHelper_.installMachineEnrollmentResponse(
                source.toLocalFile(), certificate->sha256Fingerprint, request->providerName,
                request->keyContainerName, request->friendlyName); !installed) {
            setError(installed.error());
            return false;
        }
    } else if (auto installed = enrollmentBackend_.installResponse(
                   certificateDer, request->scope, request->providerName,
                   request->keyContainerName, request->friendlyName); !installed) {
        setError(installed.error());
        return false;
    }
    request->state = domain::EnrollmentState::Installed;
    request->updatedAt = QDateTime::currentDateTimeUtc();
    request->certificateFingerprint = certificate->sha256Fingerprint;
    if (auto saved = vault_.saveEnrollmentRequest(*request); !saved) { setError(saved.error()); return false; }
    const persistence::SqlCipherVault::ManagedRootRecord managedRecord{certificate->sha256Fingerprint,
        domain::storeScopeName(request->scope), domain::storeRoleName(domain::StoreRole::Personal),
        certificate->commonName.isEmpty() ? certificate->subject : certificate->commonName};
    if (auto managed = vault_.saveManagedCertificate(managedRecord); !managed) {
        setError(managed.error());
        return false;
    }
    static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(), QStringLiteral("INSTALL_RESPONSE"),
        certificate->sha256Fingerprint, domain::storeScopeName(request->scope), QStringLiteral("SUCCESS"), {}}));
    setStatus(QStringLiteral("签发证书已安装并与 Windows 中的申请私钥关联。"));
    refresh();
    return true;
}

bool AppController::manageRoot(const QString &certificateId)
{
    const auto *certificate = certificates_.find(certificateId);
    if (!certificate || certificate->location.role != domain::StoreRole::TrustedRoot || !certificate->isCA) {
        setError({domain::ErrorCategory::Validation, QStringLiteral("root.manage_invalid"), 0,
                  QStringLiteral("只能将 Windows 受信任根存储中的 CA 证书加入 APCM 管理。"), {}});
        return false;
    }
    const persistence::SqlCipherVault::ManagedRootRecord record{certificate->sha256Fingerprint,
        domain::storeScopeName(certificate->location.scope), domain::storeRoleName(certificate->location.role),
        certificate->commonName.isEmpty() ? certificate->subject : certificate->commonName};
    if (auto result = vault_.saveManagedRoot(record); !result) { setError(result.error()); return false; }
    static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(), QStringLiteral("MANAGE_ROOT"),
        certificate->sha256Fingerprint, record.scope, QStringLiteral("SUCCESS"), {}}));
    setStatus(QStringLiteral("根证书已加入 APCM 管理，但其 Windows 信任状态没有改变。"));
    loadVaultData();
    emit dataChanged();
    return true;
}

bool AppController::unmanageRoot(const QString &fingerprint)
{
    if (auto result = vault_.removeManagedRoot(fingerprint); !result) { setError(result.error()); return false; }
    static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(), QStringLiteral("UNMANAGE_ROOT"),
        fingerprint, QStringLiteral("APCM"), QStringLiteral("SUCCESS"), {}}));
    setStatus(QStringLiteral("已从 APCM 管理清单移除；Windows 中的根证书未被删除。"));
    loadVaultData();
    emit dataChanged();
    return true;
}

QString AppController::savePkiConnection(const QString &id, const QString &name,
                                         const QString &type, const QString &endpoint)
{
    const QString cleanName = name.trimmed();
    const QString cleanType = type.trimmed().toLower();
    const QString cleanEndpoint = endpoint.trimmed();
    const QUrl endpointUrl(cleanEndpoint);
    const bool endpointValid = endpointUrl.isValid() &&
        (endpointUrl.scheme() == QStringLiteral("http") || endpointUrl.scheme() == QStringLiteral("https"));
    const bool supportedType = cleanType == QStringLiteral("manual") ||
        cleanType == QStringLiteral("http-pkcs10");
    if (cleanName.isEmpty() || !supportedType ||
        (cleanType != QStringLiteral("manual") && !endpointValid)) {
        setError({domain::ErrorCategory::Validation, QStringLiteral("connection.invalid"), 0,
                  QStringLiteral("请输入连接名称和有效的服务地址。"), {}});
        return {};
    }
    const QString connectionId = id.isEmpty() ? QUuid::createUuid().toString(QUuid::WithoutBraces) : id;
    if (auto result = vault_.saveConnection({connectionId, cleanType, cleanName, cleanEndpoint, true}); !result) {
        setError(result.error()); return {};
    }
    static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(), QStringLiteral("SAVE_CONNECTION"),
        connectionId, cleanName, QStringLiteral("SUCCESS"), {}}));
    setStatus(QStringLiteral("PKI 连接已加密保存。"));
    loadVaultData(); emit dataChanged();
    return connectionId;
}

bool AppController::removePkiConnection(const QString &id)
{
    if (auto result = vault_.removeConnection(id); !result) { setError(result.error()); return false; }
    static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(), QStringLiteral("REMOVE_CONNECTION"),
        id, QStringLiteral("APCM"), QStringLiteral("SUCCESS"), {}}));
    setStatus(QStringLiteral("PKI 连接已删除。"));
    loadVaultData(); emit dataChanged();
    return true;
}

bool AppController::testPkiConnection(const QString &id)
{
    const auto found = std::find_if(pkiConnections_.cbegin(), pkiConnections_.cend(), [&](const QVariant &value) {
        return value.toMap().value(QStringLiteral("id")).toString() == id;
    });
    if (found == pkiConnections_.cend()) return false;
    const QVariantMap connection = found->toMap();
    if (connection.value(QStringLiteral("type")).toString() == QStringLiteral("manual")) {
        setStatus(QStringLiteral("手动连接可用：CSR 将由用户导出并通过外部流程提交。"));
        return true;
    }
    const NetworkResult result = runNetworkRequest(QUrl(connection.value(QStringLiteral("endpoint")).toString()), QByteArrayLiteral("GET"));
    if (result.status >= 200 && result.status < 400) {
        setStatus(QStringLiteral("连接成功，服务返回 HTTP %1。").arg(result.status));
        return true;
    }
    setError({domain::ErrorCategory::Network, QStringLiteral("connection.test_failed"), 0,
              QStringLiteral("PKI 端点测试失败。"), result.status > 0
                  ? QStringLiteral("服务返回 HTTP %1。%2").arg(result.status).arg(result.error)
                  : result.error});
    return false;
}

bool AppController::submitEnrollmentRequest(const QString &requestId, const QString &connectionId)
{
    auto requests = vault_.enrollmentRequests();
    auto connections = vault_.connections();
    if (!requests || !connections) return false;
    auto request = std::find_if(requests->begin(), requests->end(), [&](const auto &value) { return value.id == requestId; });
    const auto connection = std::find_if(connections->cbegin(), connections->cend(), [&](const auto &value) { return value.id == connectionId; });
    if (request == requests->end() || connection == connections->cend()) {
        setError({domain::ErrorCategory::Validation, QStringLiteral("request.submit_missing"), 0,
                  QStringLiteral("申请或 PKI 连接不存在。"), {}});
        return false;
    }
    if (connection->type == QStringLiteral("manual")) {
        auto submitted = manualConnector_.submit({request->id, request->csrText, request->csrSha256});
        if (!submitted) { setError(submitted.error()); return false; }
        request->remoteCA = connection->name;
        request->updatedAt = QDateTime::currentDateTimeUtc();
        if (auto saved = vault_.saveEnrollmentRequest(*request); !saved) { setError(saved.error()); return false; }
        static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(), QStringLiteral("PREPARE_MANUAL_SUBMISSION"),
            request->id, connection->name, QStringLiteral("SUCCESS"), {}}));
        setStatus(QStringLiteral("手动流程已准备；CSR 尚未由 APCM 提交，请先导出并交给 CA。"));
        loadVaultData();
        emit dataChanged();
        return true;
    }
    const NetworkResult result = runNetworkRequest(QUrl(connection->endpoint), QByteArrayLiteral("POST"), request->csrText.toUtf8());
    if (result.status < 200 || result.status >= 300) {
        setError({domain::ErrorCategory::Network, QStringLiteral("request.submit_failed"), static_cast<quint64>(result.status),
                  QStringLiteral("PKI 服务拒绝了证书申请。"), result.status > 0
                      ? QStringLiteral("HTTP %1：%2").arg(result.status).arg(result.error) : result.error});
        return false;
    }
    request->remoteRequestId = result.location.isEmpty()
        ? QString::fromUtf8(result.body).trimmed().left(256) : result.location;
    request->remoteCA = connection->name;
    request->state = domain::EnrollmentState::Submitted;
    request->updatedAt = QDateTime::currentDateTimeUtc();
    if (auto saved = vault_.saveEnrollmentRequest(*request); !saved) { setError(saved.error()); return false; }
    static_cast<void>(vault_.append({QDateTime::currentDateTimeUtc(), QStringLiteral("SUBMIT_CSR"),
        request->id, connection->name, QStringLiteral("SUCCESS"), {}}));
    setStatus(QStringLiteral("CSR 已提交到 %1。").arg(connection->name));
    loadVaultData(); emit dataChanged();
    return true;
}

} // namespace certmgr::app
