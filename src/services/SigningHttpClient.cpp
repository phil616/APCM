#include "SigningHttpClient.h"

#include <QDateTime>
#include <QJsonDocument>
#include <QNetworkCookieJar>
#include <QNetworkCookie>
#include <QNetworkProxyFactory>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSslError>
#include <QSslKey>
#include <QTimer>
#include <QUuid>
#include <openssl/crypto.h>

namespace certmgr::services {
using namespace domain::signing;
SigningHttpClient::SigningHttpClient(const bool owner, QObject *parent)
    : QObject(parent), owner_(owner) {}
bool SigningHttpClient::hasOwnerCookie() const
{
    for (const auto &cookie : manager_.cookieJar()->cookiesForUrl(base_))
        if (cookie.name() == "__Host-pki_session" && cookie.isSecure() && cookie.path() == QStringLiteral("/")) return true;
    return false;
}
void SigningHttpClient::clear()
{
    if (active_) {
        active_->disconnect(this);
        active_->abort();
        active_->deleteLater();
        active_ = nullptr;
    }
    manager_.clearAccessCache(); manager_.clearConnectionCache();
    QPointer<QNetworkCookieJar> old = manager_.cookieJar();
    manager_.setCookieJar(new QNetworkCookieJar(&manager_));
    if (old) delete old;
    tls_ = {}; base_ = QUrl{}; settings_.clear();
}
Result<void> SigningHttpClient::configure(const QUrl &base, const QVariantMap &settings, const QSslConfiguration &tls)
{
    if (active_) return tl::unexpected(domain::AppError{domain::ErrorCategory::Network,
        QStringLiteral("signing.busy"), 0, QStringLiteral("请等待当前请求结束。"), {}});
    clear(); base_ = base; settings_ = settings; tls_ = tls;
    const QString proxy = settings.value(QStringLiteral("proxyType"), QStringLiteral("system")).toString();
    if (proxy == QStringLiteral("direct")) manager_.setProxy(QNetworkProxy::NoProxy);
    else if (proxy == QStringLiteral("http") || proxy == QStringLiteral("socks5")) {
        const QString host = settings.value(QStringLiteral("proxyHost")).toString().trimmed();
        const int port = settings.value(QStringLiteral("proxyPort")).toInt();
        if (host.isEmpty() || port < 1 || port > 65535)
            return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
                QStringLiteral("signing.proxy"), 0, QStringLiteral("代理主机或端口无效。"), {}});
        manager_.setProxy(QNetworkProxy(proxy == QStringLiteral("http") ? QNetworkProxy::HttpProxy : QNetworkProxy::Socks5Proxy,
                                       host, static_cast<quint16>(port)));
    } else if (proxy == QStringLiteral("system")) manager_.setProxy(QNetworkProxy::DefaultProxy);
    else return tl::unexpected(domain::AppError{domain::ErrorCategory::Validation,
        QStringLiteral("signing.proxy"), 0, QStringLiteral("代理类型无效。"), {}});
    return {};
}
void SigningHttpClient::send(const QByteArray &method, const QUrl &url, QByteArray body, QByteArray token,
                             const QByteArray &csrf, const QByteArray &idempotencyKey, const int expectedStatus,
                             std::function<void(SigningHttpResult)> completed)
{
    SigningHttpResult rejected;
    if (active_) rejected.error = QStringLiteral("已有请求正在进行。");
    else if (url.scheme() != QStringLiteral("https") || url.host() != base_.host() || url.port(443) != base_.port(443) ||
             !url.userInfo().isEmpty() || url.hasFragment() || body.size() > 1048576)
        rejected.error = QStringLiteral("请求目标或大小无效；禁止向其他 origin 发送凭据。");
    else if (settings_.value(QStringLiteral("mtlsRequired")).toBool() && !hasIdentity()) {
        rejected.error = QStringLiteral("此端点要求 HTTP 通信 mTLS 客户端证书。请先在连接配置中加载通信证书及其私钥；它与业务签发证书无关。");
        rejected.problemCode = QStringLiteral("mtls_required");
    }
    if (!rejected.error.isEmpty()) {
        if (!body.isEmpty()) OPENSSL_cleanse(body.data(), static_cast<size_t>(body.size()));
        if (!token.isEmpty()) OPENSSL_cleanse(token.data(), static_cast<size_t>(token.size()));
        completed(std::move(rejected)); return;
    }
    QNetworkRequest request(url);
    request.setSslConfiguration(tls_);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    if (!owner_) {
        request.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
        request.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
    }
    request.setRawHeader("Accept", "application/json, application/pkix-cert, application/pkix-crl");
    request.setRawHeader("User-Agent", "APCM-Independent-Signing/1");
    const QByteArray requestId = QUuid::createUuid().toByteArray(QUuid::WithoutBraces);
    request.setRawHeader("X-Request-ID", requestId);
    if (!token.isEmpty() && !owner_) request.setRawHeader("Authorization", "Bearer " + token);
    if (owner_ && !csrf.isEmpty() && method != "GET") request.setRawHeader("X-CSRF-Token", csrf);
    if (owner_) {
        QUrl origin = base_; origin.setPath({}); origin.setQuery(QString{});
        request.setRawHeader("Origin", origin.toEncoded());
    }
    if (!idempotencyKey.isEmpty()) request.setRawHeader("Idempotency-Key", idempotencyKey);
    if (method != "GET") request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    QNetworkReply *reply = manager_.sendCustomRequest(request, method, body);
    if (!body.isEmpty()) OPENSSL_cleanse(body.data(), static_cast<size_t>(body.size()));
    if (!token.isEmpty()) OPENSSL_cleanse(token.data(), static_cast<size_t>(token.size()));
    active_ = reply;
    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, this, [reply] { reply->setProperty("apcmTimedOut", true); reply->abort(); });
    timer->start(qBound(5, settings_.value(QStringLiteral("timeoutSeconds"), 30).toInt(), 120) * 1000);
    reply->setReadBufferSize(2 * 1024 * 1024 + 1);
    auto bytes = std::make_shared<QByteArray>();
    connect(reply, &QIODevice::readyRead, this, [reply, bytes] {
        bytes->append(reply->readAll());
        if (bytes->size() > 2 * 1024 * 1024) { reply->setProperty("apcmTooLarge", true); reply->abort(); }
    });
    connect(reply, &QNetworkReply::sslErrors, this, [reply](const QList<QSslError> &errors) {
        QStringList labels;
        for (const auto &error : errors) labels.append(error.errorString());
        reply->setProperty("apcmTlsErrors", labels.join(QStringLiteral("；")));
        // Deliberately never call ignoreSslErrors().
    });
    const bool suppressProblemDetail = owner_ && method == "POST" &&
        (url.path().endsWith(QStringLiteral("/auth/login")) || url.path().endsWith(QStringLiteral("/signing-instances")));
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, timer, bytes, expectedStatus, requestId, suppressProblemDetail, completed = std::move(completed)]() mutable {
        timer->stop(); active_ = nullptr;
        if (reply->isOpen()) bytes->append(reply->readAll());
        SigningHttpResult result;
        result.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        result.contentType = reply->rawHeader("Content-Type");
        result.requestId = QString::fromLatin1(reply->rawHeader("X-Request-ID").left(128));
        if (!QRegularExpression(QStringLiteral("^[A-Za-z0-9._:-]{1,128}$")).match(result.requestId).hasMatch() || result.requestId.startsWith(QStringLiteral("ist_"))) result.requestId = QString::fromLatin1(requestId);
        result.replayed = reply->rawHeader("Idempotency-Replayed").trimmed().toLower() == "true";
        const QByteArray retry = reply->rawHeader("Retry-After").trimmed();
        if (!retry.isEmpty()) {
            bool ok = false; const qint64 seconds = retry.toLongLong(&ok);
            if (ok && seconds >= 0) result.retryAt = QDateTime::currentDateTimeUtc().addSecs(seconds);
            else result.retryAt = QDateTime::fromString(QString::fromLatin1(retry), Qt::RFC2822Date).toUTC();
        }
        if (result.status == 429 && !result.retryAt.isValid()) result.retryAt = QDateTime::currentDateTimeUtc().addSecs(60);
        const auto lower = bytes->left(32768).toLower();
        const bool missingCertificate = result.status == 496 ||
            ((result.status == 400 || result.status == 403) && (lower.contains("no required ssl certificate") || lower.contains("client certificate required") || lower.contains("ssl certificate required") || lower.contains("client certificate missing") || lower.contains("a required certificate was not provided")));
        if (reply->property("apcmTooLarge").toBool() || bytes->size() > 2 * 1024 * 1024) {
            result.error = QStringLiteral("响应超过客户端 2 MiB 上限；签发结果可能未知，请保留原任务恢复。");
            result.problemCode = QStringLiteral("response_too_large");
        } else if (missingCertificate) {
            result.problemCode = QStringLiteral("mtls_required");
            result.error = QStringLiteral("端点的反向代理要求 HTTP 通信 mTLS 客户端证书。请在连接配置中提供通信证书和私钥，再恢复原任务；不要使用业务 CA 或待签发的叶证书代替。");
        } else if (result.status == 495) {
            result.problemCode = QStringLiteral("mtls_rejected");
            result.error = QStringLiteral("端点拒绝了通信 mTLS 证书；请检查证书链、有效期和 nginx 的客户端 CA 配置。");
        } else if (result.status >= 300 && result.status < 400) {
            result.error = QStringLiteral("端点返回重定向，已阻止跳转和凭据转发。请核对完整端点。");
            result.problemCode = QStringLiteral("redirect_blocked");
        } else if (reply->error() != QNetworkReply::NoError && result.status == 0) {
            result.problemCode = QStringLiteral("transport_failed");
            if (reply->property("apcmTimedOut").toBool()) {
                result.error = QStringLiteral("请求超时；写操作的结果可能未知，请使用原任务恢复。");
                if (!hasIdentity()) result.error += QStringLiteral("若此入口要求 HTTP 通信 mTLS，请先加载专用通信客户端证书和私钥；当前未加载通信身份。");
            }
            else if (reply->error() == QNetworkReply::SslHandshakeFailedError) {
                result.error = QStringLiteral("TLS 握手失败。请检查 HTTPS 服务器信任根和主机名；此端点也可能要求专用的通信 mTLS 客户端证书。%1")
                    .arg(hasIdentity() ? QStringLiteral("已加载通信证书，请检查其授权、证书链和有效期。") : QStringLiteral("尚未加载通信证书，请先在连接配置中提供。"));
                const QString tlsErrors = reply->property("apcmTlsErrors").toString();
                if (!tlsErrors.isEmpty()) result.error += QStringLiteral("\n服务器 TLS 校验：") + tlsErrors;
            } else if (reply->error() == QNetworkReply::RemoteHostClosedError && !hasIdentity()) {
                result.error = QStringLiteral("远端关闭了连接，写操作结果可能未知。此入口也可能要求 HTTP 通信 mTLS 客户端证书；当前尚未加载，请检查通信证书配置后恢复原任务。");
            } else result.error = QStringLiteral("网络连接失败，请检查地址、代理及网络状态。写操作结果可能未知。");
        } else if (result.status != expectedStatus) {
            result.error = safeProblem(result.status, suppressProblemDetail ? QByteArray{} : *bytes, result.contentType);
            if (owner_ && result.status == 401) result.error = QStringLiteral("HTTP 401：所有者会话已失效、账户不可用，或用户名/密码不正确。请重新登录管理账户。");
            if (owner_ && result.status == 403) result.error = QStringLiteral("HTTP 403：所有者权限、CSRF 或管理端 Origin 校验未通过。请核对管理地址并重新登录。");
            if (result.contentType.toLower().contains("application/problem+json")) {
                const QString code = QJsonDocument::fromJson(*bytes).object().value(QStringLiteral("code")).toString();
                if (!code.startsWith(QStringLiteral("ist_")) && QRegularExpression(QStringLiteral("^[a-z0-9_]{1,80}$")).match(code).hasMatch()) result.problemCode = code;
            }
        } else {
            result.ok = true; result.body = *bytes;
        }
        if (!bytes->isEmpty()) OPENSSL_cleanse(bytes->data(), static_cast<size_t>(bytes->size()));
        reply->deleteLater();
        completed(std::move(result));
    });
}
} // namespace certmgr::services
