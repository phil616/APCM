#include "PkiConsoleClient.h"

#include "../platform/windows/credentials/WindowsCredentialStore.h"

#include <QCryptographicHash>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkCookieJar>
#include <QNetworkCookie>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QTcpSocket>
#include <QUrlQuery>
#include <QUuid>
#include <sodium.h>

#include <utility>

namespace certmgr::services {
namespace {

constexpr auto credentialTarget = "DreamReflexOpenSource/APCM/PKI-Console/OAuth";

class SessionCookieJar final : public QNetworkCookieJar {
public:
    using QNetworkCookieJar::QNetworkCookieJar;
    void clear() { setAllCookies({}); }
};

SessionCookieJar *sessionCookies(QNetworkAccessManager &network)
{
    return static_cast<SessionCookieJar *>(network.cookieJar());
}

QJsonObject parseObject(const QByteArray &body)
{
    QJsonParseError error{};
    const QJsonDocument document = QJsonDocument::fromJson(body, &error);
    return error.error == QJsonParseError::NoError && document.isObject()
        ? document.object() : QJsonObject{};
}

bool containsString(const QJsonArray &values, const QString &expected)
{
    for (const QJsonValue &value : values) {
        if (value.toString() == expected) return true;
    }
    return false;
}

QString firstHeaderParameter(const QByteArray &header, const QString &name)
{
    const QString text = QString::fromLatin1(header);
    const QRegularExpression quoted(QStringLiteral("(?:^|[,\\s])%1\\s*=\\s*\"([^\"]+)\"")
                                        .arg(QRegularExpression::escape(name)),
                                    QRegularExpression::CaseInsensitiveOption);
    if (const auto match = quoted.match(text); match.hasMatch()) return match.captured(1);
    const QRegularExpression plain(QStringLiteral("(?:^|[,\\s])%1\\s*=\\s*([^,\\s]+)")
                                       .arg(QRegularExpression::escape(name)),
                                   QRegularExpression::CaseInsensitiveOption);
    const auto match = plain.match(text);
    return match.hasMatch() ? match.captured(1) : QString{};
}

} // namespace

PkiConsoleClient::PkiConsoleClient(QObject *parent) : QObject(parent)
{
    // QNetworkAccessManager takes ownership and assigns the jar's parent.
    network_.setCookieJar(new SessionCookieJar);
    connect(&callbackServer_, &QTcpServer::newConnection,
            this, &PkiConsoleClient::acceptOAuthConnection);
    callbackTimeout_.setSingleShot(true);
    connect(&callbackTimeout_, &QTimer::timeout, this, [this] {
        callbackServer_.close();
        pkceVerifier_.fill('\0');
        oauthState_.fill('\0');
        pkceVerifier_.clear();
        oauthState_.clear();
        setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
        setError(QStringLiteral("浏览器授权等待超时，请重新开始。"));
    });
    restoreOAuthCredentials();
}

PkiConsoleClient::~PkiConsoleClient()
{
    callbackServer_.close();
    callbackTimeout_.stop();
    pkceVerifier_.fill('\0');
    oauthState_.fill('\0');
    csrfToken_.fill(QChar('\0'));
    accessToken_.fill(QChar('\0'));
    refreshToken_.fill(QChar('\0'));
}

void PkiConsoleClient::setBusy(const bool value, const QString &phase)
{
    busy_ = value;
    if (!phase.isEmpty()) phase_ = phase;
    emit stateChanged();
}

void PkiConsoleClient::setStatus(const QString &message)
{
    statusMessage_ = message;
    errorMessage_.clear();
    emit stateChanged();
}

void PkiConsoleClient::setError(const QString &message, const QString &details)
{
    errorMessage_ = details.trimmed().isEmpty() ? message
        : QStringLiteral("%1\n%2").arg(message, details);
    statusMessage_.clear();
    emit stateChanged();
}

void PkiConsoleClient::clearError()
{
    errorMessage_.clear();
    emit stateChanged();
}

void PkiConsoleClient::browserLaunchFailed()
{
    callbackServer_.close();
    callbackTimeout_.stop();
    pkceVerifier_.fill('\0');
    oauthState_.fill('\0');
    pkceVerifier_.clear();
    oauthState_.clear();
    setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
    setError(QStringLiteral("无法打开系统默认浏览器。"));
}

void PkiConsoleClient::clearApplicationSession()
{
    sessionCookies(network_)->clear();
    csrfToken_.fill(QChar('\0'));
    csrfToken_.clear();
    authenticated_ = false;
    userName_.clear();
    userRole_.clear();
    sessionExpiresAt_ = {};
    authorities_.clear();
    profiles_.clear();
    inventory_.clear();
    phase_ = oauthAuthorized_ ? QStringLiteral("需要 PKI-Console 本地账户登录")
                              : QStringLiteral("需要 Cloudflare Access 授权");
    emit stateChanged();
    emit dataChanged();
}

void PkiConsoleClient::clearOAuthCredentials()
{
    static_cast<void>(platform::windows::WindowsCredentialStore::remove(
        QString::fromLatin1(credentialTarget)));
    accessToken_.fill(QChar('\0'));
    refreshToken_.fill(QChar('\0'));
    accessToken_.clear();
    refreshToken_.clear();
    clientId_.clear();
    accessTokenExpiresAt_ = {};
    tokenEndpoint_ = {};
    revocationEndpoint_ = {};
    authorizationIssuer_ = {};
    oauthAuthorized_ = false;
    clearApplicationSession();
}

void PkiConsoleClient::restoreOAuthCredentials()
{
    auto stored = platform::windows::WindowsCredentialStore::read(
        QString::fromLatin1(credentialTarget));
    if (!stored) {
        setError(stored.error().message, stored.error().details);
        return;
    }
    if (stored->isEmpty()) return;
    const QJsonObject value = parseObject(*stored);
    stored->fill('\0');
    if (value.value(QStringLiteral("origin")).toString() != origin_.toString()) return;
    accessToken_ = value.value(QStringLiteral("access_token")).toString();
    refreshToken_ = value.value(QStringLiteral("refresh_token")).toString();
    clientId_ = value.value(QStringLiteral("client_id")).toString();
    tokenEndpoint_ = QUrl(value.value(QStringLiteral("token_endpoint")).toString());
    revocationEndpoint_ = QUrl(value.value(QStringLiteral("revocation_endpoint")).toString());
    authorizationIssuer_ = QUrl(value.value(QStringLiteral("issuer")).toString());
    accessTokenExpiresAt_ = QDateTime::fromString(
        value.value(QStringLiteral("expires_at")).toString(), Qt::ISODate);
    oauthAuthorized_ = accessTokenUsable();
    phase_ = oauthAuthorized_ ? QStringLiteral("需要 PKI-Console 本地账户登录")
                              : QStringLiteral("Cloudflare Access 授权需要刷新");
    emit stateChanged();
}

bool PkiConsoleClient::persistOAuthCredentials()
{
    const QJsonObject value{
        {QStringLiteral("origin"), origin_.toString()},
        {QStringLiteral("access_token"), accessToken_},
        {QStringLiteral("refresh_token"), refreshToken_},
        {QStringLiteral("client_id"), clientId_},
        {QStringLiteral("token_endpoint"), tokenEndpoint_.toString()},
        {QStringLiteral("revocation_endpoint"), revocationEndpoint_.toString()},
        {QStringLiteral("issuer"), authorizationIssuer_.toString()},
        {QStringLiteral("expires_at"), accessTokenExpiresAt_.toString(Qt::ISODate)}
    };
    QByteArray serialized = QJsonDocument(value).toJson(QJsonDocument::Compact);
    const auto result = platform::windows::WindowsCredentialStore::write(
        QString::fromLatin1(credentialTarget), serialized);
    serialized.fill('\0');
    if (!result) {
        setError(result.error().message, result.error().details);
        return false;
    }
    return true;
}

bool PkiConsoleClient::accessTokenUsable() const
{
    return !accessToken_.isEmpty() && accessTokenExpiresAt_.isValid() &&
           accessTokenExpiresAt_ > QDateTime::currentDateTimeUtc().addSecs(60);
}

void PkiConsoleClient::send(QNetworkRequest request, const QByteArray &method,
                            const QByteArray &body, ReplyHandler handler)
{
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    QNetworkReply *reply = nullptr;
    if (method == QByteArrayLiteral("GET")) reply = network_.get(request);
    else if (method == QByteArrayLiteral("POST")) reply = network_.post(request, body);
    else reply = network_.sendCustomRequest(request, method, body);
    connect(reply, &QNetworkReply::finished, this,
            [reply, handler = std::move(handler)] { handler(reply); });
}

void PkiConsoleClient::beginAuthorization()
{
    if (busy_) return;
    errorMessage_.clear();
    if (!refreshToken_.isEmpty() && isTrustedHttpsUrl(tokenEndpoint_)) {
        setBusy(true, QStringLiteral("正在刷新 Cloudflare Access 授权"));
        refreshAccessToken([this](const bool ok) {
            setBusy(false, ok ? QStringLiteral("需要 PKI-Console 本地账户登录")
                              : QStringLiteral("需要 Cloudflare Access 授权"));
            if (!ok) startDiscovery();
        });
        return;
    }
    startDiscovery();
}

void PkiConsoleClient::startDiscovery()
{
    setBusy(true, QStringLiteral("正在发现 Cloudflare OAuth 服务"));
    QNetworkRequest request(apiBase_.resolved(QUrl(QStringLiteral("version"))));
    request.setRawHeader("Accept", "application/json");
    send(request, QByteArrayLiteral("GET"), {}, [this](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray challenge = reply->rawHeader("WWW-Authenticate");
        const QUrl metadata(firstHeaderParameter(challenge, QStringLiteral("resource_metadata")));
        const QUrl redirect(reply->rawHeader("Location"));
        reply->deleteLater();
        if (status != 401 || !isTrustedHttpsUrl(metadata)) {
            setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
            setError(QStringLiteral("无法发现 Cloudflare Managed OAuth。"),
                !redirect.isEmpty()
                    ? QStringLiteral("服务返回了登录重定向；请确认已启用 Managed OAuth、动态客户端注册和 loopback client。")
                    : QStringLiteral("未授权响应中缺少可信的 resource_metadata。"));
            return;
        }
        fetchProtectedResourceMetadata(metadata);
    });
}

void PkiConsoleClient::fetchProtectedResourceMetadata(const QUrl &metadataUrl)
{
    QNetworkRequest request(metadataUrl);
    request.setRawHeader("Accept", "application/json");
    send(request, QByteArrayLiteral("GET"), {}, [this](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        const QJsonObject object = parseObject(body);
        reply->deleteLater();
        const QUrl resource(object.value(QStringLiteral("resource")).toString());
        const QJsonArray servers = object.value(QStringLiteral("authorization_servers")).toArray();
        const QUrl issuer(servers.isEmpty() ? QString{} : servers.first().toString());
        if (status != 200 || !sameOrigin(resource, origin_) || !isTrustedHttpsUrl(issuer)) {
            setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
            setError(QStringLiteral("Cloudflare protected-resource 元数据校验失败。"));
            return;
        }
        authorizationIssuer_ = issuer;
        fetchAuthorizationServerMetadata(issuer);
    });
}

void PkiConsoleClient::fetchAuthorizationServerMetadata(const QUrl &issuerUrl)
{
    const QUrl metadata = issuerUrl.resolved(QUrl(QStringLiteral("/.well-known/oauth-authorization-server")));
    QNetworkRequest request(metadata);
    request.setRawHeader("Accept", "application/json");
    send(request, QByteArrayLiteral("GET"), {}, [this, issuerUrl](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QJsonObject object = parseObject(reply->readAll());
        reply->deleteLater();
        authorizationEndpoint_ = QUrl(object.value(QStringLiteral("authorization_endpoint")).toString());
        tokenEndpoint_ = QUrl(object.value(QStringLiteral("token_endpoint")).toString());
        registrationEndpoint_ = QUrl(object.value(QStringLiteral("registration_endpoint")).toString());
        revocationEndpoint_ = QUrl(object.value(QStringLiteral("revocation_endpoint")).toString());
        const QUrl declaredIssuer(object.value(QStringLiteral("issuer")).toString());
        const bool capabilities = containsString(object.value(QStringLiteral("grant_types_supported")).toArray(),
                                                  QStringLiteral("authorization_code")) &&
            containsString(object.value(QStringLiteral("token_endpoint_auth_methods_supported")).toArray(),
                           QStringLiteral("none")) &&
            containsString(object.value(QStringLiteral("code_challenge_methods_supported")).toArray(),
                           QStringLiteral("S256"));
        if (status != 200 || declaredIssuer != issuerUrl || !capabilities ||
            !isTrustedHttpsUrl(authorizationEndpoint_) || !isTrustedHttpsUrl(tokenEndpoint_) ||
            !isTrustedHttpsUrl(registrationEndpoint_)) {
            setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
            setError(QStringLiteral("Cloudflare OAuth 服务不满足原生客户端安全要求。"),
                     QStringLiteral("需要 authorization_code、public client、PKCE S256 和动态注册。"));
            return;
        }
        registerClient();
    });
}

void PkiConsoleClient::registerClient()
{
    callbackServer_.close();
    if (!callbackServer_.listen(QHostAddress::LocalHost, 0)) {
        setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
        setError(QStringLiteral("无法在 127.0.0.1 启动 OAuth 回调监听器。"),
                 callbackServer_.errorString());
        return;
    }
    redirectUri_ = QUrl(QStringLiteral("http://127.0.0.1:%1/oauth/callback")
                            .arg(callbackServer_.serverPort()));
    const QJsonObject registration{
        {QStringLiteral("client_name"), QStringLiteral("APCM Certificate Manager")},
        {QStringLiteral("redirect_uris"), QJsonArray{redirectUri_.toString()}},
        {QStringLiteral("grant_types"), QJsonArray{QStringLiteral("authorization_code"),
                                                    QStringLiteral("refresh_token")}},
        {QStringLiteral("response_types"), QJsonArray{QStringLiteral("code")}},
        {QStringLiteral("token_endpoint_auth_method"), QStringLiteral("none")},
        {QStringLiteral("resource"), origin_.toString()}
    };
    QNetworkRequest request(registrationEndpoint_);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setRawHeader("Accept", "application/json");
    send(request, QByteArrayLiteral("POST"), QJsonDocument(registration).toJson(QJsonDocument::Compact),
         [this](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        const QJsonObject object = parseObject(body);
        if (status < 200 || status >= 300 || object.value(QStringLiteral("client_id")).toString().isEmpty()) {
            const QString problem = problemMessage(reply, body);
            reply->deleteLater();
            callbackServer_.close();
            setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
            setError(QStringLiteral("Cloudflare OAuth 动态客户端注册失败。"), problem);
            return;
        }
        clientId_ = object.value(QStringLiteral("client_id")).toString();
        reply->deleteLater();
        openAuthorizationPage();
    });
}

void PkiConsoleClient::openAuthorizationPage()
{
    do {
        pkceVerifier_ = randomBase64Url(48);
    } while (pkceVerifier_.isEmpty());
    QByteArray challenge = QCryptographicHash::hash(pkceVerifier_, QCryptographicHash::Sha256)
                               .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    while (challenge.isEmpty() || !challenge.front() ||
           !QChar::fromLatin1(challenge.front()).isLetterOrNumber()) {
        pkceVerifier_.fill('\0');
        pkceVerifier_ = randomBase64Url(48);
        challenge = QCryptographicHash::hash(pkceVerifier_, QCryptographicHash::Sha256)
                        .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    }
    oauthState_ = randomBase64Url(24);
    QUrl authorizationUrl = authorizationEndpoint_;
    QUrlQuery query;
    query.addQueryItem(QStringLiteral("response_type"), QStringLiteral("code"));
    query.addQueryItem(QStringLiteral("client_id"), clientId_);
    query.addQueryItem(QStringLiteral("redirect_uri"), redirectUri_.toString());
    query.addQueryItem(QStringLiteral("code_challenge"), QString::fromLatin1(challenge));
    query.addQueryItem(QStringLiteral("code_challenge_method"), QStringLiteral("S256"));
    query.addQueryItem(QStringLiteral("state"), QString::fromLatin1(oauthState_));
    query.addQueryItem(QStringLiteral("resource"), origin_.toString());
    authorizationUrl.setQuery(query);
    emit authorizationUrlReady(authorizationUrl);
    callbackTimeout_.start(300000);
    setBusy(true, QStringLiteral("等待浏览器完成 Cloudflare Access 授权"));
    setStatus(QStringLiteral("已在系统默认浏览器中打开授权页面。"));
}

void PkiConsoleClient::acceptOAuthConnection()
{
    QTcpSocket *socket = callbackServer_.nextPendingConnection();
    if (!socket) return;
    callbackServer_.pauseAccepting();
    connect(socket, &QTcpSocket::readyRead, this, [this, socket] {
        QByteArray request = socket->property("oauthRequest").toByteArray();
        request += socket->readAll();
        if (!request.contains("\r\n\r\n") && request.size() <= 8192) {
            socket->setProperty("oauthRequest", request);
            return;
        }
        const qsizetype firstLineEnd = request.indexOf("\r\n");
        const QList<QByteArray> parts = request.left(firstLineEnd).split(' ');
        const QUrl callback(parts.size() >= 2 ? QString::fromLatin1(parts.at(1)) : QString{});
        QUrlQuery query(callback);
        const QByteArray returnedState = query.queryItemValue(QStringLiteral("state")).toLatin1();
        const QString code = query.queryItemValue(QStringLiteral("code"));
        const QString oauthError = query.queryItemValue(QStringLiteral("error"));
        const bool valid = callback.path() == QStringLiteral("/oauth/callback") &&
                           oauthError.isEmpty() && !code.isEmpty() &&
                           sameState(returnedState, oauthState_);
        const QByteArray page = valid
            ? QByteArrayLiteral("<!doctype html><meta charset=utf-8><title>APCM</title><h2>授权已完成</h2><p>可以关闭此页面并返回 APCM。</p>")
            : QByteArrayLiteral("<!doctype html><meta charset=utf-8><title>APCM</title><h2>授权失败</h2><p>请返回 APCM 后重试。</p>");
        const QByteArray response = QByteArrayLiteral("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: ") +
                                    QByteArray::number(page.size()) + QByteArrayLiteral("\r\n\r\n") + page;
        socket->write(response);
        socket->disconnectFromHost();
        callbackServer_.close();
        callbackTimeout_.stop();
        oauthState_.fill('\0');
        oauthState_.clear();
        if (!valid) {
            pkceVerifier_.fill('\0');
            pkceVerifier_.clear();
            setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
            setError(QStringLiteral("Cloudflare OAuth 回调无效或 state 校验失败。"), oauthError);
            return;
        }
        exchangeAuthorizationCode(code);
    });
}

void PkiConsoleClient::exchangeAuthorizationCode(const QString &code)
{
    phase_ = QStringLiteral("正在交换 Cloudflare Access 令牌");
    emit stateChanged();
    QUrlQuery form;
    form.addQueryItem(QStringLiteral("grant_type"), QStringLiteral("authorization_code"));
    form.addQueryItem(QStringLiteral("client_id"), clientId_);
    form.addQueryItem(QStringLiteral("code"), code);
    form.addQueryItem(QStringLiteral("redirect_uri"), redirectUri_.toString());
    form.addQueryItem(QStringLiteral("code_verifier"), QString::fromLatin1(pkceVerifier_));
    QByteArray body = form.query(QUrl::FullyEncoded).toUtf8();
    QNetworkRequest request(tokenEndpoint_);
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QStringLiteral("application/x-www-form-urlencoded"));
    request.setRawHeader("Accept", "application/json");
    send(request, QByteArrayLiteral("POST"), body, [this](QNetworkReply *reply) {
        pkceVerifier_.fill('\0');
        pkceVerifier_.clear();
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray responseBody = reply->readAll();
        const QJsonObject object = parseObject(responseBody);
        if (status < 200 || status >= 300 ||
            object.value(QStringLiteral("access_token")).toString().isEmpty() ||
            object.value(QStringLiteral("token_type")).toString().compare(
                QStringLiteral("Bearer"), Qt::CaseInsensitive) != 0) {
            const QString problem = problemMessage(reply, responseBody);
            reply->deleteLater();
            setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
            setError(QStringLiteral("无法取得 Cloudflare Access 令牌。"), problem);
            return;
        }
        accessToken_ = object.value(QStringLiteral("access_token")).toString();
        if (!object.value(QStringLiteral("refresh_token")).toString().isEmpty())
            refreshToken_ = object.value(QStringLiteral("refresh_token")).toString();
        const int expiresIn = object.value(QStringLiteral("expires_in")).toInt(300);
        accessTokenExpiresAt_ = QDateTime::currentDateTimeUtc().addSecs(expiresIn);
        oauthAuthorized_ = true;
        reply->deleteLater();
        if (!persistOAuthCredentials()) {
            clearOAuthCredentials();
            setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
            return;
        }
        setBusy(false, QStringLiteral("需要 PKI-Console 本地账户登录"));
        setStatus(QStringLiteral("Cloudflare Access 授权成功。请登录 PKI-Console 本地账户。"));
    });
    body.fill('\0');
}

void PkiConsoleClient::refreshAccessToken(std::function<void(bool)> completion)
{
    if (refreshToken_.isEmpty() || clientId_.isEmpty() || !isTrustedHttpsUrl(tokenEndpoint_)) {
        completion(false);
        return;
    }
    QUrlQuery form;
    form.addQueryItem(QStringLiteral("grant_type"), QStringLiteral("refresh_token"));
    form.addQueryItem(QStringLiteral("client_id"), clientId_);
    form.addQueryItem(QStringLiteral("refresh_token"), refreshToken_);
    QByteArray body = form.query(QUrl::FullyEncoded).toUtf8();
    QNetworkRequest request(tokenEndpoint_);
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QStringLiteral("application/x-www-form-urlencoded"));
    request.setRawHeader("Accept", "application/json");
    send(request, QByteArrayLiteral("POST"), body,
         [this, completion = std::move(completion)](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QJsonObject object = parseObject(reply->readAll());
        reply->deleteLater();
        if (status < 200 || status >= 300 ||
            object.value(QStringLiteral("access_token")).toString().isEmpty() ||
            object.value(QStringLiteral("token_type")).toString().compare(
                QStringLiteral("Bearer"), Qt::CaseInsensitive) != 0) {
            clearOAuthCredentials();
            completion(false);
            return;
        }
        accessToken_ = object.value(QStringLiteral("access_token")).toString();
        const QString replacement = object.value(QStringLiteral("refresh_token")).toString();
        if (!replacement.isEmpty()) refreshToken_ = replacement;
        accessTokenExpiresAt_ = QDateTime::currentDateTimeUtc().addSecs(
            object.value(QStringLiteral("expires_in")).toInt(300));
        oauthAuthorized_ = true;
        const bool persisted = persistOAuthCredentials();
        if (!persisted) clearOAuthCredentials();
        emit stateChanged();
        completion(persisted);
    });
    body.fill('\0');
}

void PkiConsoleClient::login(const QString &loginName, const QString &password,
                             const QString &totp)
{
    if (busy_) return;
    if (loginName.trimmed().isEmpty() || password.isEmpty() ||
        (!totp.isEmpty() && !QRegularExpression(QStringLiteral("^[0-9]{6}$")).match(totp).hasMatch())) {
        setError(QStringLiteral("请输入 PKI-Console 用户名和密码；超级管理员 TOTP 必须为六位数字。"));
        return;
    }
    const auto performLogin = [this, loginName, password, totp] {
        setBusy(true, QStringLiteral("正在登录 PKI-Console"));
        QJsonObject payload{{QStringLiteral("login"), loginName.trimmed()},
                            {QStringLiteral("password"), password}};
        if (!totp.isEmpty()) payload.insert(QStringLiteral("totp"), totp);
        QByteArray body = QJsonDocument(payload).toJson(QJsonDocument::Compact);
        QNetworkRequest request(apiBase_.resolved(QUrl(QStringLiteral("auth/login"))));
        request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
        request.setRawHeader("Accept", "application/json, application/problem+json");
        request.setRawHeader("Authorization", QByteArrayLiteral("Bearer ") + accessToken_.toUtf8());
        send(request, QByteArrayLiteral("POST"), body, [this](QNetworkReply *reply) {
            const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const QByteArray responseBody = reply->readAll();
            const QJsonObject object = parseObject(responseBody);
            if (status != 200 || object.value(QStringLiteral("csrf_token")).toString().isEmpty()) {
                const QString problem = problemMessage(reply, responseBody);
                reply->deleteLater();
                clearApplicationSession();
                setBusy(false, QStringLiteral("需要 PKI-Console 本地账户登录"));
                setError(QStringLiteral("PKI-Console 登录失败。"), problem);
                return;
            }
            csrfToken_ = object.value(QStringLiteral("csrf_token")).toString();
            const QJsonObject user = object.value(QStringLiteral("user")).toObject();
            userName_ = user.value(QStringLiteral("username")).toString();
            userRole_ = user.value(QStringLiteral("role")).toString();
            sessionExpiresAt_ = QDateTime::fromString(
                object.value(QStringLiteral("expires_at")).toString(), Qt::ISODate);
            authenticated_ = true;
            reply->deleteLater();
            setBusy(false, QStringLiteral("已连接私有 PKI"));
            setStatus(QStringLiteral("已作为 %1 登录 PKI-Console。").arg(userName_));
            refreshRemoteData();
        });
        body.fill('\0');
    };
    if (accessTokenUsable()) {
        performLogin();
        return;
    }
    setBusy(true, QStringLiteral("正在刷新 Cloudflare Access 授权"));
    refreshAccessToken([this, performLogin](const bool ok) {
        setBusy(false);
        if (ok) performLogin();
        else setError(QStringLiteral("Cloudflare Access 授权已失效，请重新在浏览器中授权。"));
    });
}

void PkiConsoleClient::sendApi(const QString &path, const QByteArray &method,
                               const QByteArray &body, const bool needsCsrf,
                               const bool idempotent, ReplyHandler handler,
                               const bool retried, QByteArray idempotencyKey)
{
    if (idempotent && idempotencyKey.isEmpty())
        idempotencyKey = QUuid::createUuid().toString(QUuid::WithoutBraces).toLatin1();
    if (!accessTokenUsable()) {
        refreshAccessToken([this, path, method, body, needsCsrf, idempotent, handler, retried,
                            idempotencyKey](const bool ok) {
            if (!ok) {
                setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
                setError(QStringLiteral("Cloudflare Access 授权已失效，请重新授权。"));
                return;
            }
            sendApi(path, method, body, needsCsrf, idempotent, handler, retried, idempotencyKey);
        });
        return;
    }
    QNetworkRequest request(apiBase_.resolved(QUrl(path)));
    request.setRawHeader("Accept", "application/json, application/problem+json, application/x-pem-file");
    request.setRawHeader("Authorization", QByteArrayLiteral("Bearer ") + accessToken_.toUtf8());
    if (!body.isEmpty()) request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    if (needsCsrf) request.setRawHeader("X-CSRF-Token", csrfToken_.toUtf8());
    if (idempotent) request.setRawHeader("Idempotency-Key", idempotencyKey);
    send(request, method, body,
         [this, path, method, body, needsCsrf, idempotent, handler, retried,
          idempotencyKey](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (status == 401 && !retried && !refreshToken_.isEmpty() &&
            !reply->rawHeader("WWW-Authenticate").isEmpty()) {
            reply->deleteLater();
            refreshAccessToken([this, path, method, body, needsCsrf, idempotent, handler,
                                idempotencyKey](const bool ok) {
                if (!ok) {
                    setBusy(false, QStringLiteral("需要 Cloudflare Access 授权"));
                    setError(QStringLiteral("Cloudflare Access 授权已失效，请重新授权。"));
                    return;
                }
                sendApi(path, method, body, needsCsrf, idempotent, handler, true, idempotencyKey);
            });
            return;
        }
        if (status == 401 && reply->rawHeader("WWW-Authenticate").isEmpty() && authenticated_)
            clearApplicationSession();
        handler(reply);
    });
}

void PkiConsoleClient::logout(const bool forgetDevice)
{
    if (busy_) return;
    if (!authenticated_) {
        if (forgetDevice) clearOAuthCredentials();
        return;
    }
    setBusy(true, QStringLiteral("正在退出 PKI-Console"));
    sendApi(QStringLiteral("auth/logout"), QByteArrayLiteral("POST"), {}, true, false,
            [this, forgetDevice](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        const QString problem = status == 204 ? QString{} : problemMessage(reply, body);
        reply->deleteLater();
        clearApplicationSession();
        if (forgetDevice) clearOAuthCredentials();
        setBusy(false, forgetDevice ? QStringLiteral("需要 Cloudflare Access 授权")
                                    : QStringLiteral("需要 PKI-Console 本地账户登录"));
        if (status == 204) setStatus(forgetDevice ? QStringLiteral("已从此设备完全退出私有 PKI。")
                                                  : QStringLiteral("已退出 PKI-Console 会话。"));
        else setError(QStringLiteral("远程退出未确认，本地会话已清除。"), problem);
    });
}

void PkiConsoleClient::refreshRemoteData(const QString &status)
{
    if (busy_ || !authenticated_) return;
    setBusy(true, QStringLiteral("正在同步私有 PKI 数据"));
    loadAuthorities([this, status](const bool ok) {
        if (!ok) { setBusy(false, QStringLiteral("私有 PKI 同步失败")); return; }
        loadInventory(status, [this](const bool inventoryOk) {
            setBusy(false, inventoryOk ? QStringLiteral("已连接私有 PKI")
                                       : QStringLiteral("私有 PKI 同步失败"));
            if (inventoryOk) setStatus(QStringLiteral("私有 PKI 证书清单已更新。"));
        });
    });
}

void PkiConsoleClient::loadAuthorities(std::function<void(bool)> completion)
{
    sendApi(QStringLiteral("cas"), QByteArrayLiteral("GET"), {}, false, false,
            [this, completion = std::move(completion)](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        if (status != 200) {
            const QString problem = problemMessage(reply, body);
            reply->deleteLater();
            setError(QStringLiteral("无法读取私有 PKI 的证书颁发机构。"), problem);
            completion(false);
            return;
        }
        authorities_.clear();
        for (const QJsonValue &value : parseObject(body).value(QStringLiteral("items")).toArray())
            authorities_.append(toVariantMap(value.toObject()));
        reply->deleteLater();
        emit dataChanged();
        completion(true);
    });
}

void PkiConsoleClient::loadInventory(const QString &statusFilter,
                                     std::function<void(bool)> completion)
{
    QUrl path(QStringLiteral("certificate-inventory"));
    if (!statusFilter.trimmed().isEmpty()) {
        QUrlQuery query;
        query.addQueryItem(QStringLiteral("status"), statusFilter.trimmed());
        path.setQuery(query);
    }
    sendApi(path.toString(), QByteArrayLiteral("GET"), {}, false, false,
            [this, completion = std::move(completion)](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        if (status != 200) {
            const QString problem = problemMessage(reply, body);
            reply->deleteLater();
            setError(QStringLiteral("无法读取通过私有 PKI 申请的证书。"), problem);
            completion(false);
            return;
        }
        inventory_.clear();
        for (const QJsonValue &value : parseObject(body).value(QStringLiteral("items")).toArray())
            inventory_.append(toVariantMap(value.toObject()));
        reply->deleteLater();
        emit dataChanged();
        completion(true);
    });
}

void PkiConsoleClient::loadProfiles(const QString &caId)
{
    if (busy_ || !authenticated_ || caId.trimmed().isEmpty()) return;
    setBusy(true, QStringLiteral("正在读取签名配置档"));
    sendApi(QStringLiteral("cas/%1/profiles").arg(caId), QByteArrayLiteral("GET"), {}, false, false,
            [this](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        if (status != 200) {
            const QString problem = problemMessage(reply, body);
            reply->deleteLater();
            setBusy(false, QStringLiteral("已连接私有 PKI"));
            setError(QStringLiteral("无法读取所选 CA 的签名配置档。"), problem);
            return;
        }
        profiles_.clear();
        for (const QJsonValue &value : parseObject(body).value(QStringLiteral("items")).toArray()) {
            const QJsonObject object = value.toObject();
            if (object.value(QStringLiteral("enabled")).toBool(true))
                profiles_.append(toVariantMap(object));
        }
        reply->deleteLater();
        setBusy(false, QStringLiteral("已连接私有 PKI"));
        emit dataChanged();
    });
}

void PkiConsoleClient::createCertificateRequest(const QString &localRequestId,
                                                 const QString &csrPem,
                                                 const int validityDays,
                                                 const QString &caId,
                                                 const QString &profileId)
{
    if (busy_ || !authenticated_) return;
    if (localRequestId.isEmpty() || csrPem.isEmpty() || caId.isEmpty()) {
        setError(QStringLiteral("请选择本地 CSR、证书颁发机构和签名配置档。"));
        return;
    }
    QJsonObject payload{{QStringLiteral("ca_id"), caId},
                        {QStringLiteral("csr_pem"), csrPem},
                        {QStringLiteral("requested_validity_seconds"),
                         qBound(1, validityDays, 3650) * 86400}};
    if (!profileId.isEmpty()) payload.insert(QStringLiteral("profile_id"), profileId);
    setBusy(true, QStringLiteral("正在向私有 PKI 提交证书申请"));
    const QByteArray body = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    sendApi(QStringLiteral("certificate-requests"), QByteArrayLiteral("POST"), body, true, true,
            [this, localRequestId, caId](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray responseBody = reply->readAll();
        const QJsonObject object = parseObject(responseBody);
        if (status != 201 || object.value(QStringLiteral("id")).toString().isEmpty()) {
            const QString problem = problemMessage(reply, responseBody);
            reply->deleteLater();
            setBusy(false, QStringLiteral("已连接私有 PKI"));
            setError(QStringLiteral("私有 PKI 拒绝了证书申请。"), problem);
            return;
        }
        const QString remoteId = object.value(QStringLiteral("id")).toString();
        QString authorityName = caId;
        for (const QVariant &value : std::as_const(authorities_)) {
            const QVariantMap authority = value.toMap();
            if (authority.value(QStringLiteral("id")).toString() == caId) {
                authorityName = authority.value(QStringLiteral("name")).toString();
                break;
            }
        }
        reply->deleteLater();
        setBusy(false, QStringLiteral("已连接私有 PKI"));
        setStatus(QStringLiteral("证书申请已提交到 %1。").arg(authorityName));
        emit requestCreated(localRequestId, remoteId, authorityName);
        refreshRemoteData();
    });
}

void PkiConsoleClient::downloadCertificate(const QString &localRequestId,
                                           const QString &certificateId)
{
    if (busy_ || !authenticated_ || localRequestId.isEmpty() || certificateId.isEmpty()) return;
    setBusy(true, QStringLiteral("正在下载私有 PKI 签发证书"));
    sendApi(QStringLiteral("certificates/%1/download").arg(certificateId),
            QByteArrayLiteral("GET"), {}, false, false,
            [this, localRequestId](QNetworkReply *reply) {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        if (status != 200 || !body.contains("-----BEGIN CERTIFICATE-----")) {
            const QString problem = problemMessage(reply, body);
            reply->deleteLater();
            setBusy(false, QStringLiteral("已连接私有 PKI"));
            setError(QStringLiteral("无法下载私有 PKI 签发的证书。"), problem);
            return;
        }
        reply->deleteLater();
        setBusy(false, QStringLiteral("已连接私有 PKI"));
        emit certificateDownloaded(localRequestId, body);
    });
}

QString PkiConsoleClient::problemMessage(QNetworkReply *reply, const QByteArray &body)
{
    const QJsonObject object = parseObject(body);
    QString detail = object.value(QStringLiteral("detail")).toString();
    const QString code = object.value(QStringLiteral("code")).toString();
    if (detail.isEmpty()) detail = reply->errorString();
    if (!code.isEmpty()) detail += QStringLiteral(" [%1]").arg(code);
    const QByteArray requestId = reply->rawHeader("X-Request-ID");
    if (!requestId.isEmpty()) detail += QStringLiteral(" 请求 ID：%1").arg(QString::fromLatin1(requestId));
    const QByteArray retryAfter = reply->rawHeader("Retry-After");
    if (!retryAfter.isEmpty()) detail += QStringLiteral(" 请在 %1 秒后重试。").arg(QString::fromLatin1(retryAfter));
    return detail;
}

QVariantMap PkiConsoleClient::toVariantMap(const QJsonObject &object)
{
    return object.toVariantMap();
}

QByteArray PkiConsoleClient::randomBase64Url(const int bytes)
{
    if (bytes <= 0) return {};
    QByteArray random(bytes, Qt::Uninitialized);
    randombytes_buf(random.data(), static_cast<size_t>(random.size()));
    const QByteArray encoded = random.toBase64(QByteArray::Base64UrlEncoding |
                                                QByteArray::OmitTrailingEquals);
    random.fill('\0');
    return encoded;
}

bool PkiConsoleClient::sameState(const QByteArray &left, const QByteArray &right)
{
    return left.size() == right.size() && !left.isEmpty() &&
           sodium_memcmp(left.constData(), right.constData(), static_cast<size_t>(left.size())) == 0;
}

bool PkiConsoleClient::isTrustedHttpsUrl(const QUrl &url)
{
    return url.isValid() && url.scheme() == QStringLiteral("https") &&
           !url.host().isEmpty() && url.userInfo().isEmpty();
}

bool PkiConsoleClient::sameOrigin(const QUrl &left, const QUrl &right)
{
    const auto effectivePort = [](const QUrl &url) {
        return url.port(url.scheme() == QStringLiteral("https") ? 443 : 80);
    };
    return left.scheme().compare(right.scheme(), Qt::CaseInsensitive) == 0 &&
           left.host().compare(right.host(), Qt::CaseInsensitive) == 0 &&
           effectivePort(left) == effectivePort(right);
}

} // namespace certmgr::services
