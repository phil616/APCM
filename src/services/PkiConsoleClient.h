#pragma once

#include <QDateTime>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QObject>
#include <QTcpServer>
#include <QTimer>
#include <QUrl>
#include <QVariantList>

#include <functional>

class QNetworkReply;

namespace certmgr::services {

class PkiConsoleClient final : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool busy READ busy NOTIFY stateChanged)
    Q_PROPERTY(bool oauthAuthorized READ oauthAuthorized NOTIFY stateChanged)
    Q_PROPERTY(bool authenticated READ authenticated NOTIFY stateChanged)
    Q_PROPERTY(QString phase READ phase NOTIFY stateChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY stateChanged)
    Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY stateChanged)
    Q_PROPERTY(QString userName READ userName NOTIFY stateChanged)
    Q_PROPERTY(QString userRole READ userRole NOTIFY stateChanged)
    Q_PROPERTY(QString sessionExpiresAt READ sessionExpiresAt NOTIFY stateChanged)
    Q_PROPERTY(QString serviceOrigin READ serviceOrigin CONSTANT)
    Q_PROPERTY(QVariantList authorities READ authorities NOTIFY dataChanged)
    Q_PROPERTY(QVariantList profiles READ profiles NOTIFY dataChanged)
    Q_PROPERTY(QVariantList inventory READ inventory NOTIFY dataChanged)

public:
    explicit PkiConsoleClient(QObject *parent = nullptr);
    ~PkiConsoleClient() override;

    bool busy() const { return busy_; }
    bool oauthAuthorized() const { return oauthAuthorized_; }
    bool authenticated() const { return authenticated_; }
    QString phase() const { return phase_; }
    QString statusMessage() const { return statusMessage_; }
    QString errorMessage() const { return errorMessage_; }
    QString userName() const { return userName_; }
    QString userRole() const { return userRole_; }
    QString sessionExpiresAt() const { return sessionExpiresAt_.toString(Qt::ISODate); }
    QString serviceOrigin() const { return origin_.toString(); }
    QVariantList authorities() const { return authorities_; }
    QVariantList profiles() const { return profiles_; }
    QVariantList inventory() const { return inventory_; }

    Q_INVOKABLE void beginAuthorization();
    Q_INVOKABLE void login(const QString &login, const QString &password,
                           const QString &totp = {});
    Q_INVOKABLE void logout(bool forgetDevice = false);
    Q_INVOKABLE void refreshRemoteData(const QString &status = {});
    Q_INVOKABLE void loadProfiles(const QString &caId);
    Q_INVOKABLE void createCertificateRequest(const QString &localRequestId,
                                               const QString &csrPem,
                                               int validityDays,
                                               const QString &caId,
                                               const QString &profileId);
    Q_INVOKABLE void downloadCertificate(const QString &localRequestId,
                                         const QString &certificateId);
    Q_INVOKABLE void clearError();
    void browserLaunchFailed();

signals:
    void stateChanged();
    void dataChanged();
    void authorizationUrlReady(const QUrl &url);
    void requestCreated(const QString &localRequestId, const QString &remoteRequestId,
                        const QString &authorityName);
    void certificateDownloaded(const QString &localRequestId, const QByteArray &pemData);

private:
    using ReplyHandler = std::function<void(QNetworkReply *)>;

    void setBusy(bool value, const QString &phase = {});
    void setStatus(const QString &message);
    void setError(const QString &message, const QString &details = {});
    void clearApplicationSession();
    void clearOAuthCredentials();
    void restoreOAuthCredentials();
    bool persistOAuthCredentials();
    bool accessTokenUsable() const;
    void refreshAccessToken(std::function<void(bool)> completion);
    void startDiscovery();
    void fetchProtectedResourceMetadata(const QUrl &metadataUrl);
    void fetchAuthorizationServerMetadata(const QUrl &issuerUrl);
    void registerClient();
    void openAuthorizationPage();
    void acceptOAuthConnection();
    void exchangeAuthorizationCode(const QString &code);
    void send(QNetworkRequest request, const QByteArray &method, const QByteArray &body,
              ReplyHandler handler);
    void sendApi(const QString &path, const QByteArray &method, const QByteArray &body,
                 bool needsCsrf, bool idempotent, ReplyHandler handler, bool retried = false,
                 QByteArray idempotencyKey = {});
    void loadAuthorities(std::function<void(bool)> completion);
    void loadInventory(const QString &status, std::function<void(bool)> completion);
    static QString problemMessage(QNetworkReply *reply, const QByteArray &body);
    static QVariantMap toVariantMap(const QJsonObject &object);
    static QByteArray randomBase64Url(int bytes);
    static bool sameState(const QByteArray &left, const QByteArray &right);
    static bool isTrustedHttpsUrl(const QUrl &url);
    static bool sameOrigin(const QUrl &left, const QUrl &right);

    const QUrl origin_{QStringLiteral("https://pki-console.altasci.com")};
    const QUrl apiBase_{QStringLiteral("https://pki-console.altasci.com/api/v1/")};
    QNetworkAccessManager network_;
    QTcpServer callbackServer_;
    QTimer callbackTimeout_;
    bool busy_{false};
    bool oauthAuthorized_{false};
    bool authenticated_{false};
    QString phase_{QStringLiteral("需要 Cloudflare Access 授权")};
    QString statusMessage_;
    QString errorMessage_;
    QString userName_;
    QString userRole_;
    QDateTime sessionExpiresAt_;
    QString csrfToken_;
    QString accessToken_;
    QString refreshToken_;
    QString clientId_;
    QDateTime accessTokenExpiresAt_;
    QUrl tokenEndpoint_;
    QUrl authorizationEndpoint_;
    QUrl registrationEndpoint_;
    QUrl revocationEndpoint_;
    QUrl authorizationIssuer_;
    QUrl redirectUri_;
    QByteArray pkceVerifier_;
    QByteArray oauthState_;
    QVariantList authorities_;
    QVariantList profiles_;
    QVariantList inventory_;
};

} // namespace certmgr::services
