#pragma once

#include "../persistence/SqlCipherVault.h"
#include "../platform/windows/cert_enroll/WindowsCertEnrollBackend.h"
#include "../services/SigningHttpClient.h"
#include <QHash>
#include <QObject>
#include <functional>

namespace certmgr::app {
class IndependentSigningController final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QVariantList profiles READ profiles NOTIFY changed)
    Q_PROPERTY(QVariantMap currentProfile READ currentProfile NOTIFY changed)
    Q_PROPERTY(QString selectedProfileId READ selectedProfileId NOTIFY changed)
    Q_PROPERTY(QVariantList operations READ operations NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY changed)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY changed)
    Q_PROPERTY(QString transportSummary READ transportSummary NOTIFY changed)
    Q_PROPERTY(QVariantMap issuerInfo READ issuerInfo NOTIFY changed)
    Q_PROPERTY(QVariantMap crlInfo READ crlInfo NOTIFY changed)
    Q_PROPERTY(QVariantMap ownerSettings READ ownerSettings NOTIFY changed)
    Q_PROPERTY(bool ownerAuthenticated READ ownerAuthenticated NOTIFY changed)
    Q_PROPERTY(QString ownerUser READ ownerUser NOTIFY changed)
    Q_PROPERTY(QString ownerSessionExpiry READ ownerSessionExpiry NOTIFY changed)
    Q_PROPERTY(QVariantList ownerInstances READ ownerInstances NOTIFY changed)
    Q_PROPERTY(QVariantList ownerCredentials READ ownerCredentials NOTIFY changed)
    Q_PROPERTY(QVariantList ownerCertificates READ ownerCertificates NOTIFY changed)
    Q_PROPERTY(QString ownerInstanceId READ ownerInstanceId NOTIFY changed)
    Q_PROPERTY(QString ownerNextCursor READ ownerNextCursor NOTIFY changed)
    Q_PROPERTY(QString ownerTransportSummary READ ownerTransportSummary NOTIFY changed)
public:
    using Installer = std::function<bool(const QString &, const QByteArray &)>;
    IndependentSigningController(persistence::SqlCipherVault &vault, Installer installer, QObject *parent = nullptr);
    void load();
    void clear();
    QVariantList profiles() const;
    QVariantMap currentProfile() const;
    QString selectedProfileId() const { return selectedProfileId_; }
    QVariantList operations() const;
    bool busy() const { return busy_; }
    QString errorMessage() const { return error_; }
    QString statusMessage() const { return status_; }
    QString transportSummary() const;
    QVariantMap issuerInfo() const { return issuerInfo_; }
    QVariantMap crlInfo() const { return crlInfo_; }
    QVariantMap ownerSettings() const { return ownerSettings_; }
    bool ownerAuthenticated() const { return !csrf_.isEmpty(); }
    QString ownerUser() const { return ownerUser_; }
    QString ownerSessionExpiry() const { return ownerSessionExpiry_; }
    QVariantList ownerInstances() const { return ownerInstances_; }
    QVariantList ownerCredentials() const { return ownerCredentials_; }
    QVariantList ownerCertificates() const { return ownerCertificates_; }
    QString ownerInstanceId() const { return ownerInstanceId_; }
    QString ownerNextCursor() const { return ownerNextCursor_; }
    QString ownerTransportSummary() const;

    Q_INVOKABLE void clearMessage();
    Q_INVOKABLE bool saveProfile(const QVariantMap &settings, const QString &token, const QString &transportPassword);
    Q_INVOKABLE bool selectProfile(const QString &id);
    Q_INVOKABLE bool deleteProfile(const QString &id, bool confirmed);
    Q_INVOKABLE bool forgetToken(const QString &id, bool confirmed);
    Q_INVOKABLE QString prepareIssue(const QVariantMap &options);
    Q_INVOKABLE void retryOperation(const QString &id);
    Q_INVOKABLE void refreshCertificate(const QString &id);
    Q_INVOKABLE void trackCertificate(const QString &certificateId);
    Q_INVOKABLE void revokeCertificate(const QString &id, int reason, bool confirmed);
    Q_INVOKABLE void revalidateOperation(const QString &id);
    Q_INVOKABLE void installOperation(const QString &id);
    Q_INVOKABLE bool exportOperation(const QString &id, const QString &part, const QUrl &destination);
    Q_INVOKABLE void fetchArtifact(const QString &kind);
    Q_INVOKABLE bool exportArtifact(const QString &kind, const QUrl &destination);
    Q_INVOKABLE bool saveOwnerSettings(const QVariantMap &settings, const QString &transportPassword);
    Q_INVOKABLE void ownerLogin(const QString &login, const QString &password);
    Q_INVOKABLE void ownerLogout();
    Q_INVOKABLE void ownerCheckSession();
    Q_INVOKABLE void ownerAcknowledgePending(bool confirmed);
    Q_INVOKABLE void ownerRefreshInstances();
    Q_INVOKABLE void ownerRefreshInstance();
    Q_INVOKABLE void ownerSelectInstance(const QString &id);
    Q_INVOKABLE void ownerSaveInstance(const QVariantMap &options, bool uploadConfirmed);
    Q_INVOKABLE void ownerRefreshCredentials();
    Q_INVOKABLE void ownerCreateCredential(const QVariantMap &options);
    Q_INVOKABLE void ownerRevokeCredential(const QString &credentialId, bool confirmed);
    Q_INVOKABLE void ownerLoadCertificates(bool nextPage);
    Q_INVOKABLE void ownerRevokeCertificate(const QString &certificateId, int reason, bool confirmed);

signals:
    void changed();
    void enrollmentChanged();
    void credentialCreated(const QString &token);
private:
    bool ready();
    bool networkReady();
    void rememberBackoff(const QDateTime &retryAt);
    void fail(const QString &message);
    void notice(const QString &message);
    QString secretTarget(const QString &id) const;
    domain::signing::Result<QByteArray> tokenFor(const QJsonObject &operation) const;
    domain::signing::Result<QByteArray> businessRoots(const QVariantMap &profile) const;
    bool persist(QJsonObject operation);
    void completeOperation(const QString &id, const services::SigningHttpResult &result, const QString &action);
    void holderRequest(const QString &id, const QString &action);
    QUrl holderUrl(const QString &suffix) const;
    QUrl ownerUrl(const QString &suffix) const;
    void ownerRequest(const QByteArray &method, const QString &path, QByteArray body, int expected,
                       std::function<void(const services::SigningHttpResult &)> completed);
    void resetOwnerSession();
    bool saveFile(const QUrl &url, const QByteArray &data);
    void audit(const QString &action, const QString &id, const QString &result);
    persistence::SqlCipherVault &vault_;
    Installer installer_;
    platform::windows::WindowsCertEnrollBackend enrollment_;
    services::SigningHttpClient holderHttp_;
    services::SigningHttpClient ownerHttp_;
    QHash<QString, QVariantMap> profiles_;
    QHash<QString, QJsonObject> operations_;
    QString selectedProfileId_;
    QVariantMap ownerSettings_;
    bool busy_{false};
    QString error_, status_;
    QByteArray issuerDer_, crlDer_, csrf_;
    QVariantMap issuerInfo_, crlInfo_;
    QString ownerUser_, ownerSessionExpiry_, ownerInstanceId_, ownerNextCursor_;
    QVariantList ownerInstances_, ownerCredentials_, ownerCertificates_;
    QDateTime retryAt_;
};
}
