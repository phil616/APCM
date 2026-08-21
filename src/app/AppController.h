#pragma once

#include "CertificateListModel.h"
#include "../persistence/SqlCipherVault.h"
#include "../platform/windows/certificate_store/WindowsCertificateStore.h"
#include "../platform/windows/cert_enroll/WindowsCertEnrollBackend.h"
#include "../platform/windows/cng/WindowsCngKeyProvider.h"
#include "../platform/windows/privilege/ElevatedHelperLauncher.h"
#include "../services/TemplateService.h"
#include "../connectors/ManualCAConnector.h"

#include <QObject>
#include <QUrl>
#include <QVariantList>

namespace certmgr::app {

class AppController final : public QObject {
    Q_OBJECT
    Q_PROPERTY(CertificateListModel *certificates READ certificates CONSTANT)
    Q_PROPERTY(bool vaultExists READ vaultExists NOTIFY vaultStateChanged)
    Q_PROPERTY(bool unlocked READ unlocked NOTIFY vaultStateChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(bool tpmReady READ tpmReady NOTIFY dataChanged)
    Q_PROPERTY(int expiringSoon READ expiringSoon NOTIFY dataChanged)
    Q_PROPERTY(int privateKeyCount READ privateKeyCount NOTIFY dataChanged)
    Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY errorMessageChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(QVariantList templates READ templates CONSTANT)
    Q_PROPERTY(QVariantList enrollmentRequests READ enrollmentRequests NOTIFY dataChanged)
    Q_PROPERTY(QVariantList privateKeys READ privateKeys NOTIFY dataChanged)
    Q_PROPERTY(QVariantList managedRoots READ managedRoots NOTIFY dataChanged)
    Q_PROPERTY(QVariantList managedCertificates READ managedCertificates NOTIFY dataChanged)
    Q_PROPERTY(QVariantList pkiConnections READ pkiConnections NOTIFY dataChanged)
    Q_PROPERTY(QVariantList auditEvents READ auditEvents NOTIFY dataChanged)

public:
    explicit AppController(QObject *parent = nullptr);
    CertificateListModel *certificates() { return &certificates_; }
    bool vaultExists() const { return vault_.exists(); }
    bool unlocked() const { return vault_.isUnlocked(); }
    bool busy() const { return busy_; }
    bool tpmReady() const { return tpmReady_; }
    int expiringSoon() const { return expiringSoon_; }
    int privateKeyCount() const { return privateKeyCount_; }
    QString errorMessage() const { return errorMessage_; }
    QString statusMessage() const { return statusMessage_; }
    QVariantList templates() const;
    QVariantList enrollmentRequests() const { return enrollmentRequests_; }
    QVariantList privateKeys() const { return privateKeys_; }
    QVariantList managedRoots() const { return managedRoots_; }
    QVariantList managedCertificates() const { return managedCertificates_; }
    QVariantList pkiConnections() const { return pkiConnections_; }
    QVariantList auditEvents() const { return auditEvents_; }

    Q_INVOKABLE bool initializeVault(const QString &masterPassword);
    Q_INVOKABLE bool unlockVault(const QString &masterPassword);
    Q_INVOKABLE void lockVault();
    Q_INVOKABLE void prepareForExit();
    Q_INVOKABLE void exitApplication();
    Q_INVOKABLE void refresh();
    Q_INVOKABLE bool copyToClipboard(const QString &text, const QString &description);
    Q_INVOKABLE QVariantMap certificateDetails(const QString &id) const;
    Q_INVOKABLE QVariantMap previewCertificate(const QUrl &source);
    Q_INVOKABLE bool exportCertificate(const QString &id, const QUrl &destination);
    Q_INVOKABLE bool importCertificate(const QUrl &source, int scope, int role, bool rootTrustConfirmed);
    Q_INVOKABLE QVariantMap previewCertificatePackage(const QUrl &source, const QString &password);
    Q_INVOKABLE QVariantMap installCertificatePackage(const QUrl &source, const QString &password,
                                                       int scope, int role, bool rootTrustConfirmed);
    Q_INVOKABLE bool deleteCertificate(const QString &id, bool confirmed);
    Q_INVOKABLE QVariantMap generateRequest(const QString &templateId, const QVariantMap &options);
    Q_INVOKABLE QString requestCsr(const QString &requestId) const;
    Q_INVOKABLE bool exportRequestCsr(const QString &requestId, const QUrl &destination);
    Q_INVOKABLE bool installEnrollmentResponse(const QString &requestId, const QUrl &source);
    Q_INVOKABLE bool submitEnrollmentRequest(const QString &requestId, const QString &connectionId);
    Q_INVOKABLE bool manageRoot(const QString &certificateId);
    Q_INVOKABLE bool unmanageRoot(const QString &fingerprint);
    Q_INVOKABLE QString savePkiConnection(const QString &id, const QString &name,
                                          const QString &type, const QString &endpoint);
    Q_INVOKABLE bool removePkiConnection(const QString &id);
    Q_INVOKABLE bool testPkiConnection(const QString &id);
    Q_INVOKABLE void clearMessage();

signals:
    void vaultStateChanged();
    void busyChanged();
    void dataChanged();
    void errorMessageChanged();
    void statusMessageChanged();

private:
    void closeVault(const QString &auditAction);
    void loadVaultData();
    void setBusy(bool value);
    void setError(const domain::AppError &error);
    void setStatus(QString message);
    static QByteArray decodeCertificateFile(const QByteArray &contents);

    CertificateListModel certificates_;
    platform::windows::WindowsCertificateStore certificateStore_;
    platform::windows::WindowsCngKeyProvider keyProvider_;
    platform::windows::WindowsCertEnrollBackend enrollmentBackend_;
    platform::windows::ElevatedHelperLauncher elevatedHelper_;
    services::TemplateService templateService_;
    connectors::ManualCAConnector manualConnector_;
    persistence::SqlCipherVault vault_;
    bool busy_{false};
    bool tpmReady_{false};
    int expiringSoon_{0};
    int privateKeyCount_{0};
    QString errorMessage_;
    QString statusMessage_;
    QVariantList enrollmentRequests_;
    QVariantList privateKeys_;
    QVariantList managedRoots_;
    QVariantList managedCertificates_;
    QVariantList pkiConnections_;
    QVariantList auditEvents_;
};

} // namespace certmgr::app
