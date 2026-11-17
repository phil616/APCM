#pragma once

#include "../platform/interfaces/IAuditLog.h"
#include "../platform/interfaces/IVault.h"
#include "SecureBuffer.h"
#include "../domain/enrollment/EnrollmentRequest.h"

#include <QFileInfo>
#include <QJsonObject>
#include <QVariantList>
#include <memory>
#include <vector>

struct sqlite3;

namespace certmgr::persistence {

class SqlCipherVault final : public platform::IVault, public platform::IAuditLog {
public:
    struct ManagedRootRecord {
        QString fingerprint;
        QString scope;
        QString storeRole;
        QString friendlyName;
    };

    explicit SqlCipherVault(QString directoryPath);
    ~SqlCipherVault() override;

    bool exists() const override;
    bool isUnlocked() const override;
    tl::expected<void, domain::AppError> initialize(const QByteArray &masterPassword) override;
    tl::expected<void, domain::AppError> unlock(const QByteArray &masterPassword) override;
    void lock() override;
    tl::expected<void, domain::AppError> append(const platform::AuditEvent &event) override;
    tl::expected<std::vector<platform::AuditEvent>, domain::AppError> auditEvents(int limit = 500) const;
    tl::expected<void, domain::AppError> saveEnrollmentRequest(const domain::EnrollmentRequest &request);
    tl::expected<std::vector<domain::EnrollmentRequest>, domain::AppError> enrollmentRequests() const;
    tl::expected<void, domain::AppError> saveManagedRoot(const ManagedRootRecord &record);
    tl::expected<void, domain::AppError> saveManagedCertificate(const ManagedRootRecord &record);
    tl::expected<void, domain::AppError> removeManagedRoot(const QString &fingerprint);
    tl::expected<std::vector<ManagedRootRecord>, domain::AppError> managedRoots() const;
    tl::expected<std::vector<ManagedRootRecord>, domain::AppError> managedCertificates() const;

    tl::expected<void, domain::AppError> saveSigningRecord(const QString &kind, const QString &id, const QJsonObject &record);
    tl::expected<QVariantList, domain::AppError> signingRecords(const QString &kind) const;
    tl::expected<void, domain::AppError> removeSigningRecord(const QString &kind, const QString &id);

    [[nodiscard]] QString databasePath() const;
    [[nodiscard]] QString metadataPath() const;

private:
    struct VaultMetadata;
    tl::expected<VaultMetadata, domain::AppError> readMetadata() const;
    tl::expected<void, domain::AppError> writeMetadata(const VaultMetadata &metadata) const;
    tl::expected<SecureBuffer, domain::AppError> deriveKek(const QByteArray &masterPassword,
                                                           const VaultMetadata &metadata) const;
    tl::expected<void, domain::AppError> openDatabase(const SecureBuffer &databaseKey,
                                                       bool createSchema);
    tl::expected<void, domain::AppError> execute(const char *sql);

    QString directoryPath_;
    sqlite3 *database_{nullptr};
    SecureBuffer databaseKey_;
    bool cryptoReady_{false};
};

} // namespace certmgr::persistence
