#pragma once

#include "../domain/certificate/CertificateInfo.h"

#include <QAbstractListModel>

#include <vector>

namespace certmgr::app {

class CertificateListModel final : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(int count READ rowCount NOTIFY countChanged)

public:
    enum Role {
        IdRole = Qt::UserRole + 1,
        NameRole,
        SubjectRole,
        IssuerRole,
        ScopeRole,
        StoreRole,
        ExpiresRole,
        DaysRemainingRole,
        HasPrivateKeyRole,
        TpmBackedRole,
        ValidRole,
        FingerprintRole
    };
    Q_ENUM(Role)

    explicit CertificateListModel(QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;
    void replace(std::vector<domain::CertificateInfo> certificates);
    [[nodiscard]] const domain::CertificateInfo *find(const QString &id) const;
    [[nodiscard]] const std::vector<domain::CertificateInfo> &values() const { return certificates_; }

signals:
    void countChanged();

private:
    std::vector<domain::CertificateInfo> certificates_;
};

} // namespace certmgr::app
