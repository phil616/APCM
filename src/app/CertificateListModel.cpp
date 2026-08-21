#include "CertificateListModel.h"

#include <algorithm>

namespace certmgr::app {

CertificateListModel::CertificateListModel(QObject *parent) : QAbstractListModel(parent) {}

int CertificateListModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(certificates_.size());
}

QVariant CertificateListModel::data(const QModelIndex &index, const int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) return {};
    const auto &value = certificates_[static_cast<size_t>(index.row())];
    switch (role) {
    case IdRole: return value.id;
    case NameRole: return value.commonName.isEmpty() ? value.subject : value.commonName;
    case SubjectRole: return value.subject;
    case IssuerRole: return value.issuer;
    case ScopeRole: return domain::storeScopeName(value.location.scope);
    case StoreRole: return domain::storeRoleName(value.location.role);
    case ExpiresRole: return value.notAfter;
    case DaysRemainingRole: return QDateTime::currentDateTime().daysTo(value.notAfter);
    case HasPrivateKeyRole: return value.hasPrivateKey;
    case TpmBackedRole: return value.tpmBacked;
    case ValidRole: return value.chain.valid;
    case FingerprintRole: return value.sha256Fingerprint;
    default: return {};
    }
}

QHash<int, QByteArray> CertificateListModel::roleNames() const
{
    return {{IdRole, "certificateId"}, {NameRole, "name"}, {SubjectRole, "subject"},
        {IssuerRole, "issuer"}, {ScopeRole, "scope"}, {StoreRole, "storeRole"},
        {ExpiresRole, "expires"}, {DaysRemainingRole, "daysRemaining"},
        {HasPrivateKeyRole, "hasPrivateKey"}, {TpmBackedRole, "tpmBacked"},
        {ValidRole, "valid"}, {FingerprintRole, "fingerprint"}};
}

void CertificateListModel::replace(std::vector<domain::CertificateInfo> certificates)
{
    beginResetModel();
    certificates_ = std::move(certificates);
    endResetModel();
    emit countChanged();
}

const domain::CertificateInfo *CertificateListModel::find(const QString &id) const
{
    const auto found = std::find_if(certificates_.cbegin(), certificates_.cend(),
                                    [&](const auto &value) { return value.id == id; });
    return found == certificates_.cend() ? nullptr : &*found;
}

} // namespace certmgr::app
