#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QStringList>

namespace certmgr::domain {

enum class StoreScope { User, Machine, Service };
enum class StoreRole {
    Personal,
    TrustedRoot,
    IntermediateCA,
    EnterpriseTrust,
    EnrollmentRequest,
    Other
};

struct CertificateStoreLocation {
    StoreScope scope{StoreScope::User};
    StoreRole role{StoreRole::Personal};
    QString nativeStore;
};

struct ChainStatus {
    bool valid{false};
    bool trustedRoot{false};
    bool validTime{false};
    bool correctUsage{true};
    enum class Revocation { Good, Revoked, Unknown, NotChecked } revocation{Revocation::NotChecked};
    quint32 nativeErrorStatus{0};
    QStringList diagnostics;
};

struct CertificateInfo {
    QString id;
    CertificateStoreLocation location;
    QString subject;
    QString commonName;
    QString issuer;
    QString serialNumber;
    QString sha256Fingerprint;
    QString sha1Thumbprint;
    QDateTime notBefore;
    QDateTime notAfter;
    QStringList subjectAlternativeNames;
    QStringList keyUsage;
    QStringList extendedKeyUsage;
    bool isCA{false};
    int pathLength{-1};
    QString publicKeyAlgorithm;
    int publicKeyBits{0};
    QString signatureAlgorithm;
    bool hasPrivateKey{false};
    QString keyProvider;
    QString keyContainer;
    bool machineKey{false};
    bool hardwareBacked{false};
    bool tpmBacked{false};
    bool exportable{false};
    ChainStatus chain;
    QString friendlyName;
    QByteArray encodedDer;
};

QString storeScopeName(StoreScope scope);
QString storeRoleName(StoreRole role);

} // namespace certmgr::domain
