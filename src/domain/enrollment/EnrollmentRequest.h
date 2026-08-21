#pragma once

#include "../certificate/CertificateInfo.h"

#include <QDateTime>
#include <QString>

namespace certmgr::domain {

enum class EnrollmentState {
    Draft,
    KeyCreated,
    CsrCreated,
    Submitted,
    Pending,
    Issued,
    Installed,
    Denied,
    Failed,
    Revoked
};

struct EnrollmentRequest {
    QString id;
    QString templateId;
    int templateVersion{1};
    StoreScope scope{StoreScope::User};
    QDateTime createdAt;
    QDateTime updatedAt;
    QString subject;
    QString csrSha256;
    QString publicKeySha256;
    QString providerName;
    QString keyContainerName;
    EnrollmentState state{EnrollmentState::Draft};
    QString remoteRequestId;
    QString remoteCA;
    QString certificateFingerprint;
    QString errorCode;
    QString errorMessage;
    QString friendlyName;
    int requestedValidityDays{365};
    QString csrText;
};

QString enrollmentStateName(EnrollmentState state);

} // namespace certmgr::domain
