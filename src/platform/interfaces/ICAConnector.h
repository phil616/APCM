#pragma once

#include "../../domain/AppError.h"

#include <QByteArray>
#include <QString>
#include <tl/expected.hpp>

namespace certmgr::platform {

struct CertificateRequestPayload {
    QString localRequestId;
    QString csrBase64;
    QString csrSha256;
};

struct SubmitResult {
    QString remoteRequestId;
    QString message;
};

enum class RemoteRequestState { Pending, Issued, Denied, Failed, ManualActionRequired };

struct RequestStatus {
    RemoteRequestState state{RemoteRequestState::Pending};
    QString message;
};

struct CertificateResponse {
    QByteArray encodedCertificate;
    QString mediaType;
};

class ICAConnector {
public:
    virtual ~ICAConnector() = default;
    virtual QString type() const = 0;
    virtual tl::expected<SubmitResult, domain::AppError>
        submit(const CertificateRequestPayload &request) = 0;
    virtual tl::expected<RequestStatus, domain::AppError>
        query(const QString &remoteRequestId) = 0;
    virtual tl::expected<CertificateResponse, domain::AppError>
        retrieve(const QString &remoteRequestId) = 0;
    virtual tl::expected<void, domain::AppError>
        revoke(const QString &certificateFingerprint, const QString &reason) = 0;
};

} // namespace certmgr::platform

