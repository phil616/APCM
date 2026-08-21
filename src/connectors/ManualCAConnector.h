#pragma once

#include "../platform/interfaces/ICAConnector.h"

namespace certmgr::connectors {

class ManualCAConnector final : public platform::ICAConnector {
public:
    QString type() const override { return QStringLiteral("manual"); }
    tl::expected<platform::SubmitResult, domain::AppError>
        submit(const platform::CertificateRequestPayload &request) override;
    tl::expected<platform::RequestStatus, domain::AppError>
        query(const QString &remoteRequestId) override;
    tl::expected<platform::CertificateResponse, domain::AppError>
        retrieve(const QString &remoteRequestId) override;
    tl::expected<void, domain::AppError>
        revoke(const QString &certificateFingerprint, const QString &reason) override;
};

} // namespace certmgr::connectors

