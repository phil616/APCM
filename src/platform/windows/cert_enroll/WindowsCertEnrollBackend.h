#pragma once

#include "../../interfaces/IEnrollmentBackend.h"

namespace certmgr::platform::windows {

class WindowsCertEnrollBackend final : public IEnrollmentBackend {
public:
    tl::expected<GeneratedEnrollment, domain::AppError>
        createPkcs10(const domain::CertificateTemplate &certificateTemplate) override;
    tl::expected<void, domain::AppError>
        installResponse(const QByteArray &certificateDer, domain::StoreScope scope,
                        const QString &providerName, const QString &keyContainerName,
                        const QString &friendlyName) override;
};

} // namespace certmgr::platform::windows
