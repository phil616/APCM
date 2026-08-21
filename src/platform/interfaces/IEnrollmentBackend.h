#pragma once

#include "../../domain/AppError.h"
#include "../../domain/templates/CertificateTemplate.h"

#include <QByteArray>
#include <QString>
#include <tl/expected.hpp>

namespace certmgr::platform {

struct GeneratedEnrollment {
    QString csrBase64;
    QString csrSha256;
    QString publicKeySha256;
    QString providerName;
    QString keyContainerName;
};

class IEnrollmentBackend {
public:
    virtual ~IEnrollmentBackend() = default;
    virtual tl::expected<GeneratedEnrollment, domain::AppError>
        createPkcs10(const domain::CertificateTemplate &certificateTemplate) = 0;
    virtual tl::expected<void, domain::AppError>
        installResponse(const QByteArray &certificateDer, domain::StoreScope scope,
                        const QString &providerName, const QString &keyContainerName,
                        const QString &friendlyName) = 0;
};

} // namespace certmgr::platform
