#pragma once

#include "../../domain/AppError.h"
#include "../../domain/certificate/CertificateInfo.h"

#include <QByteArray>
#include <QString>
#include <tl/expected.hpp>
#include <vector>

namespace certmgr::platform {

class ICertificateStore {
public:
    virtual ~ICertificateStore() = default;
    virtual tl::expected<std::vector<domain::CertificateInfo>, domain::AppError>
        listCertificates(const domain::CertificateStoreLocation &location) = 0;
    virtual tl::expected<domain::CertificateInfo, domain::AppError>
        inspect(const QString &id) = 0;
    virtual tl::expected<domain::CertificateInfo, domain::AppError>
        decodeCertificate(const QByteArray &encodedCertificate) = 0;
    virtual tl::expected<void, domain::AppError>
        installCertificate(const QByteArray &encodedCertificate,
                           const domain::CertificateStoreLocation &location) = 0;
    virtual tl::expected<void, domain::AppError> removeCertificate(const QString &id) = 0;
};

} // namespace certmgr::platform
