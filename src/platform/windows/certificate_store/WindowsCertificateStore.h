#pragma once

#include "../../interfaces/ICertificateStore.h"

namespace certmgr::platform::windows {

class WindowsCertificateStore final : public ICertificateStore {
public:
    static QString nativeStoreName(domain::StoreRole role);
    static bool isPkcs12(const QByteArray &contents);
    tl::expected<std::vector<domain::CertificateInfo>, domain::AppError>
        listCertificates(const domain::CertificateStoreLocation &location) override;
    tl::expected<domain::CertificateInfo, domain::AppError>
        inspect(const QString &id) override;
    tl::expected<domain::CertificateInfo, domain::AppError>
        decodeCertificate(const QByteArray &encodedCertificate) override;
    tl::expected<void, domain::AppError>
        installCertificate(const QByteArray &encodedCertificate,
                           const domain::CertificateStoreLocation &location) override;
    tl::expected<std::vector<domain::CertificateInfo>, domain::AppError>
        inspectPkcs12(const QByteArray &encodedPkcs12, const QString &password);
    tl::expected<std::vector<domain::CertificateInfo>, domain::AppError>
        importPkcs12(const QByteArray &encodedPkcs12, const QString &password,
                     const domain::CertificateStoreLocation &location);
    tl::expected<void, domain::AppError> removeCertificate(const QString &id) override;

};

} // namespace certmgr::platform::windows
