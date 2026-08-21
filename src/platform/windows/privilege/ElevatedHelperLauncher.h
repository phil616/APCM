#pragma once

#include "../../../domain/AppError.h"
#include "../../../domain/certificate/CertificateInfo.h"
#include "../../interfaces/IEnrollmentBackend.h"

#include <QString>
#include <QStringList>
#include <tl/expected.hpp>

namespace certmgr::platform::windows {

class ElevatedHelperLauncher {
public:
    tl::expected<platform::GeneratedEnrollment, domain::AppError>
        createMachinePkcs10(const domain::CertificateTemplate &certificateTemplate) const;
    tl::expected<void, domain::AppError> installMachineRoot(const QString &certificatePath,
                                                           const QString &sha256Fingerprint) const;
    tl::expected<void, domain::AppError> installMachineCertificate(const QString &certificatePath,
        const QString &sha256Fingerprint, domain::StoreRole role) const;
    tl::expected<void, domain::AppError> installMachineCertificatePackage(const QString &certificatePath,
        const QStringList &sha256Fingerprints, domain::StoreRole role) const;
    tl::expected<void, domain::AppError> importMachinePkcs12(const QString &certificatePath,
        const QString &password, domain::StoreRole role) const;
    tl::expected<void, domain::AppError> installMachineEnrollmentResponse(
        const QString &certificatePath, const QString &sha256Fingerprint,
        const QString &providerName, const QString &keyContainerName,
        const QString &friendlyName) const;

private:
    tl::expected<void, domain::AppError> runWhitelisted(const QString &command,
                                                       const QStringList &arguments) const;
};

} // namespace certmgr::platform::windows
