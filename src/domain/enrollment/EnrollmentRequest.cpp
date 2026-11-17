#include "EnrollmentRequest.h"

namespace certmgr::domain {

QString enrollmentStateName(const EnrollmentState state)
{
    switch (state) {
    case EnrollmentState::Draft: return QStringLiteral("DRAFT");
    case EnrollmentState::KeyCreated: return QStringLiteral("KEY_CREATED");
    case EnrollmentState::CsrCreated: return QStringLiteral("CSR_CREATED");
    case EnrollmentState::Submitted: return QStringLiteral("SUBMITTED");
    case EnrollmentState::Pending: return QStringLiteral("PENDING");
    case EnrollmentState::Issued: return QStringLiteral("ISSUED");
    case EnrollmentState::Installed: return QStringLiteral("INSTALLED");
    case EnrollmentState::Denied: return QStringLiteral("DENIED");
    case EnrollmentState::Failed: return QStringLiteral("FAILED");
    case EnrollmentState::Revoked: return QStringLiteral("REVOKED");
    }
    return QStringLiteral("UNKNOWN");
}

QByteArray encodeCsrPem(const QByteArray &der)
{
    if (der.isEmpty()) return {};
    const QByteArray base64 = der.toBase64();
    QByteArray pem("-----BEGIN CERTIFICATE REQUEST-----\n");
    for (qsizetype offset = 0; offset < base64.size(); offset += 64) {
        pem.append(base64.mid(offset, 64));
        pem.append('\n');
    }
    pem.append("-----END CERTIFICATE REQUEST-----\n");
    return pem;
}

} // namespace certmgr::domain

