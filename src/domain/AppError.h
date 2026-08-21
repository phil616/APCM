#pragma once

#include <QString>

namespace certmgr::domain {

enum class ErrorCategory {
    General,
    CertificateStore,
    ChainValidation,
    KeyProvider,
    Enrollment,
    Vault,
    Validation,
    Permission,
    Network
};

struct AppError {
    ErrorCategory category{ErrorCategory::General};
    QString code;
    quint64 nativeCode{0};
    QString message;
    QString details;
};

} // namespace certmgr::domain

