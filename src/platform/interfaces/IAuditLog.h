#pragma once

#include "../../domain/AppError.h"

#include <QDateTime>
#include <QString>
#include <tl/expected.hpp>

namespace certmgr::platform {

struct AuditEvent {
    QDateTime timestamp;
    QString action;
    QString target;
    QString scope;
    QString result;
    QString error;
};

class IAuditLog {
public:
    virtual ~IAuditLog() = default;
    virtual tl::expected<void, domain::AppError> append(const AuditEvent &event) = 0;
};

} // namespace certmgr::platform

