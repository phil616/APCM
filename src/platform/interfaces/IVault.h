#pragma once

#include "../../domain/AppError.h"

#include <QByteArray>
#include <QString>
#include <tl/expected.hpp>

namespace certmgr::platform {

class IVault {
public:
    virtual ~IVault() = default;
    virtual bool exists() const = 0;
    virtual bool isUnlocked() const = 0;
    virtual tl::expected<void, domain::AppError> initialize(const QByteArray &masterPassword) = 0;
    virtual tl::expected<void, domain::AppError> unlock(const QByteArray &masterPassword) = 0;
    virtual void lock() = 0;
};

} // namespace certmgr::platform

