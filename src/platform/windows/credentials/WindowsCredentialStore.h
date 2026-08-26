#pragma once

#include "../../../domain/AppError.h"

#include <QByteArray>
#include <QString>
#include <tl/expected.hpp>

namespace certmgr::platform::windows {

class WindowsCredentialStore final {
public:
    static tl::expected<QByteArray, domain::AppError> read(const QString &targetName);
    static tl::expected<void, domain::AppError> write(const QString &targetName,
                                                       const QByteArray &secret);
    static tl::expected<void, domain::AppError> remove(const QString &targetName);
};

} // namespace certmgr::platform::windows
