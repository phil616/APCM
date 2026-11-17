#pragma once
#include "../../../domain/AppError.h"
#include <QByteArray>
#include <tl/expected.hpp>

namespace certmgr::platform::windows {
// Only independent-signing Bearer credentials, never CA or leaf private keys.
class SigningCredentialStore {
public:
    static tl::expected<QByteArray, domain::AppError> read(const QString &target);
    static tl::expected<void, domain::AppError> write(const QString &target, const QByteArray &token);
    static tl::expected<void, domain::AppError> remove(const QString &target);
};
}
