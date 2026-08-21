#pragma once

#include "../../domain/AppError.h"
#include "../../domain/keys/PrivateKeyInfo.h"

#include <tl/expected.hpp>
#include <vector>

namespace certmgr::platform {

class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;
    virtual tl::expected<std::vector<domain::PrivateKeyInfo>, domain::AppError> listKeys() = 0;
    virtual bool isTpmAvailable() const = 0;
};

} // namespace certmgr::platform

