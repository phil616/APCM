#pragma once

#include "../../interfaces/IKeyProvider.h"

namespace certmgr::platform::windows {

class WindowsCngKeyProvider final : public IKeyProvider {
public:
    tl::expected<std::vector<domain::PrivateKeyInfo>, domain::AppError> listKeys() override;
    bool isTpmAvailable() const override;
};

} // namespace certmgr::platform::windows

