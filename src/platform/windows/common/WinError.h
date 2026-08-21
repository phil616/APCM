#pragma once

#include "../../../domain/AppError.h"

#include <QString>

namespace certmgr::platform::windows {

domain::AppError winError(domain::ErrorCategory category,
                          QString code,
                          quint64 nativeCode,
                          QString fallbackMessage,
                          QString details = {});

} // namespace certmgr::platform::windows

