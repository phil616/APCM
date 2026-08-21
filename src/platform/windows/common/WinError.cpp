#include "WinError.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace certmgr::platform::windows {

domain::AppError winError(const domain::ErrorCategory category,
                          QString code,
                          const quint64 nativeCode,
                          QString fallbackMessage,
                          QString details)
{
    wchar_t *buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, static_cast<DWORD>(nativeCode), 0, reinterpret_cast<wchar_t *>(&buffer), 0, nullptr);
    QString message = length ? QString::fromWCharArray(buffer, static_cast<qsizetype>(length)).trimmed()
                             : std::move(fallbackMessage);
    if (buffer) LocalFree(buffer);
    return {category, std::move(code), nativeCode, std::move(message), std::move(details)};
}

} // namespace certmgr::platform::windows

