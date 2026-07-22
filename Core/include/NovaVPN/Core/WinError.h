// NovaVPN - Core/WinError.h
// Bridges Win32/HRESULT/NTSTATUS failures into the nova::Status taxonomy and
// provides the RAII handle wrappers used throughout the Windows-facing modules.
#pragma once

#include <NovaVPN/Core/Status.h>

#include <string>
#include <string_view>

// Avoid pulling <Windows.h> into every translation unit that only needs to
// report an error. The few typedefs we need are declared structurally.
using HRESULT_t = long;

namespace nova::win {

/// Formats a Win32 error code (GetLastError) as "0x00000005 Access is denied."
[[nodiscard]] std::string formatWin32(unsigned long code);

/// Formats an HRESULT the same way.
[[nodiscard]] std::string formatHresult(HRESULT_t hr);

/// Maps a Win32 code onto the closest ErrorCode. Unmapped codes become
/// ErrorCode::Unknown while preserving the raw code in Status::platformCode().
[[nodiscard]] ErrorCode classifyWin32(unsigned long code) noexcept;

/// Builds a Status from GetLastError() with the caller's context prepended:
///   return win::lastError("CreateFile(profiles.db)");
[[nodiscard]] Status lastError(std::string_view context);

/// Builds a Status from an explicit Win32 code.
[[nodiscard]] Status fromWin32(unsigned long code, std::string_view context);

/// Builds a Status from an HRESULT (COM, WinRT, WFP APIs).
[[nodiscard]] Status fromHresult(HRESULT_t hr, std::string_view context);

/// UTF-8 <-> UTF-16 conversion. NovaVPN stores and logs UTF-8 exclusively and
/// converts only at the Windows API boundary.
[[nodiscard]] std::wstring toWide(std::string_view utf8);
[[nodiscard]] std::string toUtf8(std::wstring_view utf16);

} // namespace nova::win

/// Returns a Status built from GetLastError() when `expr` evaluates to FALSE/0.
#define NOVA_WIN32_CHECK(expr, context)                                              \
    do {                                                                             \
        if (!(expr)) {                                                               \
            return ::nova::win::lastError(context);                                  \
        }                                                                            \
    } while (false)

/// Returns a Status when an HRESULT-returning call fails.
#define NOVA_HR_CHECK(expr, context)                                                 \
    do {                                                                             \
        const HRESULT_t nova_hr_ = (expr);                                           \
        if (nova_hr_ < 0) {                                                          \
            return ::nova::win::fromHresult(nova_hr_, context);                      \
        }                                                                            \
    } while (false)
