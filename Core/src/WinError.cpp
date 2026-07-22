#include <NovaVPN/Core/WinError.h>

#include <Windows.h>

#include <cstdio>

namespace nova::win {
namespace {

std::string formatMessageForCode(unsigned long code)
{
    LPWSTR buffer = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::string text;
    if (length != 0 && buffer != nullptr) {
        text = toUtf8(std::wstring_view{buffer, length});
        while (!text.empty() && (text.back() == ' ' || text.back() == '\r' || text.back() == '\n')) {
            text.pop_back();
        }
    }
    if (buffer != nullptr) {
        ::LocalFree(buffer);
    }
    if (text.empty()) {
        text = "unrecognised system error";
    }
    return text;
}

std::string hexCode(unsigned long code)
{
    char buffer[16]{};
    std::snprintf(buffer, sizeof(buffer), "0x%08lX", code);
    return std::string{buffer};
}

} // namespace

std::string formatWin32(unsigned long code)
{
    return hexCode(code) + " " + formatMessageForCode(code);
}

std::string formatHresult(HRESULT_t hr)
{
    return hexCode(static_cast<unsigned long>(hr)) +
           " " + formatMessageForCode(static_cast<unsigned long>(hr));
}

ErrorCode classifyWin32(unsigned long code) noexcept
{
    switch (code) {
    case ERROR_SUCCESS:                return ErrorCode::Ok;

    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_SERVICE_DOES_NOT_EXIST:
    case ERROR_NOT_FOUND:              return ErrorCode::NotFound;

    case ERROR_ACCESS_DENIED:
    case ERROR_PRIVILEGE_NOT_HELD:
    case ERROR_ELEVATION_REQUIRED:     return ErrorCode::PermissionDenied;

    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:
    case ERROR_SERVICE_EXISTS:
    case ERROR_OBJECT_ALREADY_EXISTS:  return ErrorCode::AlreadyExists;

    case ERROR_INVALID_PARAMETER:
    case ERROR_INVALID_NAME:
    case ERROR_BAD_ARGUMENTS:          return ErrorCode::InvalidArgument;

    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:            return ErrorCode::OutOfMemory;

    case ERROR_TIMEOUT:
    case ERROR_SEM_TIMEOUT:
    case WAIT_TIMEOUT:                 return ErrorCode::Timeout;

    case ERROR_OPERATION_ABORTED:
    case ERROR_CANCELLED:              return ErrorCode::Cancelled;

    case ERROR_CALL_NOT_IMPLEMENTED:   return ErrorCode::NotImplemented;

    case ERROR_BUSY:
    case ERROR_DEVICE_IN_USE:
    case ERROR_SERVICE_REQUEST_TIMEOUT:return ErrorCode::Unavailable;

    case ERROR_INVALID_STATE:
    case ERROR_SERVICE_ALREADY_RUNNING:
    case ERROR_SERVICE_NOT_ACTIVE:     return ErrorCode::InvalidState;

    case ERROR_NETWORK_UNREACHABLE:
    case ERROR_HOST_UNREACHABLE:
    case ERROR_NETWORK_BUSY:           return ErrorCode::NetworkUnreachable;

    case ERROR_CONNECTION_REFUSED:     return ErrorCode::ConnectionRefused;

    case ERROR_NETNAME_DELETED:
    case ERROR_CONNECTION_ABORTED:
    case ERROR_BROKEN_PIPE:
    case ERROR_PIPE_NOT_CONNECTED:     return ErrorCode::ConnectionReset;

    case ERROR_HANDLE_EOF:
    case ERROR_READ_FAULT:
    case ERROR_WRITE_FAULT:
    case ERROR_DISK_FULL:              return ErrorCode::IoError;

    case ERROR_FILE_CORRUPT:
    case ERROR_CRC:                    return ErrorCode::ChecksumMismatch;

    case ERROR_LOGON_FAILURE:
    case ERROR_INVALID_PASSWORD:
    case ERROR_ACCOUNT_DISABLED:       return ErrorCode::AuthFailed;

    case ERROR_NO_SUCH_DEVICE:
    case ERROR_DEV_NOT_EXIST:          return ErrorCode::AdapterNotFound;

    case ERROR_DRIVER_BLOCKED:
    case ERROR_BAD_DRIVER:
    case ERROR_BAD_DRIVER_LEVEL:       return ErrorCode::DriverMissing;

    default:                           return ErrorCode::Unknown;
    }
}

Status fromWin32(unsigned long code, std::string_view context)
{
    std::string message;
    message.reserve(context.size() + 64);
    message.append(context);
    message.append(" failed: ");
    message.append(formatWin32(code));
    return Status{classifyWin32(code), std::move(message), static_cast<u32>(code)};
}

Status lastError(std::string_view context)
{
    return fromWin32(::GetLastError(), context);
}

Status fromHresult(HRESULT_t hr, std::string_view context)
{
    // Win32 errors wrapped with HRESULT_FROM_WIN32 keep their facility, so we
    // can recover the original code and classify it precisely.
    const auto raw = static_cast<HRESULT>(hr);
    unsigned long win32 = static_cast<unsigned long>(raw);
    if (HRESULT_FACILITY(raw) == FACILITY_WIN32) {
        win32 = static_cast<unsigned long>(HRESULT_CODE(raw));
    }

    std::string message;
    message.reserve(context.size() + 64);
    message.append(context);
    message.append(" failed: ");
    message.append(formatHresult(hr));

    ErrorCode code = classifyWin32(win32);
    if (code == ErrorCode::Unknown && raw == E_INVALIDARG) {
        code = ErrorCode::InvalidArgument;
    }
    return Status{code, std::move(message), static_cast<u32>(raw)};
}

std::wstring toWide(std::string_view utf8)
{
    if (utf8.empty()) {
        return {};
    }
    const int required = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                                               static_cast<int>(utf8.size()), nullptr, 0);
    if (required <= 0) {
        // Fall back to a lossy conversion rather than losing the diagnostic.
        const int lossy = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
                                                static_cast<int>(utf8.size()), nullptr, 0);
        if (lossy <= 0) {
            return {};
        }
        std::wstring out(static_cast<std::size_t>(lossy), L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), out.data(),
                              lossy);
        return out;
    }

    std::wstring out(static_cast<std::size_t>(required), L'\0');
    ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                          static_cast<int>(utf8.size()), out.data(), required);
    return out;
}

std::string toUtf8(std::wstring_view utf16)
{
    if (utf16.empty()) {
        return {};
    }
    const int required = ::WideCharToMultiByte(CP_UTF8, 0, utf16.data(),
                                               static_cast<int>(utf16.size()), nullptr, 0, nullptr,
                                               nullptr);
    if (required <= 0) {
        return {};
    }
    std::string out(static_cast<std::size_t>(required), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, utf16.data(), static_cast<int>(utf16.size()), out.data(),
                          required, nullptr, nullptr);
    return out;
}

} // namespace nova::win
