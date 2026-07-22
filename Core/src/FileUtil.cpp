#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/Handle.h>
#include <NovaVPN/Core/WinError.h>

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <system_error>

namespace nova::file {
namespace {

struct FileHandleTraits {
    using value_type = HANDLE;
    static value_type invalid() noexcept { return INVALID_HANDLE_VALUE; }
    static void close(value_type handle) noexcept { ::CloseHandle(handle); }
};

using FileHandle = win::UniqueResource<FileHandleTraits>;

/// Largest file any NovaVPN component will read into memory in one go. A
/// legitimate .ovpn bundle or config is a few hundred kilobytes; the cap stops
/// a hostile or corrupt path from exhausting the service's working set.
constexpr u64 kMaxInMemoryFile = 64ull * 1024 * 1024;

Result<FileHandle> openForRead(const std::filesystem::path& path)
{
    FileHandle handle{::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (!handle) {
        return win::lastError("CreateFile(" + path.string() + ")");
    }
    return handle;
}

Result<u64> fileSize(HANDLE handle, const std::filesystem::path& path)
{
    LARGE_INTEGER size{};
    if (::GetFileSizeEx(handle, &size) == FALSE) {
        return win::lastError("GetFileSizeEx(" + path.string() + ")");
    }
    return static_cast<u64>(size.QuadPart);
}

Status readInto(HANDLE handle, void* destination, u64 size, const std::filesystem::path& path)
{
    auto* cursor = static_cast<u8*>(destination);
    u64 remaining = size;
    while (remaining > 0) {
        const DWORD chunk = static_cast<DWORD>(std::min<u64>(remaining, 1u << 20));
        DWORD read = 0;
        if (::ReadFile(handle, cursor, chunk, &read, nullptr) == FALSE) {
            return win::lastError("ReadFile(" + path.string() + ")");
        }
        if (read == 0) {
            return err::io("unexpected end of file reading " + path.string());
        }
        cursor += read;
        remaining -= read;
    }
    return Status::ok();
}

/// Writes `contents` to a sibling temp file, flushes it to stable storage and
/// swaps it into place. ReplaceFile is used when the target exists so that its
/// ACL and any file-system attributes survive the update.
Status writeAtomicBytes(const std::filesystem::path& path, const void* data, std::size_t size)
{
    const std::filesystem::path directory = path.parent_path();
    if (!directory.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(directory, ec);
        if (ec && !std::filesystem::is_directory(directory, ec)) {
            return Status{ErrorCode::IoError,
                          "cannot create directory " + directory.string() + ": " + ec.message()};
        }
    }

    std::filesystem::path temp = path;
    temp += L".tmp";

    {
        FileHandle handle{::CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                        FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (!handle) {
            return win::lastError("CreateFile(" + temp.string() + ")");
        }

        const auto* cursor = static_cast<const u8*>(data);
        std::size_t remaining = size;
        while (remaining > 0) {
            const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(remaining, 1u << 20));
            DWORD written = 0;
            if (::WriteFile(handle.get(), cursor, chunk, &written, nullptr) == FALSE) {
                return win::lastError("WriteFile(" + temp.string() + ")");
            }
            cursor += written;
            remaining -= written;
        }

        // Durability: without this the rename can land before the data does.
        if (::FlushFileBuffers(handle.get()) == FALSE) {
            return win::lastError("FlushFileBuffers(" + temp.string() + ")");
        }
    }

    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        if (::ReplaceFileW(path.c_str(), temp.c_str(), nullptr,
                           REPLACEFILE_IGNORE_MERGE_ERRORS | REPLACEFILE_IGNORE_ACL_ERRORS,
                           nullptr, nullptr) == FALSE) {
            const Status status = win::lastError("ReplaceFile(" + path.string() + ")");
            ::DeleteFileW(temp.c_str());
            return status;
        }
    } else if (::MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING |
                                                             MOVEFILE_WRITE_THROUGH) == FALSE) {
        const Status status = win::lastError("MoveFileEx(" + path.string() + ")");
        ::DeleteFileW(temp.c_str());
        return status;
    }

    return Status::ok();
}

} // namespace

bool exists(const std::filesystem::path& path) noexcept
{
    std::error_code ec;
    return std::filesystem::exists(path, ec) && !ec;
}

Result<u64> sizeOf(const std::filesystem::path& path)
{
    NOVA_ASSIGN_OR_RETURN(auto handle, openForRead(path));
    return fileSize(handle.get(), path);
}

Result<std::vector<u8>> readAll(const std::filesystem::path& path)
{
    NOVA_ASSIGN_OR_RETURN(auto handle, openForRead(path));
    NOVA_ASSIGN_OR_RETURN(const u64 size, fileSize(handle.get(), path));

    if (size > kMaxInMemoryFile) {
        return err::invalidArgument("file too large to read into memory: " + path.string());
    }

    std::vector<u8> buffer(static_cast<std::size_t>(size));
    if (size > 0) {
        NOVA_RETURN_IF_ERROR(readInto(handle.get(), buffer.data(), size, path));
    }
    return buffer;
}

Result<std::string> readText(const std::filesystem::path& path)
{
    NOVA_ASSIGN_OR_RETURN(auto bytes, readAll(path));

    std::string text{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    secureZero(bytes.data(), bytes.size());

    // Strip UTF-8 BOM - Notepad-saved .ovpn files routinely carry one and it
    // would otherwise corrupt the first directive.
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF) {
        text.erase(0, 3);
    }

    text.erase(std::remove(text.begin(), text.end(), '\r'), text.end());
    return text;
}

Result<SecureBuffer> readSecure(const std::filesystem::path& path)
{
    NOVA_ASSIGN_OR_RETURN(auto handle, openForRead(path));
    NOVA_ASSIGN_OR_RETURN(const u64 size, fileSize(handle.get(), path));

    if (size > kMaxInMemoryFile) {
        return err::invalidArgument("secret file too large: " + path.string());
    }

    SecureBuffer buffer{static_cast<std::size_t>(size)};
    if (size > 0) {
        NOVA_RETURN_IF_ERROR(readInto(handle.get(), buffer.data(), size, path));
    }
    return buffer;
}

Status writeAtomic(const std::filesystem::path& path, std::span<const u8> contents)
{
    return writeAtomicBytes(path, contents.data(), contents.size_bytes());
}

Status writeAtomicText(const std::filesystem::path& path, std::string_view contents)
{
    return writeAtomicBytes(path, contents.data(), contents.size());
}

Status secureDelete(const std::filesystem::path& path)
{
    if (!nova::file::exists(path)) {
        return Status::ok();
    }

    {
        FileHandle handle{::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (!handle) {
            return win::lastError("CreateFile(" + path.string() + ") for secure delete");
        }

        NOVA_ASSIGN_OR_RETURN(const u64 size, fileSize(handle.get(), path));

        std::vector<u8> zeros(static_cast<std::size_t>(std::min<u64>(size, 1u << 20)), 0);
        u64 remaining = size;
        while (remaining > 0) {
            const DWORD chunk = static_cast<DWORD>(std::min<u64>(remaining, zeros.size()));
            DWORD written = 0;
            if (::WriteFile(handle.get(), zeros.data(), chunk, &written, nullptr) == FALSE) {
                return win::lastError("WriteFile(" + path.string() + ") for secure delete");
            }
            remaining -= written;
        }
        ::FlushFileBuffers(handle.get());
    }

    if (::DeleteFileW(path.c_str()) == FALSE) {
        return win::lastError("DeleteFile(" + path.string() + ")");
    }
    return Status::ok();
}

} // namespace nova::file
