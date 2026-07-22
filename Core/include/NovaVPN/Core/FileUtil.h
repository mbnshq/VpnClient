// NovaVPN - Core/FileUtil.h
// File primitives with the durability guarantees the rest of the product
// assumes. Configuration, profiles and the update manifest are all rewritten
// atomically: a power loss must never leave a half-written policy file that the
// service would then refuse to start on.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/SecureMemory.h>

#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace nova::file {

/// Reads the whole file as bytes.
[[nodiscard]] Result<std::vector<u8>> readAll(const std::filesystem::path& path);

/// Reads the whole file as UTF-8 text, stripping a BOM if present and
/// normalising CRLF to LF (config and .ovpn parsers expect LF).
[[nodiscard]] Result<std::string> readText(const std::filesystem::path& path);

/// Reads a file into locked, self-zeroing memory. Use for private keys and any
/// credential material read off disk.
[[nodiscard]] Result<SecureBuffer> readSecure(const std::filesystem::path& path);

/// Write-to-temp + flush + ReplaceFile. Either the previous contents or the new
/// contents survive a crash; never a mixture.
[[nodiscard]] Status writeAtomic(const std::filesystem::path& path,
                                 std::span<const u8> contents);
[[nodiscard]] Status writeAtomicText(const std::filesystem::path& path,
                                     std::string_view contents);

/// Overwrites the file's bytes before unlinking it. Best effort on SSDs (wear
/// levelling can retain the old blocks) but it defeats casual recovery of a
/// deleted profile.
[[nodiscard]] Status secureDelete(const std::filesystem::path& path);

/// File size in bytes, or an error when the file is missing/unreadable.
[[nodiscard]] Result<u64> sizeOf(const std::filesystem::path& path);

[[nodiscard]] bool exists(const std::filesystem::path& path) noexcept;

} // namespace nova::file
