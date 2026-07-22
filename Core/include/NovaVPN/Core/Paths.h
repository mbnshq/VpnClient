// NovaVPN - Core/Paths.h
// Canonical on-disk layout. Two roots exist and the distinction is a security
// boundary, not a convenience:
//
//   machine root  %ProgramData%\NovaVPN\      - written by the SYSTEM service,
//                                               ACL'd so users cannot modify it
//   user root     %LocalAppData%\NovaVPN\     - written by the UI, per-user
//
// Anything that influences tunnel behaviour (profiles in use, firewall policy,
// split-tunnel rules) lives under the machine root so an unprivileged user
// cannot rewrite it behind the service's back.
#pragma once

#include <NovaVPN/Core/Result.h>

#include <filesystem>

namespace nova::paths {

/// %ProgramData%\NovaVPN
[[nodiscard]] Result<std::filesystem::path> machineRoot();

/// %LocalAppData%\NovaVPN
[[nodiscard]] Result<std::filesystem::path> userRoot();

/// Directory of the running executable.
[[nodiscard]] Result<std::filesystem::path> executableDirectory();

/// Full path of the running executable.
[[nodiscard]] Result<std::filesystem::path> executablePath();

/// <machineRoot>\logs - service, tunnel and firewall logs.
[[nodiscard]] Result<std::filesystem::path> machineLogDirectory();

/// <userRoot>\logs - UI logs.
[[nodiscard]] Result<std::filesystem::path> userLogDirectory();

/// <machineRoot>\profiles - imported .ovpn payloads (encrypted at rest).
[[nodiscard]] Result<std::filesystem::path> profileDirectory();

/// <machineRoot>\novavpn.db - SQLite catalogue.
[[nodiscard]] Result<std::filesystem::path> databasePath();

/// <machineRoot>\config.json - service configuration.
[[nodiscard]] Result<std::filesystem::path> machineConfigPath();

/// <userRoot>\settings.json - UI preferences (theme, language, window state).
[[nodiscard]] Result<std::filesystem::path> userSettingsPath();

/// <machineRoot>\updates - staged update packages.
[[nodiscard]] Result<std::filesystem::path> updateStagingDirectory();

/// Creates `directory` (and parents) if missing.
[[nodiscard]] Status ensureDirectory(const std::filesystem::path& directory);

/// Creates `directory` and restricts it to SYSTEM + Administrators (full) and
/// Users (read/execute). Used for every machine-root directory.
[[nodiscard]] Status ensureProtectedDirectory(const std::filesystem::path& directory);

/// True when `candidate` is inside `root` after both are lexically normalised.
/// Guards against traversal in imported profile names and update payloads.
[[nodiscard]] bool isContainedIn(const std::filesystem::path& root,
                                 const std::filesystem::path& candidate);

/// Strips characters Windows forbids and path separators, so an untrusted
/// display name can safely become a file name.
[[nodiscard]] std::string sanitizeFileName(std::string_view name);

} // namespace nova::paths
