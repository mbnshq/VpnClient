// NovaVPN - Core/DataProtection.h
// DPAPI wrapper for sealing data at rest.
//
// Used to encrypt the verbatim .ovpn source and any at-rest blob that must be
// recoverable by the service without a user password. Machine scope means the
// SYSTEM service can unseal it after a reboot; the trade-off - anyone who can
// run code as SYSTEM on this machine can unseal it too - is acceptable because
// such an attacker has already lost the game (see docs/SECURITY.md threat
// model). An optional entropy argument binds the ciphertext to a caller-chosen
// secret so two blobs sealed by the same machine are not interchangeable.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/SecureMemory.h>

#include <span>
#include <vector>

namespace nova::crypto {

/// Seals `plaintext` with DPAPI at the requested scope.
enum class ProtectionScope : u8 {
    /// Recoverable by any process on this machine. Used by the service for
    /// profile blobs, since the service runs as SYSTEM with no user context.
    Machine,
    /// Recoverable only by the current user. Used for user-scope UI data.
    User,
};

/// Encrypts `plaintext`, optionally bound to `entropy`. The result is opaque
/// ciphertext safe to store in the database or on disk.
[[nodiscard]] Result<std::vector<u8>> seal(std::span<const u8> plaintext, ProtectionScope scope,
                                           std::span<const u8> entropy = {});

/// Convenience overload for text (a .ovpn source is UTF-8 text).
[[nodiscard]] Result<std::vector<u8>> seal(std::string_view plaintext, ProtectionScope scope,
                                           std::span<const u8> entropy = {});

/// Decrypts what seal() produced, into locked memory. The same `entropy` used
/// to seal must be supplied, or unsealing fails.
[[nodiscard]] Result<SecureBuffer> unseal(std::span<const u8> ciphertext,
                                          std::span<const u8> entropy = {});

} // namespace nova::crypto
