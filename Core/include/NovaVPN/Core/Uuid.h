// NovaVPN - Core/Uuid.h
// Identifier generation. Backed by the OS CSPRNG (BCryptGenRandom) rather than
// std::random_device so that profile ids and IPC nonces are unpredictable.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/Status.h>
#include <NovaVPN/Core/Types.h>

#include <array>
#include <span>
#include <string>
#include <string_view>

namespace nova {

/// RFC 4122 version 4 UUID.
class Uuid final {
public:
    Uuid() noexcept = default; ///< Nil UUID.

    /// Cryptographically random UUID. Never returns the nil UUID.
    [[nodiscard]] static Uuid generate();

    /// Parses "550e8400-e29b-41d4-a716-446655440000" (braces optional,
    /// case-insensitive). Returns nullopt-equivalent nil on failure - use
    /// tryParse() when the distinction matters.
    [[nodiscard]] static bool tryParse(std::string_view text, Uuid& out) noexcept;

    [[nodiscard]] bool isNil() const noexcept;

    /// Lowercase canonical form without braces.
    [[nodiscard]] std::string toString() const;

    [[nodiscard]] std::span<const u8, 16> bytes() const noexcept { return m_bytes; }

    friend bool operator==(const Uuid& a, const Uuid& b) noexcept { return a.m_bytes == b.m_bytes; }
    friend bool operator!=(const Uuid& a, const Uuid& b) noexcept { return !(a == b); }

private:
    std::array<u8, 16> m_bytes{};
};

/// Fills `out` with cryptographically secure random bytes.
Status randomBytes(std::span<u8> out) noexcept;

/// Uniform random value in [0, bound) without modulo bias. `bound` must be > 0.
[[nodiscard]] Result<u64> randomBelow(u64 bound) noexcept;

} // namespace nova
