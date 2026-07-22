// NovaVPN - Core/Types.h
// Fundamental value types shared by every module. Nothing here may depend on
// Windows headers so that the type vocabulary stays testable in isolation.
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

namespace nova {

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

/// Steady clock used for durations that must not jump when the wall clock is
/// corrected (connection uptime, reconnect back-off, keepalive timers).
using SteadyClock = std::chrono::steady_clock;
using SteadyTime  = SteadyClock::time_point;

/// Wall clock used for anything persisted or shown to the user.
using SystemClock = std::chrono::system_clock;
using SystemTime  = SystemClock::time_point;

using Milliseconds = std::chrono::milliseconds;
using Seconds      = std::chrono::seconds;

/// Byte counter. VPN sessions can move terabytes, so 64-bit everywhere.
using ByteCount = std::uint64_t;

/// Identifier of a profile, tunnel or rule. Stable across restarts.
/// Formatted as a lowercase RFC 4122 UUID when serialised.
using Id = std::string;

/// Windows process identifier.
using ProcessId = std::uint32_t;

/// A transport protocol usable by a tunnel endpoint.
enum class Transport : std::uint8_t {
    Udp,
    Tcp,
};

/// Address family selector used by routing and leak-protection code.
enum class AddressFamily : std::uint8_t {
    IPv4,
    IPv6,
};

/// Lifecycle of a single tunnel. The UI maps these directly to dashboard
/// states; the service is the sole authority for transitions.
enum class ConnectionState : std::uint8_t {
    Disconnected,   ///< No tunnel, no firewall locks held.
    Resolving,      ///< Resolving remote host names.
    Connecting,     ///< Transport handshake in progress.
    Authenticating, ///< Credentials/certificates being exchanged.
    Configuring,    ///< Adapter, routes, DNS and firewall being applied.
    Connected,      ///< Tunnel is carrying traffic.
    Reconnecting,   ///< Lost the tunnel, back-off retry in progress.
    Disconnecting,  ///< Tearing down; firewall lock still held.
    Faulted,        ///< Stopped by an unrecoverable error.
};

[[nodiscard]] std::string_view toString(ConnectionState state) noexcept;
[[nodiscard]] std::string_view toString(Transport transport) noexcept;
[[nodiscard]] std::string_view toString(AddressFamily family) noexcept;

/// True while the tunnel holds kernel state (adapter/routes/firewall filters)
/// that must be unwound before the process may exit.
[[nodiscard]] constexpr bool holdsNetworkState(ConnectionState state) noexcept
{
    switch (state) {
    case ConnectionState::Configuring:
    case ConnectionState::Connected:
    case ConnectionState::Reconnecting:
    case ConnectionState::Disconnecting:
        return true;
    default:
        return false;
    }
}

/// True for states the user perceives as "working on it".
[[nodiscard]] constexpr bool isTransitional(ConnectionState state) noexcept
{
    switch (state) {
    case ConnectionState::Resolving:
    case ConnectionState::Connecting:
    case ConnectionState::Authenticating:
    case ConnectionState::Configuring:
    case ConnectionState::Reconnecting:
    case ConnectionState::Disconnecting:
        return true;
    default:
        return false;
    }
}

} // namespace nova
