// NovaVPN - Tunnel/Tunnel.h
// The tunnel abstraction and its lifecycle.
//
// A Tunnel owns exactly one virtual adapter, one engine session and the network
// state (routes, DNS, firewall filters) that belongs to it. Multi-VPN is simply
// several Tunnels alive at once, each with its own adapter and its own slice of
// the routing policy - which is why nothing in this interface is a singleton.
//
// State transitions are the only way tunnel state changes, and only the service
// may drive them. The UI observes; it never mutates.
//
// Implemented in Phase 3.
#pragma once

#include <NovaVPN/Core/Cancellation.h>
#include <NovaVPN/Core/EventBus.h>
#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/SecureMemory.h>
#include <NovaVPN/Networking/IpAddress.h>
#include <NovaVPN/Networking/Statistics.h>
#include <NovaVPN/Profiles/Profile.h>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nova::tunnel {

// Engine.h includes this header, so the engine registry is forward-declared
// here to break the cycle; the manager only needs the pointer type.
class IEngineRegistry;
using EngineRegistryPtr = std::shared_ptr<IEngineRegistry>;

/// Credentials supplied for one connection attempt. Held only for the duration
/// of the handshake and zeroed immediately afterwards.
struct ConnectCredentials {
    std::string  userName;
    SecureString password;
    SecureString totpCode;
    SecureString privateKeyPassphrase;
};

/// What the engine asks the user for mid-handshake.
enum class ChallengeKind : u8 {
    UserPassword,
    Totp,
    PrivateKeyPassphrase,
    /// Server-driven static or dynamic challenge (CRV1).
    ServerChallenge,
};

struct AuthChallenge {
    ChallengeKind kind = ChallengeKind::UserPassword;
    std::string   prompt;
    /// False when the answer should be masked in the UI.
    bool          echo = false;
    Id            tunnelId;
};

/// Everything the server pushed plus what we negotiated. Populated once the
/// tunnel reaches Connected and shown on the dashboard.
struct TunnelSessionInfo {
    net::IpRange                localAddress;      ///< Address assigned to us.
    std::optional<net::IpRange> localAddressV6;
    std::optional<net::IpAddress> serverVirtualIp;
    net::Endpoint               remoteEndpoint;    ///< Actual server we reached.
    std::vector<net::IpAddress> dnsServers;
    std::vector<std::string>    searchDomains;
    std::vector<net::IpRange>   pushedRoutes;
    u32                         mtu = 0;
    std::string                 cipher;            ///< e.g. "AES-256-GCM"
    std::string                 authDigest;
    std::string                 tlsVersion;
    std::string                 peerCertificateSubject;
    std::string                 peerCertificateFingerprint;
    SystemTime                  connectedAt{};
    u32                         adapterInterfaceIndex = 0;
};

/// Published on the EventBus whenever a tunnel changes state.
struct TunnelStateChanged {
    Id              tunnelId;
    Id              profileId;
    ConnectionState previous = ConnectionState::Disconnected;
    ConnectionState current  = ConnectionState::Disconnected;
    /// Set when `current` is Faulted or Reconnecting.
    Status          reason;
    /// Attempt number within the current connect sequence, 1-based.
    u32             attempt = 0;
};

class ITunnel {
public:
    virtual ~ITunnel() = default;

    [[nodiscard]] virtual const Id& id() const noexcept = 0;
    [[nodiscard]] virtual const Id& profileId() const noexcept = 0;
    [[nodiscard]] virtual ConnectionState state() const noexcept = 0;

    /// Valid only while state() == Connected.
    [[nodiscard]] virtual std::optional<TunnelSessionInfo> sessionInfo() const = 0;

    /// Latest counters and quality metrics.
    [[nodiscard]] virtual net::StatisticsSample statistics() const = 0;

    /// Time since the tunnel entered Connected, zero otherwise.
    [[nodiscard]] virtual Seconds uptime() const = 0;

    /// Starts connecting. Returns as soon as the attempt is scheduled; progress
    /// arrives as TunnelStateChanged events.
    [[nodiscard]] virtual Status connect(ConnectCredentials credentials) = 0;

    /// Requests a graceful disconnect. Network state is unwound before the
    /// tunnel reports Disconnected, so a kill switch never releases early.
    [[nodiscard]] virtual Status disconnect() = 0;

    /// Forces a reconnect (used by the network monitor when the underlay
    /// changes, and by the user's "reconnect" button).
    [[nodiscard]] virtual Status reconnect() = 0;

    /// Supplies the answer to a pending AuthChallenge.
    [[nodiscard]] virtual Status answerChallenge(ChallengeKind kind, SecureString answer) = 0;
};

using TunnelPtr = std::shared_ptr<ITunnel>;

/// Owns every tunnel and enforces the global constraints: the concurrent-tunnel
/// limit, adapter-name allocation and the ordering rules between firewall,
/// routing and tunnel teardown.
class ITunnelManager {
public:
    virtual ~ITunnelManager() = default;

    [[nodiscard]] virtual Result<TunnelPtr> create(const profiles::Profile& profile) = 0;
    [[nodiscard]] virtual Result<TunnelPtr> find(const Id& tunnelId) const = 0;
    [[nodiscard]] virtual std::vector<TunnelPtr> all() const = 0;

    /// Disconnects and destroys the tunnel, releasing its adapter.
    [[nodiscard]] virtual Status destroy(const Id& tunnelId) = 0;

    /// Disconnects everything, in the order required to avoid a leak window.
    [[nodiscard]] virtual Status disconnectAll() = 0;

    /// The tunnel that unmatched traffic uses.
    [[nodiscard]] virtual Result<TunnelPtr> primary() const = 0;
    [[nodiscard]] virtual Status setPrimary(const Id& tunnelId) = 0;
};

using TunnelManagerPtr = std::shared_ptr<ITunnelManager>;

/// Dependencies the tunnel manager orchestrates. Any may be null in a reduced
/// configuration (tests), in which case the corresponding step is skipped.
struct TunnelManagerDeps {
    EngineRegistryPtr        engines;
    std::shared_ptr<EventBus> events;
    /// Optional: applied when a session is established / torn down. Left as a
    /// forward reference so Tunnel does not depend on Routing's concrete types.
    std::function<void(const Id& tunnelId, const TunnelSessionInfo&)> onSessionUp;
    std::function<void(const Id& tunnelId)>                           onSessionDown;
    /// Global connection defaults (reconnect policy, timeouts).
    bool                     autoReconnect = true;
    u32                      maxConcurrentTunnels = 4;
};

/// Creates the standard tunnel manager.
[[nodiscard]] TunnelManagerPtr makeTunnelManager(TunnelManagerDeps deps);

} // namespace nova::tunnel
