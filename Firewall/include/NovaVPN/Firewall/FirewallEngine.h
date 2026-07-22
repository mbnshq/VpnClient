// NovaVPN - Firewall/FirewallEngine.h
// Windows Filtering Platform policy: kill switch, leak protection and the
// enforcement half of split tunnelling.
//
// Everything NovaVPN adds lives in one WFP provider and one sublayer, both
// registered with a fixed GUID. That gives three properties the product needs:
//   * every filter is attributable to NovaVPN and removable in one sweep,
//   * filters can be *persistent*, surviving a reboot, so a hard kill switch
//     still holds if the machine restarts while connected,
//   * a crashed service leaves a known, greppable state that the next start
//     reconciles rather than an anonymous pile of filters.
//
// Ordering matters: the block-all filters must exist *before* the tunnel starts
// and be removed *after* it is fully down, so there is no window where traffic
// can escape. The engine enforces this with an explicit transaction.
//
// Implemented in Phase 6.
#pragma once

#include <NovaVPN/Core/Cancellation.h>
#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Networking/IpAddress.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nova::firewall {

/// How aggressively traffic is confined to the tunnel.
enum class KillSwitchMode : u8 {
    /// No filters. Traffic falls back to the ISP if the tunnel drops.
    Off,
    /// Block non-tunnel traffic only while a tunnel is up or reconnecting.
    /// Releases automatically when the user disconnects.
    Soft,
    /// Block non-tunnel traffic from the moment the client starts until the
    /// user explicitly disables it, including across reboots and crashes.
    Hard,
};

[[nodiscard]] std::string_view toString(KillSwitchMode mode) noexcept;
[[nodiscard]] bool parseKillSwitchMode(std::string_view text, KillSwitchMode& out) noexcept;

/// Exceptions punched through the block-all policy. Each is a deliberate
/// trade-off and is surfaced in the UI with its consequence spelled out.
struct FirewallExceptions {
    /// Loopback traffic. Blocking it breaks most local development tooling.
    bool allowLoopback = true;
    /// DHCP to/from the local segment. Without it the machine loses its lease
    /// and therefore its internet access after a while.
    bool allowDhcp = true;
    /// RFC 1918 destinations - printers, NAS, router admin pages.
    bool allowLan = false;
    /// mDNS/LLMNR/SSDP discovery on the local segment.
    bool allowLocalDiscovery = false;
    /// IPv6 entirely. Blocking is the default because a v6 leak around a
    /// v4-only tunnel is the single most common VPN leak.
    bool allowIpv6 = false;
    /// Extra destinations that must stay reachable (captive portal, corporate
    /// split-DNS, licence servers).
    std::vector<net::IpRange> allowedDestinations;
    /// Applications permitted to bypass the kill switch entirely. Empty by
    /// default; every entry is a hole and is logged as such.
    std::vector<std::string>  bypassApplications;
};

/// The complete firewall policy for the current moment.
struct FirewallPolicy {
    KillSwitchMode     mode = KillSwitchMode::Soft;
    FirewallExceptions exceptions;
    /// Interface LUIDs traffic is permitted on (the tunnel adapters).
    std::vector<u64>   permittedInterfaceLuids;
    /// The VPN server endpoints that must remain reachable over the underlay,
    /// otherwise the tunnel could never re-establish under a hard kill switch.
    std::vector<net::Endpoint> vpnEndpoints;
    /// Survive reboots (WFP persistent filters). Requires mode == Hard.
    bool               persistent = false;
    /// Block plaintext DNS to anything but the tunnel's resolvers.
    bool               enforceDnsLeakProtection = true;
    /// Block the UDP/TCP ports WebRTC uses to discover host candidates outside
    /// the tunnel. Narrow by design: it targets STUN/TURN, not all UDP.
    bool               blockWebRtcLeaks = true;
};

/// A filter NovaVPN owns, as reported by the engine for diagnostics.
struct FilterInfo {
    u64         id = 0;
    std::string name;
    std::string layer;
    u32         weight = 0;
    bool        persistent = false;
};

class IFirewallEngine {
public:
    virtual ~IFirewallEngine() = default;

    /// Opens the WFP engine session and registers the NovaVPN provider and
    /// sublayer if they do not exist.
    [[nodiscard]] virtual Status open() = 0;
    virtual void close() = 0;

    /// Applies `policy` in a single WFP transaction: either every filter lands
    /// or none do, so a partial policy can never leave a leak.
    [[nodiscard]] virtual Status apply(const FirewallPolicy& policy) = 0;

    /// Removes every NovaVPN filter, including persistent ones.
    [[nodiscard]] virtual Status clear() = 0;

    /// Removes filters left behind by a crashed run, matching on the provider
    /// GUID. Called during service start, before any tunnel is created.
    [[nodiscard]] virtual Status reconcile() = 0;

    [[nodiscard]] virtual Result<std::vector<FilterInfo>> activeFilters() const = 0;
    [[nodiscard]] virtual bool isEngaged() const = 0;

    /// Current effective policy, for the UI's firewall panel.
    [[nodiscard]] virtual std::optional<FirewallPolicy> currentPolicy() const = 0;
};

using FirewallEnginePtr = std::shared_ptr<IFirewallEngine>;

/// Active leak detection. Runs probes that deliberately try to escape the
/// tunnel and reports anything that succeeds.
struct LeakTestResult {
    bool                   dnsLeak = false;
    bool                   ipv6Leak = false;
    bool                   webRtcLeak = false;
    /// Resolver addresses observed answering our probes.
    std::vector<net::IpAddress> observedResolvers;
    /// Public address seen by the probe endpoint.
    std::optional<net::IpAddress> observedPublicAddress;
    std::vector<std::string> details;
};

class ILeakTester {
public:
    virtual ~ILeakTester() = default;
    [[nodiscard]] virtual Result<LeakTestResult> run(const CancellationToken& token) = 0;
};

} // namespace nova::firewall
