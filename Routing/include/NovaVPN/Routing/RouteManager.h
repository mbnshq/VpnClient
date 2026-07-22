// NovaVPN - Routing/RouteManager.h
// Ownership of the Windows routing table entries NovaVPN creates.
//
// Two invariants drive the design:
//   1. Every route NovaVPN adds is tracked and removed on teardown, including
//      after a crash - the service reconciles its recorded routes against the
//      live table on start. A VPN that leaves a default route behind takes the
//      machine offline, which is the worst failure mode this product has.
//   2. The gateway host route is pinned to the *underlay* adapter before the
//      default route is redirected, otherwise redirecting the default route
//      tears down the very connection carrying the tunnel.
//
// Implemented in Phase 2.
#pragma once

#include <NovaVPN/Core/Json.h>
#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Networking/IpAddress.h>
#include <NovaVPN/Routing/RoutingRules.h>

#include <filesystem>
#include <memory>
#include <vector>

namespace nova::routing {

struct RouteEntry {
    net::IpRange              destination;
    std::optional<net::IpAddress> nextHop; ///< unset = on-link
    u32                       interfaceIndex = 0;
    u32                       metric = 0;
    /// Marks the entry as created by NovaVPN so reconciliation can identify it.
    bool                      owned = true;
};

/// How the default route is captured.
enum class DefaultRouteMode : u8 {
    /// Leave the system default alone (split-tunnel-only setups).
    None,
    /// Add 0.0.0.0/1 + 128.0.0.0/1, the classic OpenVPN technique: it beats the
    /// existing default on longest-prefix without deleting it, so teardown is
    /// safe even if the process dies.
    SplitHalves,
    /// Replace the default route outright with a lower metric.
    Replace,
};

class IRouteManager {
public:
    virtual ~IRouteManager() = default;

    /// Interface bindings. applyPolicy() turns rules into concrete routes, and
    /// for that it must know which interface index each disposition maps to.
    /// The tunnel manager maintains these as tunnels come and go.
    virtual void setUnderlayInterface(u32 interfaceIndex) = 0;
    virtual void setTunnelInterface(const Id& tunnelId, u32 interfaceIndex) = 0;
    virtual void clearTunnelInterface(const Id& tunnelId) = 0;

    /// Pins a host route to `gateway` over the underlay adapter. Must be called
    /// before capturing the default route.
    [[nodiscard]] virtual Status pinGatewayRoute(const net::IpAddress& gateway,
                                                 u32 underlayInterfaceIndex) = 0;

    /// Captures the default route for the tunnel adapter.
    [[nodiscard]] virtual Status captureDefaultRoute(u32 tunnelInterfaceIndex,
                                                     DefaultRouteMode mode,
                                                     AddressFamily family) = 0;

    [[nodiscard]] virtual Status addRoute(const RouteEntry& entry) = 0;
    [[nodiscard]] virtual Status removeRoute(const RouteEntry& entry) = 0;

    /// Applies the IP rules of a policy as concrete routes.
    [[nodiscard]] virtual Status applyPolicy(const RoutingPolicy& policy) = 0;

    /// Removes every route NovaVPN owns. Idempotent; safe to call from an
    /// abnormal-shutdown handler.
    [[nodiscard]] virtual Status removeAllOwnedRoutes() = 0;

    /// Compares the recorded route set against the live table and removes
    /// leftovers from a previous, crashed run. Called during service start.
    [[nodiscard]] virtual Status reconcile() = 0;

    [[nodiscard]] virtual Result<std::vector<RouteEntry>> ownedRoutes() const = 0;
};

using RouteManagerPtr = std::shared_ptr<IRouteManager>;

/// The concrete route set a DefaultRouteMode expands to. Pure - exists so the
/// capture behaviour is unit-testable without touching the live table.
[[nodiscard]] std::vector<RouteEntry> defaultRouteEntries(DefaultRouteMode mode,
                                                          AddressFamily family,
                                                          u32 tunnelInterfaceIndex);

/// Serialisation of the ownership record persisted across crashes.
[[nodiscard]] Json toJson(const RouteEntry& entry);
[[nodiscard]] Result<RouteEntry> routeEntryFromJson(const Json& value);

/// Windows implementation over CreateIpForwardEntry2/DeleteIpForwardEntry2.
/// `recordPath` is the crash-recovery ledger: every owned route is written
/// there before it is created and removed after it is deleted, so reconcile()
/// can always unwind a previous run.
[[nodiscard]] RouteManagerPtr makeRouteManager(std::filesystem::path recordPath);

} // namespace nova::routing
