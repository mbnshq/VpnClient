// NovaVPN - Networking/NetworkMonitor.h
// Observation of the machine's real network state: which adapters exist, which
// one carries the default route, and when any of that changes.
//
// The tunnel depends on this for three things:
//   * pinning a host route to the VPN gateway over the physical adapter,
//   * detecting the "laptop moved from Wi-Fi to Ethernet" case that requires a
//     reconnect rather than a silent stall,
//   * knowing when the underlay is genuinely gone so the kill switch can hold
//     instead of thrashing reconnect attempts.
//
// Implemented in Phase 2.
#pragma once

#include <NovaVPN/Core/EventBus.h>
#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Networking/IpAddress.h>

#include <memory>
#include <string>
#include <vector>

namespace nova::net {

enum class AdapterType : u8 {
    Unknown,
    Ethernet,
    WiFi,
    Cellular,
    Loopback,
    /// A NovaVPN tunnel adapter (Wintun). Excluded from underlay selection.
    Tunnel,
    /// Someone else's VPN or virtual adapter.
    Virtual,
};

struct NetworkAdapter {
    /// Windows interface LUID rendered as a string - stable across reboots.
    std::string            id;
    u32                    interfaceIndex = 0;
    u64                    luid = 0;
    std::string            name;         ///< "Ethernet 2"
    std::string            description;  ///< "Intel(R) I225-V"
    AdapterType            type = AdapterType::Unknown;
    bool                   isUp = false;
    bool                   hasDefaultRouteV4 = false;
    bool                   hasDefaultRouteV6 = false;
    u32                    metric = 0;
    u32                    mtu = 0;
    std::vector<IpAddress> addresses;
    std::vector<IpAddress> gateways;
    std::vector<IpAddress> dnsServers;
    /// MAC address, hex, no separators. Empty for adapters without one.
    std::string            physicalAddress;
};

/// Published on the EventBus whenever the adapter set or default route changes.
struct NetworkChangedEvent {
    /// Adapter that now carries the default route, if any.
    std::optional<NetworkAdapter> defaultAdapter;
    bool                          hasInternetV4 = false;
    bool                          hasInternetV6 = false;
};

class INetworkMonitor {
public:
    virtual ~INetworkMonitor() = default;

    /// Begins watching (NotifyIpInterfaceChange / NotifyRouteChange2).
    [[nodiscard]] virtual Status start() = 0;
    virtual void stop() = 0;

    /// Current adapters, including tunnel adapters.
    [[nodiscard]] virtual Result<std::vector<NetworkAdapter>> adapters() const = 0;

    /// The adapter carrying the default route, ignoring tunnel adapters. This
    /// is the "underlay" every VPN-gateway host route is pinned to.
    [[nodiscard]] virtual Result<NetworkAdapter> underlayAdapter(AddressFamily family) const = 0;

    /// True when the machine has a usable path to the internet independent of
    /// any tunnel.
    [[nodiscard]] virtual bool hasUnderlayConnectivity() const = 0;
};

using NetworkMonitorPtr = std::shared_ptr<INetworkMonitor>;

/// Windows implementation backed by GetAdaptersAddresses, GetIpForwardTable2
/// and NotifyIpInterfaceChange/NotifyRouteChange2. Publishes
/// NetworkChangedEvent on `events` (when provided), debounced so that the
/// burst of notifications a media change produces becomes one event.
[[nodiscard]] NetworkMonitorPtr makeNetworkMonitor(std::shared_ptr<EventBus> events);

} // namespace nova::net
