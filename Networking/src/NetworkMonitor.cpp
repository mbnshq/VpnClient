#include <NovaVPN/Core/Handle.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Networking/NetworkMonitor.h>
#include <NovaVPN/Networking/SockAddr.h>

#include <winsock2.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <mutex>
#include <thread>
#include <unordered_map>

#pragma comment(lib, "iphlpapi.lib")

using nova::logs::Channel;

namespace nova::net {
namespace {

struct EventHandleTraits {
    using value_type = HANDLE;
    static value_type invalid() noexcept { return nullptr; }
    static void close(value_type handle) noexcept { ::CloseHandle(handle); }
};
using EventHandle = win::UniqueResource<EventHandleTraits>;

/// Classifies an adapter from its interface type and driver description.
/// Wintun adapters report IF_TYPE_PROP_VIRTUAL, so the description is what
/// separates "our tunnel" from "someone else's virtual adapter".
AdapterType classify(const IP_ADAPTER_ADDRESSES& adapter)
{
    const std::string description = win::toUtf8(adapter.Description != nullptr
                                                    ? adapter.Description
                                                    : L"");
    const std::string friendly =
        win::toUtf8(adapter.FriendlyName != nullptr ? adapter.FriendlyName : L"");

    if (adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
        return AdapterType::Loopback;
    }
    if (str::contains(str::toLower(description), "wintun") ||
        str::startsWith(str::toLower(friendly), "novavpn")) {
        return AdapterType::Tunnel;
    }

    switch (adapter.IfType) {
    case IF_TYPE_ETHERNET_CSMACD:
        return AdapterType::Ethernet;
    case IF_TYPE_IEEE80211:
        return AdapterType::WiFi;
    case IF_TYPE_WWANPP:
    case IF_TYPE_WWANPP2:
        return AdapterType::Cellular;
    case IF_TYPE_PROP_VIRTUAL:
    case IF_TYPE_TUNNEL:
        return AdapterType::Virtual;
    default:
        return AdapterType::Unknown;
    }
}

std::string formatLuid(u64 luid)
{
    char buffer[24]{};
    std::snprintf(buffer, sizeof(buffer), "%016llx", static_cast<unsigned long long>(luid));
    return std::string{buffer};
}

/// Default-route facts per interface LUID, harvested from the forwarding table
/// in one pass so adapter enumeration stays O(adapters + routes).
struct DefaultRouteFacts {
    bool hasV4 = false;
    bool hasV6 = false;
    u32  bestMetric = 0xFFFFFFFF;
};

Result<std::unordered_map<u64, DefaultRouteFacts>> queryDefaultRoutes()
{
    MIB_IPFORWARD_TABLE2* table = nullptr;
    const NETIO_STATUS status = ::GetIpForwardTable2(AF_UNSPEC, &table);
    if (status != NO_ERROR) {
        return win::fromWin32(status, "GetIpForwardTable2");
    }

    std::unordered_map<u64, DefaultRouteFacts> facts;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPFORWARD_ROW2& row = table->Table[i];
        if (row.DestinationPrefix.PrefixLength != 0) {
            continue; // only 0.0.0.0/0 and ::/0 matter here
        }

        DefaultRouteFacts& entry = facts[row.InterfaceLuid.Value];
        if (row.DestinationPrefix.Prefix.si_family == AF_INET) {
            entry.hasV4 = true;
        } else if (row.DestinationPrefix.Prefix.si_family == AF_INET6) {
            entry.hasV6 = true;
        }
        entry.bestMetric = std::min(entry.bestMetric, static_cast<u32>(row.Metric));
    }

    ::FreeMibTable(table);
    return facts;
}

Result<std::vector<NetworkAdapter>> enumerateAdapters()
{
    // 16 KiB fits a typical machine; the loop covers the race where an adapter
    // appears between the size probe and the real call.
    ULONG size = 16 * 1024;
    std::vector<u8> buffer;
    ULONG status = ERROR_BUFFER_OVERFLOW;

    constexpr ULONG kFlags =
        GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;

    for (int attempt = 0; attempt < 4 && status == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buffer.resize(size);
        status = ::GetAdaptersAddresses(AF_UNSPEC, kFlags, nullptr,
                                        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()),
                                        &size);
    }
    if (status != NO_ERROR) {
        return win::fromWin32(status, "GetAdaptersAddresses");
    }

    NOVA_ASSIGN_OR_RETURN(auto routeFacts, queryDefaultRoutes());

    std::vector<NetworkAdapter> adapters;
    for (const auto* raw = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data());
         raw != nullptr; raw = raw->Next) {
        NetworkAdapter adapter;
        adapter.luid           = raw->Luid.Value;
        adapter.id             = formatLuid(adapter.luid);
        adapter.interfaceIndex = raw->IfIndex != 0 ? raw->IfIndex : raw->Ipv6IfIndex;
        adapter.name  = win::toUtf8(raw->FriendlyName != nullptr ? raw->FriendlyName : L"");
        adapter.description =
            win::toUtf8(raw->Description != nullptr ? raw->Description : L"");
        adapter.type = classify(*raw);
        adapter.isUp = raw->OperStatus == IfOperStatusUp;
        adapter.mtu  = raw->Mtu;

        if (raw->PhysicalAddressLength > 0) {
            adapter.physicalAddress =
                str::toHex(raw->PhysicalAddress, raw->PhysicalAddressLength);
        }

        for (const auto* unicast = raw->FirstUnicastAddress; unicast != nullptr;
             unicast = unicast->Next) {
            if (auto address = fromSockAddr(unicast->Address.lpSockaddr,
                                            unicast->Address.iSockaddrLength);
                address.isOk()) {
                adapter.addresses.push_back(address.value());
            }
        }
        for (const auto* gateway = raw->FirstGatewayAddress; gateway != nullptr;
             gateway = gateway->Next) {
            if (auto address = fromSockAddr(gateway->Address.lpSockaddr,
                                            gateway->Address.iSockaddrLength);
                address.isOk()) {
                adapter.gateways.push_back(address.value());
            }
        }
        for (const auto* dns = raw->FirstDnsServerAddress; dns != nullptr; dns = dns->Next) {
            if (auto address =
                    fromSockAddr(dns->Address.lpSockaddr, dns->Address.iSockaddrLength);
                address.isOk()) {
                adapter.dnsServers.push_back(address.value());
            }
        }

        if (const auto facts = routeFacts.find(adapter.luid); facts != routeFacts.end()) {
            adapter.hasDefaultRouteV4 = facts->second.hasV4;
            adapter.hasDefaultRouteV6 = facts->second.hasV6;
            adapter.metric            = facts->second.bestMetric;
        }

        adapters.push_back(std::move(adapter));
    }
    return adapters;
}

class WindowsNetworkMonitor final : public INetworkMonitor {
public:
    explicit WindowsNetworkMonitor(std::shared_ptr<EventBus> events)
        : m_events(std::move(events))
    {
    }

    ~WindowsNetworkMonitor() override { stop(); }

    Status start() override
    {
        std::lock_guard lock{m_lifecycleMutex};
        if (m_running) {
            return Status::ok();
        }

        m_kickEvent.reset(::CreateEventW(nullptr, FALSE, FALSE, nullptr));
        m_stopEvent.reset(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!m_kickEvent || !m_stopEvent) {
            return win::lastError("CreateEvent(network monitor)");
        }

        // FALSE = no initial callback; the worker publishes a first snapshot
        // itself so subscribers always see one baseline event.
        NETIO_STATUS status = ::NotifyIpInterfaceChange(
            AF_UNSPEC, &WindowsNetworkMonitor::onOsNotification, this, FALSE,
            &m_interfaceNotification);
        if (status != NO_ERROR) {
            return win::fromWin32(status, "NotifyIpInterfaceChange");
        }

        status = ::NotifyRouteChange2(AF_UNSPEC, &WindowsNetworkMonitor::onOsRouteNotification,
                                      this, FALSE, &m_routeNotification);
        if (status != NO_ERROR) {
            ::CancelMibChangeNotify2(m_interfaceNotification);
            m_interfaceNotification = nullptr;
            return win::fromWin32(status, "NotifyRouteChange2");
        }

        m_running = true;
        m_worker  = std::thread{[this] { workerLoop(); }};

        NOVA_LOG_INFO(Channel::Network, "network monitor started");
        return Status::ok();
    }

    void stop() override
    {
        std::lock_guard lock{m_lifecycleMutex};
        if (!m_running) {
            return;
        }

        // Cancel OS callbacks first: CancelMibChangeNotify2 blocks until any
        // in-flight callback returns, so after this point nothing can touch
        // the events the worker is about to close.
        if (m_interfaceNotification != nullptr) {
            ::CancelMibChangeNotify2(m_interfaceNotification);
            m_interfaceNotification = nullptr;
        }
        if (m_routeNotification != nullptr) {
            ::CancelMibChangeNotify2(m_routeNotification);
            m_routeNotification = nullptr;
        }

        ::SetEvent(m_stopEvent.get());
        if (m_worker.joinable()) {
            m_worker.join();
        }

        m_running = false;
        NOVA_LOG_INFO(Channel::Network, "network monitor stopped");
    }

    Result<std::vector<NetworkAdapter>> adapters() const override
    {
        return enumerateAdapters();
    }

    Result<NetworkAdapter> underlayAdapter(AddressFamily family) const override
    {
        NOVA_ASSIGN_OR_RETURN(auto all, enumerateAdapters());
        return pickUnderlay(all, family);
    }

    bool hasUnderlayConnectivity() const override
    {
        auto all = enumerateAdapters();
        if (all.isError()) {
            return false;
        }
        return pickUnderlay(all.value(), AddressFamily::IPv4).isOk() ||
               pickUnderlay(all.value(), AddressFamily::IPv6).isOk();
    }

private:
    static Result<NetworkAdapter> pickUnderlay(const std::vector<NetworkAdapter>& adapters,
                                               AddressFamily family)
    {
        // The underlay is the real path to the internet: up, physical (never a
        // tunnel - selecting our own adapter here would route the tunnel
        // through itself), carrying a default route, lowest metric wins.
        const NetworkAdapter* best = nullptr;
        for (const auto& adapter : adapters) {
            if (!adapter.isUp || adapter.type == AdapterType::Tunnel ||
                adapter.type == AdapterType::Loopback) {
                continue;
            }
            const bool hasRoute = family == AddressFamily::IPv4 ? adapter.hasDefaultRouteV4
                                                                : adapter.hasDefaultRouteV6;
            if (!hasRoute) {
                continue;
            }
            if (best == nullptr || adapter.metric < best->metric) {
                best = &adapter;
            }
        }
        if (best == nullptr) {
            return err::notFound(std::string{"no underlay adapter with a default "} +
                                 (family == AddressFamily::IPv4 ? "IPv4" : "IPv6") + " route");
        }
        return *best;
    }

    static VOID WINAPI onOsNotification(PVOID context, PMIB_IPINTERFACE_ROW row,
                                        MIB_NOTIFICATION_TYPE type)
    {
        (void)row;
        (void)type;
        auto* self = static_cast<WindowsNetworkMonitor*>(context);
        ::SetEvent(self->m_kickEvent.get());
    }

    static VOID WINAPI onOsRouteNotification(PVOID context, PMIB_IPFORWARD_ROW2 row,
                                             MIB_NOTIFICATION_TYPE type)
    {
        (void)row;
        (void)type;
        auto* self = static_cast<WindowsNetworkMonitor*>(context);
        ::SetEvent(self->m_kickEvent.get());
    }

    void workerLoop()
    {
        ::SetThreadDescription(::GetCurrentThread(), L"NovaVPN.NetworkMonitor");

        // Baseline event so a subscriber never has to poll for the initial state.
        publishSnapshot();

        const HANDLE waits[2] = {m_stopEvent.get(), m_kickEvent.get()};
        while (true) {
            const DWORD woke = ::WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (woke != WAIT_OBJECT_0 + 1) {
                return; // stop, or an error there is no way to recover from
            }

            // Debounce: media changes arrive as a burst of interface + route
            // notifications. Absorb the burst, then publish once.
            while (::WaitForSingleObject(m_stopEvent.get(), 400) == WAIT_TIMEOUT) {
                if (::WaitForSingleObject(m_kickEvent.get(), 0) != WAIT_OBJECT_0) {
                    break; // quiet for a full window
                }
            }
            if (::WaitForSingleObject(m_stopEvent.get(), 0) == WAIT_OBJECT_0) {
                return;
            }

            publishSnapshot();
        }
    }

    void publishSnapshot()
    {
        auto all = enumerateAdapters();
        if (all.isError()) {
            NOVA_LOG_WARN(Channel::Network, "adapter enumeration failed")
                .status(all.status());
            return;
        }

        NetworkChangedEvent event;
        if (auto v4 = pickUnderlay(all.value(), AddressFamily::IPv4); v4.isOk()) {
            event.hasInternetV4  = true;
            event.defaultAdapter = std::move(v4).value();
        }
        if (auto v6 = pickUnderlay(all.value(), AddressFamily::IPv6); v6.isOk()) {
            event.hasInternetV6 = true;
            if (!event.defaultAdapter.has_value()) {
                event.defaultAdapter = std::move(v6).value();
            }
        }

        NOVA_LOG_DEBUG(Channel::Network, "network state")
            .field("internetV4", event.hasInternetV4)
            .field("internetV6", event.hasInternetV6)
            .field("underlay", event.defaultAdapter.has_value() ? event.defaultAdapter->name
                                                                : std::string{"<none>"});

        if (m_events) {
            m_events->publish(event);
        }
    }

    std::shared_ptr<EventBus> m_events;
    std::mutex                m_lifecycleMutex;
    bool                      m_running = false;
    HANDLE                    m_interfaceNotification = nullptr;
    HANDLE                    m_routeNotification = nullptr;
    EventHandle               m_kickEvent;
    EventHandle               m_stopEvent;
    std::thread               m_worker;
};

} // namespace

NetworkMonitorPtr makeNetworkMonitor(std::shared_ptr<EventBus> events)
{
    return std::make_shared<WindowsNetworkMonitor>(std::move(events));
}

} // namespace nova::net
