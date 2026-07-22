#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Networking/SockAddr.h>
#include <NovaVPN/Routing/RouteManager.h>

#include <winsock2.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <algorithm>
#include <mutex>
#include <unordered_map>

#pragma comment(lib, "iphlpapi.lib")

using nova::logs::Channel;

namespace nova::routing {
namespace {

/// Metric for routes NovaVPN pins. Zero rides on top of the interface metric,
/// which is exactly the "most specific + cheapest" position a VPN route needs.
constexpr u32 kOwnedRouteMetric = 0;

Result<MIB_IPFORWARD_ROW2> toRow(const RouteEntry& entry)
{
    MIB_IPFORWARD_ROW2 row;
    ::InitializeIpForwardEntry(&row);

    row.InterfaceIndex = entry.interfaceIndex;
    row.DestinationPrefix.Prefix       = net::toSockAddr(entry.destination.network());
    row.DestinationPrefix.PrefixLength = entry.destination.prefixLength();

    if (entry.nextHop.has_value()) {
        if (entry.nextHop->family() != entry.destination.family()) {
            return err::invalidArgument("route next hop family does not match destination " +
                                        entry.destination.toString());
        }
        row.NextHop = net::toSockAddr(*entry.nextHop);
    } else {
        // On-link: an all-zero next hop with the family still set.
        row.NextHop = net::toSockAddr(entry.destination.family() == AddressFamily::IPv4
                                          ? net::IpAddress::anyV4()
                                          : net::IpAddress::anyV6());
    }

    row.Metric   = entry.metric;
    row.Protocol = MIB_IPPROTO_NETMGMT; // marks the entry as administratively created
    return row;
}

std::string routeKey(const RouteEntry& entry)
{
    return entry.destination.toString() + "@" + std::to_string(entry.interfaceIndex);
}

class WindowsRouteManager final : public IRouteManager {
public:
    explicit WindowsRouteManager(std::filesystem::path recordPath)
        : m_recordPath(std::move(recordPath))
    {
        loadRecord();
    }

    // --- interface bindings ------------------------------------------------

    void setUnderlayInterface(u32 interfaceIndex) override
    {
        std::lock_guard lock{m_mutex};
        m_underlayInterface = interfaceIndex;
    }

    void setTunnelInterface(const Id& tunnelId, u32 interfaceIndex) override
    {
        std::lock_guard lock{m_mutex};
        m_tunnelInterfaces[tunnelId] = interfaceIndex;
    }

    void clearTunnelInterface(const Id& tunnelId) override
    {
        std::lock_guard lock{m_mutex};
        m_tunnelInterfaces.erase(tunnelId);
    }

    // --- gateway pin and default capture -----------------------------------

    Status pinGatewayRoute(const net::IpAddress& gateway, u32 underlayInterfaceIndex) override
    {
        // Ask the stack how it reaches the gateway *today, on that interface* -
        // that yields the next hop the pinned host route must keep using after
        // the default route moves into the tunnel.
        SOCKADDR_INET destination = net::toSockAddr(gateway);
        MIB_IPFORWARD_ROW2 best{};
        SOCKADDR_INET bestSource{};

        const NETIO_STATUS status = ::GetBestRoute2(nullptr, underlayInterfaceIndex, nullptr,
                                                    &destination, 0, &best, &bestSource);
        if (status != NO_ERROR) {
            return win::fromWin32(status,
                                  "GetBestRoute2(" + gateway.toString() + ")");
        }

        RouteEntry entry;
        NOVA_ASSIGN_OR_RETURN(entry.destination,
                              net::IpRange::make(gateway, gateway.isV4() ? 32 : 128));
        entry.interfaceIndex = underlayInterfaceIndex;
        entry.metric         = kOwnedRouteMetric;

        if (auto nextHop = net::fromSockAddr(best.NextHop);
            nextHop.isOk() && !nextHop.value().isUnspecified()) {
            entry.nextHop = nextHop.value();
        }

        NOVA_LOG_INFO(Channel::Routing, "pinning gateway route")
            .field("gateway", gateway.toString())
            .field("interface", underlayInterfaceIndex)
            .field("nextHop", entry.nextHop.has_value() ? entry.nextHop->toString()
                                                        : std::string{"on-link"});
        return addRoute(entry);
    }

    Status captureDefaultRoute(u32 tunnelInterfaceIndex, DefaultRouteMode mode,
                               AddressFamily family) override
    {
        const auto entries = defaultRouteEntries(mode, family, tunnelInterfaceIndex);
        for (const auto& entry : entries) {
            NOVA_RETURN_IF_ERROR(
                addRoute(entry).withContext("capturing the default route"));
        }
        if (!entries.empty()) {
            NOVA_LOG_INFO(Channel::Routing, "default route captured")
                .field("interface", tunnelInterfaceIndex)
                .field("family", std::string{nova::toString(family)})
                .field("routes", static_cast<u64>(entries.size()));
        }
        return Status::ok();
    }

    // --- raw route operations ----------------------------------------------

    Status addRoute(const RouteEntry& entry) override
    {
        NOVA_ASSIGN_OR_RETURN(auto row, toRow(entry));

        // Record BEFORE creating: if the process dies between the two, the
        // worst case is a recorded route that does not exist, which reconcile
        // handles for free. The opposite order would leak a live route.
        NOVA_RETURN_IF_ERROR(recordRoute(entry));

        const NETIO_STATUS status = ::CreateIpForwardEntry2(&row);
        if (status != NO_ERROR && status != ERROR_OBJECT_ALREADY_EXISTS) {
            (void)unrecordRoute(entry);
            const Status failure =
                win::fromWin32(status, "CreateIpForwardEntry2(" +
                                            entry.destination.toString() + ")");
            return Status{failure.code() == ErrorCode::PermissionDenied
                              ? ErrorCode::PermissionDenied
                              : ErrorCode::RouteApplyFailed,
                          failure.message(), failure.platformCode()};
        }
        return Status::ok();
    }

    Status removeRoute(const RouteEntry& entry) override
    {
        NOVA_ASSIGN_OR_RETURN(auto row, toRow(entry));

        const NETIO_STATUS status = ::DeleteIpForwardEntry2(&row);
        if (status != NO_ERROR && status != ERROR_NOT_FOUND) {
            return win::fromWin32(status, "DeleteIpForwardEntry2(" +
                                              entry.destination.toString() + ")");
        }
        return unrecordRoute(entry);
    }

    // --- policy ------------------------------------------------------------

    Status applyPolicy(const RoutingPolicy& policy) override
    {
        for (const auto& rule : policy.ipRules) {
            if (!rule.enabled) {
                continue;
            }

            u32 interfaceIndex = 0;
            {
                std::lock_guard lock{m_mutex};
                switch (rule.disposition) {
                case Disposition::Tunnel: {
                    const auto it = m_tunnelInterfaces.find(rule.tunnelId);
                    if (it != m_tunnelInterfaces.end()) {
                        interfaceIndex = it->second;
                    } else if (rule.tunnelId.empty() && !m_tunnelInterfaces.empty()) {
                        interfaceIndex = m_tunnelInterfaces.begin()->second;
                    }
                    break;
                }
                case Disposition::Direct:
                    interfaceIndex = m_underlayInterface;
                    break;
                case Disposition::Block:
                    // Blocking is the firewall's job; a blackhole route would
                    // be undone by the next more-specific route anyway.
                    continue;
                }
            }

            if (interfaceIndex == 0) {
                NOVA_LOG_WARN(Channel::Routing, "rule has no interface to land on")
                    .field("rule", rule.id)
                    .field("disposition", std::string{toString(rule.disposition)});
                continue;
            }

            RouteEntry entry;
            entry.destination    = rule.range;
            entry.interfaceIndex = interfaceIndex;
            entry.metric         = kOwnedRouteMetric;
            NOVA_RETURN_IF_ERROR(
                addRoute(entry).withContext("applying rule " + rule.id));
        }
        return Status::ok();
    }

    // --- teardown and recovery ---------------------------------------------

    Status removeAllOwnedRoutes() override
    {
        std::vector<RouteEntry> owned;
        {
            std::lock_guard lock{m_mutex};
            for (const auto& [key, entry] : m_owned) {
                owned.push_back(entry);
            }
        }

        Status firstFailure = Status::ok();
        for (const auto& entry : owned) {
            if (const Status status = removeRoute(entry); status.isError()) {
                if (firstFailure.isOk()) {
                    firstFailure = status;
                }
                NOVA_LOG_ERROR(Channel::Routing, "failed to remove owned route")
                    .field("destination", entry.destination.toString())
                    .status(status);
            }
        }
        return firstFailure;
    }

    Status reconcile() override
    {
        std::vector<RouteEntry> recorded;
        {
            std::lock_guard lock{m_mutex};
            for (const auto& [key, entry] : m_owned) {
                recorded.push_back(entry);
            }
        }

        if (recorded.empty()) {
            return Status::ok();
        }

        // Anything in the ledger predates this run: a previous instance died
        // without unwinding. Delete what still exists, drop the rest.
        NOVA_LOG_WARN(Channel::Routing, "reconciling routes left by a previous run")
            .field("count", static_cast<u64>(recorded.size()));

        Status firstFailure = Status::ok();
        for (const auto& entry : recorded) {
            if (const Status status = removeRoute(entry);
                status.isError() && firstFailure.isOk()) {
                firstFailure = status;
            }
        }
        return firstFailure;
    }

    Result<std::vector<RouteEntry>> ownedRoutes() const override
    {
        std::lock_guard lock{m_mutex};
        std::vector<RouteEntry> out;
        out.reserve(m_owned.size());
        for (const auto& [key, entry] : m_owned) {
            out.push_back(entry);
        }
        return out;
    }

private:
    void loadRecord()
    {
        if (!file::exists(m_recordPath)) {
            return;
        }
        auto document = json::readFile(m_recordPath);
        if (document.isError() || !document.value().is_array()) {
            NOVA_LOG_WARN(Channel::Routing, "route ledger unreadable; starting empty")
                .status(document.statusOrOk());
            return;
        }
        for (const auto& item : document.value()) {
            if (auto entry = routeEntryFromJson(item); entry.isOk()) {
                m_owned[routeKey(entry.value())] = entry.value();
            }
        }
    }

    /// Caller must hold m_mutex.
    Status saveRecordLocked()
    {
        Json document = Json::array();
        for (const auto& [key, entry] : m_owned) {
            document.push_back(toJson(entry));
        }
        return json::writeFile(m_recordPath, document);
    }

    Status recordRoute(const RouteEntry& entry)
    {
        std::lock_guard lock{m_mutex};
        m_owned[routeKey(entry)] = entry;
        return saveRecordLocked().withContext("persisting the route ledger");
    }

    Status unrecordRoute(const RouteEntry& entry)
    {
        std::lock_guard lock{m_mutex};
        m_owned.erase(routeKey(entry));
        return saveRecordLocked().withContext("persisting the route ledger");
    }

    std::filesystem::path                       m_recordPath;
    mutable std::mutex                          m_mutex;
    std::unordered_map<std::string, RouteEntry> m_owned;
    u32                                         m_underlayInterface = 0;
    std::unordered_map<Id, u32>                 m_tunnelInterfaces;
};

} // namespace

std::vector<RouteEntry> defaultRouteEntries(DefaultRouteMode mode, AddressFamily family,
                                            u32 tunnelInterfaceIndex)
{
    std::vector<RouteEntry> entries;

    const auto makeEntry = [&](std::string_view cidr) {
        RouteEntry entry;
        entry.destination    = net::IpRange::parse(cidr).value();
        entry.interfaceIndex = tunnelInterfaceIndex;
        entry.metric         = kOwnedRouteMetric;
        return entry;
    };

    switch (mode) {
    case DefaultRouteMode::None:
        break;

    case DefaultRouteMode::SplitHalves:
        // Two half-space routes out-specific the existing default without
        // touching it, so teardown is safe even if the process dies: the
        // original default is still there underneath.
        if (family == AddressFamily::IPv4) {
            entries.push_back(makeEntry("0.0.0.0/1"));
            entries.push_back(makeEntry("128.0.0.0/1"));
        } else {
            entries.push_back(makeEntry("::/1"));
            entries.push_back(makeEntry("8000::/1"));
        }
        break;

    case DefaultRouteMode::Replace:
        entries.push_back(makeEntry(family == AddressFamily::IPv4 ? "0.0.0.0/0" : "::/0"));
        break;
    }
    return entries;
}

Json toJson(const RouteEntry& entry)
{
    Json value{
        {"destination", entry.destination.toString()},
        {"interfaceIndex", entry.interfaceIndex},
        {"metric", entry.metric},
        {"owned", entry.owned},
    };
    if (entry.nextHop.has_value()) {
        value["nextHop"] = entry.nextHop->toString();
    }
    return value;
}

Result<RouteEntry> routeEntryFromJson(const Json& value)
{
    if (!value.is_object()) {
        return err::parse("route entry is not a JSON object");
    }

    RouteEntry entry;
    NOVA_ASSIGN_OR_RETURN(
        entry.destination,
        net::IpRange::parse(json::get<std::string>(value, "/destination", "")));
    entry.interfaceIndex = json::get<u32>(value, "/interfaceIndex", 0);
    entry.metric         = json::get<u32>(value, "/metric", 0);
    entry.owned          = json::get<bool>(value, "/owned", true);

    if (value.contains("nextHop")) {
        NOVA_ASSIGN_OR_RETURN(auto nextHop, net::IpAddress::parse(
                                                json::get<std::string>(value, "/nextHop", "")));
        entry.nextHop = nextHop;
    }
    if (entry.interfaceIndex == 0) {
        return err::invalidArgument("route entry has no interface index");
    }
    return entry;
}

RouteManagerPtr makeRouteManager(std::filesystem::path recordPath)
{
    return std::make_shared<WindowsRouteManager>(std::move(recordPath));
}

} // namespace nova::routing
