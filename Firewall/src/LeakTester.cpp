#include <NovaVPN/Firewall/FirewallEngine.h>
#include <NovaVPN/Logs/Logger.h>

#include <algorithm>
#include <unordered_set>

using nova::logs::Channel;

namespace nova::firewall {
namespace {

class LeakTester final : public ILeakTester {
public:
    LeakTester(std::shared_ptr<net::INetworkMonitor> monitor, std::vector<u64> tunnelLuids)
        : m_monitor(std::move(monitor)),
          m_tunnelLuids(tunnelLuids.begin(), tunnelLuids.end())
    {
    }

    Result<LeakTestResult> run(const CancellationToken& token) override
    {
        if (!m_monitor) {
            return err::invalidState("leak tester has no network monitor");
        }
        if (token.isCancelled()) {
            return err::cancelled("leak test cancelled");
        }

        NOVA_ASSIGN_OR_RETURN(auto adapters, m_monitor->adapters());

        LeakTestResult result;
        for (const auto& adapter : adapters) {
            if (!adapter.isUp || adapter.type == net::AdapterType::Loopback) {
                continue;
            }
            const bool isTunnel = adapter.type == net::AdapterType::Tunnel ||
                                  m_tunnelLuids.count(adapter.luid) != 0;
            if (isTunnel) {
                continue; // traffic on the tunnel is not a leak
            }

            // A non-tunnel adapter carrying a globally-routable IPv6 address is
            // the classic v6 leak around a v4-only tunnel.
            for (const auto& address : adapter.addresses) {
                if (address.isV6() && address.isGlobalUnicast()) {
                    result.ipv6Leak = true;
                    result.details.push_back("global IPv6 address " + address.toString() +
                                             " on non-tunnel adapter '" + adapter.name + "'");
                }
                // A non-tunnel global address is a WebRTC host candidate a
                // browser could disclose.
                if (address.isGlobalUnicast()) {
                    result.webRtcLeak = true;
                    if (!result.observedPublicAddress.has_value()) {
                        result.observedPublicAddress = address;
                    }
                }
            }

            // Plaintext DNS servers configured on a non-tunnel adapter are a
            // DNS-leak surface: a query that escapes to them reveals the lookup.
            for (const auto& dns : adapter.dnsServers) {
                result.dnsLeak = true;
                result.observedResolvers.push_back(dns);
                result.details.push_back("DNS server " + dns.toString() +
                                         " on non-tunnel adapter '" + adapter.name + "'");
            }
        }

        // De-duplicate resolvers for a tidy report.
        std::sort(result.observedResolvers.begin(), result.observedResolvers.end());
        result.observedResolvers.erase(
            std::unique(result.observedResolvers.begin(), result.observedResolvers.end()),
            result.observedResolvers.end());

        NOVA_LOG_INFO(Channel::Firewall, "leak test complete")
            .field("dns", result.dnsLeak)
            .field("ipv6", result.ipv6Leak)
            .field("webrtc", result.webRtcLeak);
        return result;
    }

private:
    std::shared_ptr<net::INetworkMonitor> m_monitor;
    std::unordered_set<u64>               m_tunnelLuids;
};

} // namespace

LeakTesterPtr makeLeakTester(std::shared_ptr<net::INetworkMonitor> monitor,
                             std::vector<u64> tunnelInterfaceLuids)
{
    return std::make_shared<LeakTester>(std::move(monitor), std::move(tunnelInterfaceLuids));
}

} // namespace nova::firewall
