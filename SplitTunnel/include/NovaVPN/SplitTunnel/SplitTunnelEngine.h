// NovaVPN - SplitTunnel/SplitTunnelEngine.h
// App-based, domain-based and IP-based split tunnelling, implemented entirely
// inside NovaVPN - no Proxifier, no third-party routing shim.
//
// -------------------------------------------------------------------------
// How it works
// -------------------------------------------------------------------------
// Three mechanisms cooperate, each covering what the others cannot:
//
// 1. WFP bind/connect redirection (ALE_BIND_REDIRECT / ALE_CONNECT_REDIRECT).
//    When a process in the "tunnel" set creates a socket, the callout rewrites
//    the local bind address to the tunnel adapter's address. When a process in
//    the "direct" set does, it is bound to the physical adapter's address.
//    Because this happens at bind/connect time, the very first packet already
//    goes the right way - there is no leak window, and no packet ever has to be
//    re-routed after the fact.
//
// 2. Per-app routing tables. Binding alone is not enough when the default route
//    points into the tunnel: traffic bound to the physical address would still
//    be routed through the tunnel adapter. NovaVPN therefore keeps the physical
//    default route alive at a higher metric and pins direct-set traffic to it
//    with source-address-based rules, so the two paths coexist.
//
// 3. DNS interception. Domain rules are decided on the *name*, so the resolver
//    answers are captured and turned into short-lived IP rules with the record
//    TTL. Without this, a CDN-hosted domain rule is unenforceable.
//
// -------------------------------------------------------------------------
// Modes
// -------------------------------------------------------------------------
//   Include - only listed applications use the VPN, everything else is direct.
//             This is the mode the product leads with (the "☑ TikTok LIVE
//             Studio / ☐ Chrome" experience).
//   Exclude - everything uses the VPN except the listed applications.
//
// Implemented in Phase 4.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Routing/RoutingRules.h>
#include <NovaVPN/SplitTunnel/ProcessRegistry.h>

#include <memory>
#include <vector>

namespace nova::splittunnel {

enum class SplitMode : u8 {
    /// Only the listed applications are tunnelled.
    Include,
    /// Everything is tunnelled except the listed applications.
    Exclude,
};

[[nodiscard]] std::string_view toString(SplitMode mode) noexcept;
[[nodiscard]] bool parseSplitMode(std::string_view text, SplitMode& out) noexcept;

/// One entry in the app list, as the UI checkbox model sees it.
struct AppBinding {
    std::string imagePath;
    std::string displayName;
    bool        enabled = true;
    /// Which tunnel this app uses. Empty = the primary tunnel. Setting
    /// different tunnels per app is what produces the multi-VPN experience:
    ///   TikTok -> Hong Kong, Steam -> Japan, Discord -> Singapore.
    Id          tunnelId;
    bool        includeChildren = true;
};

struct SplitTunnelConfig {
    bool                    enabled = false;
    SplitMode               mode = SplitMode::Include;
    std::vector<AppBinding> applications;
    /// Domain and IP rules share the routing policy vocabulary.
    std::vector<routing::DomainRule> domainRules;
    std::vector<routing::IpRule>     ipRules;
    /// Address of the tunnel adapter each tunnel id binds to, filled in by the
    /// tunnel manager when a tunnel comes up.
    std::vector<std::pair<Id, net::IpAddress>> tunnelAddresses;
    /// Address of the physical adapter used for direct traffic.
    std::optional<net::IpAddress> underlayAddress;
};

/// Live attribution of a single flow, surfaced in the process manager view.
struct FlowAttribution {
    ProcessId            pid = 0;
    std::string          imagePath;
    net::Endpoint        remote;
    Transport            transport = Transport::Tcp;
    routing::Disposition disposition = routing::Disposition::Direct;
    Id                   tunnelId;
    std::string          matchedRuleId;
};

class ISplitTunnelEngine {
public:
    virtual ~ISplitTunnelEngine() = default;

    /// Registers the callout and the WFP filters. Requires the callout driver
    /// to be installed and running.
    [[nodiscard]] virtual Status start() = 0;
    virtual void stop() = 0;

    /// Replaces the configuration atomically. Existing connections keep their
    /// current path (Windows cannot re-bind an established socket); new
    /// connections follow the new rules immediately. The engine reports which
    /// processes would need a restart to take full effect.
    [[nodiscard]] virtual Result<std::vector<ProcessId>> apply(
        const SplitTunnelConfig& config) = 0;

    /// Recent flow decisions, newest first, for the diagnostics view.
    [[nodiscard]] virtual Result<std::vector<FlowAttribution>> recentFlows(
        std::size_t limit) const = 0;

    /// Per-process byte counters attributed by the callout.
    [[nodiscard]] virtual Result<std::vector<ProcessInfo>> processTraffic() const = 0;

    [[nodiscard]] virtual bool isActive() const = 0;
};

using SplitTunnelEnginePtr = std::shared_ptr<ISplitTunnelEngine>;

/// Pure classification: given the split-tunnel config plus a process's image
/// path and (optionally) the flow's remote address, decides where the flow goes.
/// This is the decision the WFP callout consults; separating it out makes the
/// policy fully unit-testable without the kernel driver.
class SplitTunnelClassifier {
public:
    explicit SplitTunnelClassifier(SplitTunnelConfig config);

    void setConfig(SplitTunnelConfig config);
    [[nodiscard]] const SplitTunnelConfig& config() const noexcept { return m_config; }

    /// Decides the disposition for a flow from `imagePath` to `remote`.
    /// In Include mode an unlisted app is Direct; in Exclude mode it is Tunnel.
    /// An explicit IP/domain rule overrides the app decision.
    [[nodiscard]] routing::RouteDecision classify(
        std::string_view imagePath,
        std::optional<net::IpAddress> remote = std::nullopt) const;

private:
    SplitTunnelConfig      m_config;
    routing::RoutingPolicy m_policy;
    void rebuild();
};

/// Creates the split-tunnel engine over the process registry. The engine owns
/// the classifier and the live flow attribution; enforcement (WFP bind/connect
/// redirection) is performed by the callout driver, which consults the
/// classifier. `registry` may be null in a reduced configuration.
[[nodiscard]] SplitTunnelEnginePtr makeSplitTunnelEngine(ProcessRegistryPtr registry);

} // namespace nova::splittunnel
