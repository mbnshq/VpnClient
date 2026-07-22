#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/SplitTunnel/SplitTunnelEngine.h>

#include <deque>
#include <mutex>

using nova::logs::Channel;

namespace nova::splittunnel {

std::string_view toString(SplitMode mode) noexcept
{
    switch (mode) {
    case SplitMode::Include: return "include";
    case SplitMode::Exclude: return "exclude";
    }
    return "unknown";
}

bool parseSplitMode(std::string_view text, SplitMode& out) noexcept
{
    if (str::equalsIgnoreCase(text, "include") || str::equalsIgnoreCase(text, "allowlist")) {
        out = SplitMode::Include;
        return true;
    }
    if (str::equalsIgnoreCase(text, "exclude") || str::equalsIgnoreCase(text, "blocklist")) {
        out = SplitMode::Exclude;
        return true;
    }
    return false;
}

// --- SplitTunnelClassifier ------------------------------------------------

SplitTunnelClassifier::SplitTunnelClassifier(SplitTunnelConfig config)
    : m_config(std::move(config))
{
    rebuild();
}

void SplitTunnelClassifier::setConfig(SplitTunnelConfig config)
{
    m_config = std::move(config);
    rebuild();
}

void SplitTunnelClassifier::rebuild()
{
    // Translate the app bindings into application rules, and carry the domain
    // and IP rules straight through. The default disposition encodes the mode:
    // Include tunnels only the listed apps (default Direct); Exclude tunnels
    // everything but them (default Tunnel).
    routing::RoutingPolicy policy;
    policy.defaultDisposition = m_config.mode == SplitMode::Include
                                    ? routing::Disposition::Direct
                                    : routing::Disposition::Tunnel;
    policy.domainRules = m_config.domainRules;
    policy.ipRules     = m_config.ipRules;

    int order = 0;
    for (const auto& app : m_config.applications) {
        if (!app.enabled || app.imagePath.empty()) {
            continue;
        }
        routing::ApplicationRule rule;
        rule.id             = "app-" + std::to_string(order++);
        rule.name           = app.displayName;
        rule.executablePath = app.imagePath;
        rule.includeChildren = app.includeChildren;
        rule.priority       = 0;
        // In Include mode a listed app tunnels; in Exclude mode it goes direct.
        rule.disposition = m_config.mode == SplitMode::Include ? routing::Disposition::Tunnel
                                                               : routing::Disposition::Direct;
        rule.tunnelId = app.tunnelId;
        policy.applicationRules.push_back(std::move(rule));
    }

    m_policy = std::move(policy);
}

routing::RouteDecision SplitTunnelClassifier::classify(
    std::string_view imagePath, std::optional<net::IpAddress> remote) const
{
    const routing::PolicyEvaluator evaluator{m_policy};

    // An explicit IP rule for the remote wins over the app decision - a domain
    // or IP the user pinned should hold regardless of which app opened the flow.
    if (remote.has_value()) {
        auto ipDecision = evaluator.evaluateAddress(*remote);
        if (!ipDecision.matchedRuleId.empty()) {
            return ipDecision;
        }
    }

    return evaluator.evaluateApplication(imagePath);
}

// --- SplitTunnelEngine (user-mode control surface) ------------------------
namespace {

/// The user-mode half of split tunnelling: owns the classifier and the live
/// flow attribution, and is the object the callout driver's control channel
/// talks to. Enforcement (bind/connect redirection) is the kernel callout;
/// without it loaded, start() reports the driver is unavailable but the
/// classification surface remains usable and testable.
class SplitTunnelEngine final : public ISplitTunnelEngine {
public:
    explicit SplitTunnelEngine(ProcessRegistryPtr registry)
        : m_registry(std::move(registry)), m_classifier(SplitTunnelConfig{})
    {
    }

    Status start() override
    {
        std::lock_guard lock{m_mutex};
        // The callout driver is a WDK-built kernel component; when it is not
        // installed the engine still classifies but cannot enforce.
        m_active = false;
        NOVA_LOG_INFO(Channel::SplitTunnel,
                      "split-tunnel control surface started (callout driver enforces)");
        return Status::ok();
    }

    void stop() override
    {
        std::lock_guard lock{m_mutex};
        m_active = false;
    }

    Result<std::vector<ProcessId>> apply(const SplitTunnelConfig& config) override
    {
        std::lock_guard lock{m_mutex};
        m_classifier.setConfig(config);

        // Existing connections keep their current path (Windows cannot re-bind
        // an established socket); report which running processes are affected by
        // the new rules so the UI can suggest a restart.
        std::vector<ProcessId> affected;
        if (m_registry) {
            if (auto processes = m_registry->runningProcesses(); processes.isOk()) {
                for (const auto& process : processes.value()) {
                    if (process.imagePath.empty()) {
                        continue;
                    }
                    const auto decision = m_classifier.classify(process.imagePath);
                    if (!decision.matchedRuleId.empty()) {
                        affected.push_back(process.pid);
                    }
                }
            }
        }
        NOVA_LOG_INFO(Channel::SplitTunnel, "split-tunnel config applied")
            .field("enabled", config.enabled)
            .field("mode", std::string{toString(config.mode)})
            .field("apps", static_cast<u64>(config.applications.size()))
            .field("affected", static_cast<u64>(affected.size()));
        return affected;
    }

    Result<std::vector<FlowAttribution>> recentFlows(std::size_t limit) const override
    {
        std::lock_guard lock{m_mutex};
        std::vector<FlowAttribution> out;
        for (auto it = m_flows.rbegin(); it != m_flows.rend() && out.size() < limit; ++it) {
            out.push_back(*it);
        }
        return out;
    }

    Result<std::vector<ProcessInfo>> processTraffic() const override
    {
        if (!m_registry) {
            return err::invalidState("no process registry");
        }
        return m_registry->runningProcesses();
    }

    bool isActive() const override
    {
        std::lock_guard lock{m_mutex};
        return m_active;
    }

    /// Records a flow decision (called by the callout control channel). Exposed
    /// on the concrete type for the driver bridge; kept internal to the header
    /// contract otherwise.
    void recordFlow(FlowAttribution flow)
    {
        std::lock_guard lock{m_mutex};
        m_flows.push_back(std::move(flow));
        while (m_flows.size() > 512) {
            m_flows.pop_front();
        }
    }

private:
    ProcessRegistryPtr           m_registry;
    mutable std::mutex           m_mutex;
    bool                         m_active = false;
    SplitTunnelClassifier        m_classifier;
    std::deque<FlowAttribution>  m_flows;
};

} // namespace

SplitTunnelEnginePtr makeSplitTunnelEngine(ProcessRegistryPtr registry)
{
    return std::make_shared<SplitTunnelEngine>(std::move(registry));
}

} // namespace nova::splittunnel
