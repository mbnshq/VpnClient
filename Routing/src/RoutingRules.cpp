#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Routing/RoutingRules.h>

#include <algorithm>
#include <unordered_set>
#include <utility>

namespace nova::routing {
namespace {

/// True when `host` is covered by `pattern`.
///
/// "*.example.com" matches "a.example.com" and "a.b.example.com" but not
/// "example.com" - matching the bare apex requires listing it, which avoids the
/// classic mistake of "*.corp.com" silently covering "evilcorp.com".
bool matchesDomain(const DomainRule& rule, std::string_view host)
{
    const std::string lowered = str::toLower(host);
    std::string_view candidate{lowered};

    // A trailing dot is a fully-qualified form of the same name.
    if (!candidate.empty() && candidate.back() == '.') {
        candidate.remove_suffix(1);
    }

    std::string_view pattern{rule.pattern};
    if (str::startsWith(pattern, "*.")) {
        const std::string_view suffix = pattern.substr(2);
        return candidate.size() > suffix.size() &&
               str::endsWith(candidate, suffix) &&
               candidate[candidate.size() - suffix.size() - 1] == '.';
    }

    if (candidate == pattern) {
        return true;
    }
    if (rule.includeSubdomains) {
        return candidate.size() > pattern.size() && str::endsWith(candidate, pattern) &&
               candidate[candidate.size() - pattern.size() - 1] == '.';
    }
    return false;
}

/// Specificity of a domain rule: the number of labels it pins. Longer wins.
std::size_t domainSpecificity(const DomainRule& rule)
{
    std::string_view pattern{rule.pattern};
    if (str::startsWith(pattern, "*.")) {
        pattern.remove_prefix(2);
    }
    return pattern.size();
}

bool matchesApplication(const ApplicationRule& rule, std::string_view executablePath)
{
    if (rule.executablePath.empty()) {
        return false;
    }
    // Windows paths are case-insensitive; globMatch already folds case.
    return str::globMatch(rule.executablePath, executablePath);
}

std::size_t applicationSpecificity(const ApplicationRule& rule)
{
    // A path without wildcards is maximally specific; otherwise longer literal
    // prefixes are more specific than short ones.
    const bool hasWildcard = rule.executablePath.find_first_of("*?") != std::string::npos;
    return rule.executablePath.size() + (hasWildcard ? 0 : 4096);
}

template <typename Rule>
RouteDecision decisionFrom(const Rule& rule, const char* kind)
{
    RouteDecision decision;
    decision.disposition     = rule.disposition;
    decision.tunnelId        = rule.tunnelId;
    decision.matchedRuleId   = rule.id;
    decision.matchedRuleKind = kind;
    return decision;
}

} // namespace

std::string_view toString(Disposition disposition) noexcept
{
    switch (disposition) {
    case Disposition::Tunnel: return "tunnel";
    case Disposition::Direct: return "direct";
    case Disposition::Block:  return "block";
    }
    return "unknown";
}

bool parseDisposition(std::string_view text, Disposition& out) noexcept
{
    if (str::equalsIgnoreCase(text, "tunnel") || str::equalsIgnoreCase(text, "vpn")) {
        out = Disposition::Tunnel;
        return true;
    }
    if (str::equalsIgnoreCase(text, "direct") || str::equalsIgnoreCase(text, "bypass")) {
        out = Disposition::Direct;
        return true;
    }
    if (str::equalsIgnoreCase(text, "block") || str::equalsIgnoreCase(text, "drop")) {
        out = Disposition::Block;
        return true;
    }
    return false;
}

Status RoutingPolicy::validate(const std::vector<Id>& knownTunnelIds) const
{
    std::unordered_set<std::string> seenIds;
    const std::unordered_set<std::string> tunnels{knownTunnelIds.begin(), knownTunnelIds.end()};

    const auto checkBase = [&](const RuleBase& rule, const char* kind) -> Status {
        if (rule.id.empty()) {
            return err::invalidArgument(std::string{kind} + " rule has no id");
        }
        if (!seenIds.insert(rule.id).second) {
            return err::alreadyExists("duplicate rule id " + rule.id);
        }
        if (rule.disposition == Disposition::Tunnel && !rule.tunnelId.empty() &&
            tunnels.find(rule.tunnelId) == tunnels.end()) {
            return err::notFound(std::string{kind} + " rule '" + rule.name +
                                 "' targets unknown tunnel " + rule.tunnelId);
        }
        return Status::ok();
    };

    for (const auto& rule : ipRules) {
        NOVA_RETURN_IF_ERROR(checkBase(rule, "ip"));
    }
    for (const auto& rule : domainRules) {
        NOVA_RETURN_IF_ERROR(checkBase(rule, "domain"));
        if (rule.pattern.empty()) {
            return err::invalidArgument("domain rule '" + rule.name + "' has an empty pattern");
        }
        // A bare "*" would silently capture everything and defeat the default.
        if (rule.pattern == "*" || rule.pattern == "*.") {
            return err::invalidArgument(
                "domain rule '" + rule.name +
                "' matches every host; change the default disposition instead");
        }
    }
    for (const auto& rule : applicationRules) {
        NOVA_RETURN_IF_ERROR(checkBase(rule, "application"));
        if (rule.executablePath.empty()) {
            return err::invalidArgument("application rule '" + rule.name + "' has no path");
        }
    }
    for (const auto& rule : countryRules) {
        NOVA_RETURN_IF_ERROR(checkBase(rule, "country"));
        if (rule.countryCode.size() != 2) {
            return err::invalidArgument("country rule '" + rule.name +
                                        "' must use a two-letter ISO code");
        }
    }

    if (defaultDisposition == Disposition::Tunnel && !defaultTunnelId.empty() &&
        tunnels.find(defaultTunnelId) == tunnels.end()) {
        return err::notFound("default tunnel " + defaultTunnelId + " does not exist");
    }

    return Status::ok();
}

// --- PolicyEvaluator ------------------------------------------------------

PolicyEvaluator::PolicyEvaluator(RoutingPolicy policy) : m_policy(std::move(policy)) {}

void PolicyEvaluator::setPolicy(RoutingPolicy policy)
{
    m_policy = std::move(policy);
}

RouteDecision PolicyEvaluator::defaultDecision() const
{
    RouteDecision decision;
    decision.disposition = m_policy.defaultDisposition;
    decision.tunnelId    = m_policy.defaultTunnelId;
    return decision;
}

RouteDecision PolicyEvaluator::evaluateAddress(const net::IpAddress& address,
                                               std::optional<u16> port,
                                               std::optional<Transport> transport) const
{
    const net::IpAddress normalized = address.normalized();

    const IpRule* best = nullptr;
    for (const auto& rule : m_policy.ipRules) {
        if (!rule.enabled || !rule.range.contains(normalized)) {
            continue;
        }
        if (rule.port.has_value() && (!port.has_value() || *rule.port != *port)) {
            continue;
        }
        if (rule.transport.has_value() &&
            (!transport.has_value() || *rule.transport != *transport)) {
            continue;
        }

        if (best == nullptr) {
            best = &rule;
            continue;
        }

        // Longest prefix wins; equal prefixes fall back to priority.
        if (rule.range.prefixLength() > best->range.prefixLength() ||
            (rule.range.prefixLength() == best->range.prefixLength() &&
             rule.priority > best->priority)) {
            best = &rule;
        }
    }

    return best != nullptr ? decisionFrom(*best, "ip") : defaultDecision();
}

RouteDecision PolicyEvaluator::evaluateDomain(std::string_view host) const
{
    const DomainRule* best = nullptr;
    std::size_t bestSpecificity = 0;

    for (const auto& rule : m_policy.domainRules) {
        if (!rule.enabled || !matchesDomain(rule, host)) {
            continue;
        }
        const std::size_t specificity = domainSpecificity(rule);
        if (best == nullptr || specificity > bestSpecificity ||
            (specificity == bestSpecificity && rule.priority > best->priority)) {
            best = &rule;
            bestSpecificity = specificity;
        }
    }

    return best != nullptr ? decisionFrom(*best, "domain") : defaultDecision();
}

RouteDecision PolicyEvaluator::evaluateApplication(std::string_view executablePath) const
{
    const ApplicationRule* best = nullptr;
    std::size_t bestSpecificity = 0;

    for (const auto& rule : m_policy.applicationRules) {
        if (!rule.enabled || !matchesApplication(rule, executablePath)) {
            continue;
        }
        const std::size_t specificity = applicationSpecificity(rule);
        if (best == nullptr || specificity > bestSpecificity ||
            (specificity == bestSpecificity && rule.priority > best->priority)) {
            best = &rule;
            bestSpecificity = specificity;
        }
    }

    return best != nullptr ? decisionFrom(*best, "application") : defaultDecision();
}

} // namespace nova::routing
