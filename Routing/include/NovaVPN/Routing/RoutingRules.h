// NovaVPN - Routing/RoutingRules.h
// The policy vocabulary shared by IP-, domain- and application-based routing.
//
// A rule says "traffic matching X goes to destination Y". Destinations are:
//   Tunnel(id) - a specific tunnel, which is what makes multi-VPN possible
//   Direct     - the physical adapter, bypassing every tunnel
//   Block      - dropped (used by the kill switch and by blocklists)
//
// Evaluation order is fixed and documented in docs/ARCHITECTURE.md:
//   1. explicit IP rules (most specific prefix wins)
//   2. domain rules (longest suffix wins)
//   3. application rules
//   4. the profile default (redirect-gateway or not)
// The first match decides; ties are broken by rule priority, then by insertion
// order, so an administrator can always pin behaviour deterministically.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/Types.h>
#include <NovaVPN/Networking/IpAddress.h>

#include <optional>
#include <string>
#include <vector>

namespace nova::routing {

/// Where matching traffic goes.
enum class Disposition : u8 {
    Tunnel, ///< Through `tunnelId` (empty = the primary tunnel).
    Direct, ///< Out of the physical adapter.
    Block,  ///< Dropped.
};

[[nodiscard]] std::string_view toString(Disposition disposition) noexcept;
[[nodiscard]] bool parseDisposition(std::string_view text, Disposition& out) noexcept;

/// Common fields of every rule kind.
struct RuleBase {
    Id          id;
    std::string name;
    bool        enabled = true;
    /// Higher wins when two rules of the same kind match equally well.
    i32         priority = 0;
    Disposition disposition = Disposition::Tunnel;
    /// Target tunnel when disposition == Tunnel. Empty means "primary".
    Id          tunnelId;
    std::string notes;
};

/// "10.0.0.0/8 -> Direct", "203.0.113.7 -> Tunnel(hk-01)".
struct IpRule : RuleBase {
    net::IpRange range;
    /// Optional port restriction; unset matches every port.
    std::optional<u16> port;
    std::optional<Transport> transport;
};

/// "*.tiktok.com -> Tunnel(hk-01)", "*.youtube.com -> Direct".
///
/// Matching is on the *requested name*, observed at the DNS layer, so it works
/// for hosts behind CDNs whose addresses change constantly. The resolved
/// addresses are then programmed as ephemeral IP rules with the same
/// disposition and the record's TTL.
struct DomainRule : RuleBase {
    /// Pattern with optional leading "*." wildcard. Stored lowercase.
    std::string pattern;
    /// Apply to sub-domains even without a leading wildcard.
    bool        includeSubdomains = true;
};

/// "TikTok LIVE Studio -> Tunnel(hk-01)".
///
/// Identity is the *image path* rather than the process name, because process
/// names are trivially spoofed. An optional signer/hash pin tightens this for
/// high-assurance deployments.
struct ApplicationRule : RuleBase {
    /// Full path, or a glob such as "C:\\Program Files\\*\\chrome.exe".
    std::string executablePath;
    /// Display name shown in the app picker.
    std::string displayName;
    /// Apply to processes the matched executable creates.
    bool        includeChildren = true;
    /// Optional Authenticode subject the image must be signed by.
    std::string requiredSigner;
    /// Optional SHA-256 of the image file.
    std::string requiredHashSha256;
};

/// Country-level routing ("everything geolocated to JP -> Tunnel(jp-01)").
/// Backed by a signed, periodically refreshed IP-to-country table shipped with
/// the updater; entries expand into IpRules at load time.
struct CountryRule : RuleBase {
    std::string countryCode; ///< ISO 3166-1 alpha-2, uppercase.
};

/// The complete routing policy for one session.
struct RoutingPolicy {
    /// What happens to traffic that matches no rule.
    Disposition                  defaultDisposition = Disposition::Tunnel;
    Id                           defaultTunnelId;
    std::vector<IpRule>          ipRules;
    std::vector<DomainRule>      domainRules;
    std::vector<ApplicationRule> applicationRules;
    std::vector<CountryRule>     countryRules;

    /// Rejects a policy that cannot be enforced: duplicate ids, a rule pointing
    /// at a tunnel that is not in `knownTunnelIds`, or a malformed pattern.
    [[nodiscard]] Status validate(const std::vector<Id>& knownTunnelIds) const;
};

/// Result of evaluating a policy.
struct RouteDecision {
    Disposition disposition = Disposition::Tunnel;
    Id          tunnelId;
    /// Id of the rule that decided, empty when the default applied.
    Id          matchedRuleId;
    /// Which rule kind decided, for the "why did this app go direct?" view.
    std::string matchedRuleKind;
};

/// Pure policy evaluation. No OS state is touched, which is what makes routing
/// decisions unit-testable and reproducible from a log.
class PolicyEvaluator final {
public:
    explicit PolicyEvaluator(RoutingPolicy policy);

    /// Replaces the policy atomically.
    void setPolicy(RoutingPolicy policy);
    [[nodiscard]] const RoutingPolicy& policy() const noexcept { return m_policy; }

    /// Most specific matching IP rule; longest prefix wins, then priority.
    [[nodiscard]] RouteDecision evaluateAddress(const net::IpAddress& address,
                                                std::optional<u16> port = std::nullopt,
                                                std::optional<Transport> transport =
                                                    std::nullopt) const;

    /// Longest matching domain suffix wins, then priority.
    [[nodiscard]] RouteDecision evaluateDomain(std::string_view host) const;

    /// Exact path match beats a glob; longer glob beats shorter.
    [[nodiscard]] RouteDecision evaluateApplication(std::string_view executablePath) const;

private:
    [[nodiscard]] RouteDecision defaultDecision() const;

    RoutingPolicy m_policy;
};

} // namespace nova::routing
