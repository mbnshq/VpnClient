#include <NovaVPN/Routing/RoutingRules.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::routing;

namespace {

IpRule makeIpRule(std::string id, std::string_view cidr, Disposition disposition,
                  std::string tunnelId = {}, i32 priority = 0)
{
    IpRule rule;
    rule.id          = std::move(id);
    rule.name        = rule.id;
    rule.range       = net::IpRange::parse(cidr).value();
    rule.disposition = disposition;
    rule.tunnelId    = std::move(tunnelId);
    rule.priority    = priority;
    return rule;
}

DomainRule makeDomainRule(std::string id, std::string pattern, Disposition disposition,
                          std::string tunnelId = {})
{
    DomainRule rule;
    rule.id          = std::move(id);
    rule.name        = rule.id;
    rule.pattern     = std::move(pattern);
    rule.disposition = disposition;
    rule.tunnelId    = std::move(tunnelId);
    return rule;
}

ApplicationRule makeAppRule(std::string id, std::string path, Disposition disposition,
                            std::string tunnelId = {})
{
    ApplicationRule rule;
    rule.id             = std::move(id);
    rule.name           = rule.id;
    rule.executablePath = std::move(path);
    rule.disposition    = disposition;
    rule.tunnelId       = std::move(tunnelId);
    return rule;
}

} // namespace

TEST_CASE("dispositions round-trip through text", "[routing]")
{
    Disposition disposition = Disposition::Block;

    REQUIRE(parseDisposition("tunnel", disposition));
    REQUIRE(disposition == Disposition::Tunnel);
    REQUIRE(parseDisposition("VPN", disposition));
    REQUIRE(disposition == Disposition::Tunnel);
    REQUIRE(parseDisposition("bypass", disposition));
    REQUIRE(disposition == Disposition::Direct);
    REQUIRE(parseDisposition("drop", disposition));
    REQUIRE(disposition == Disposition::Block);
    REQUIRE_FALSE(parseDisposition("maybe", disposition));

    REQUIRE(toString(Disposition::Direct) == "direct");
}

TEST_CASE("the default disposition applies when nothing matches", "[routing]")
{
    RoutingPolicy policy;
    policy.defaultDisposition = Disposition::Tunnel;
    policy.defaultTunnelId    = "primary";

    const PolicyEvaluator evaluator{policy};
    const auto decision = evaluator.evaluateAddress(net::IpAddress::parse("8.8.8.8").value());

    REQUIRE(decision.disposition == Disposition::Tunnel);
    REQUIRE(decision.tunnelId == "primary");
    REQUIRE(decision.matchedRuleId.empty());
}

TEST_CASE("the longest matching prefix wins", "[routing][ip]")
{
    RoutingPolicy policy;
    policy.defaultDisposition = Disposition::Tunnel;
    policy.ipRules.push_back(makeIpRule("broad", "10.0.0.0/8", Disposition::Tunnel, "hk"));
    policy.ipRules.push_back(makeIpRule("narrow", "10.1.0.0/16", Disposition::Direct));

    const PolicyEvaluator evaluator{policy};

    const auto inNarrow = evaluator.evaluateAddress(net::IpAddress::parse("10.1.2.3").value());
    REQUIRE(inNarrow.matchedRuleId == "narrow");
    REQUIRE(inNarrow.disposition == Disposition::Direct);

    const auto inBroad = evaluator.evaluateAddress(net::IpAddress::parse("10.9.9.9").value());
    REQUIRE(inBroad.matchedRuleId == "broad");
    REQUIRE(inBroad.tunnelId == "hk");
}

TEST_CASE("equal prefixes are broken by priority", "[routing][ip]")
{
    RoutingPolicy policy;
    policy.ipRules.push_back(makeIpRule("low", "10.0.0.0/8", Disposition::Tunnel, "hk", 1));
    policy.ipRules.push_back(makeIpRule("high", "10.0.0.0/8", Disposition::Direct, "", 10));

    const PolicyEvaluator evaluator{policy};
    const auto decision = evaluator.evaluateAddress(net::IpAddress::parse("10.0.0.1").value());

    REQUIRE(decision.matchedRuleId == "high");
    REQUIRE(decision.disposition == Disposition::Direct);
}

TEST_CASE("a disabled rule is ignored", "[routing][ip]")
{
    RoutingPolicy policy;
    policy.defaultDisposition = Disposition::Tunnel;

    auto rule = makeIpRule("off", "10.0.0.0/8", Disposition::Direct);
    rule.enabled = false;
    policy.ipRules.push_back(rule);

    const PolicyEvaluator evaluator{policy};
    const auto decision = evaluator.evaluateAddress(net::IpAddress::parse("10.0.0.1").value());

    REQUIRE(decision.matchedRuleId.empty());
    REQUIRE(decision.disposition == Disposition::Tunnel);
}

TEST_CASE("port and transport restrictions narrow a rule", "[routing][ip]")
{
    RoutingPolicy policy;
    policy.defaultDisposition = Disposition::Tunnel;

    auto rule = makeIpRule("dns", "0.0.0.0/0", Disposition::Block);
    rule.port      = u16{53};
    rule.transport = Transport::Udp;
    policy.ipRules.push_back(rule);

    const PolicyEvaluator evaluator{policy};
    const auto address = net::IpAddress::parse("8.8.8.8").value();

    REQUIRE(evaluator.evaluateAddress(address, u16{53}, Transport::Udp).disposition ==
            Disposition::Block);
    REQUIRE(evaluator.evaluateAddress(address, u16{443}, Transport::Udp).disposition ==
            Disposition::Tunnel);
    REQUIRE(evaluator.evaluateAddress(address, u16{53}, Transport::Tcp).disposition ==
            Disposition::Tunnel);
    // No port supplied: a port-restricted rule cannot claim the flow.
    REQUIRE(evaluator.evaluateAddress(address).disposition == Disposition::Tunnel);
}

TEST_CASE("IPv4-mapped addresses are matched by IPv4 rules",
          "[routing][ip][security]")
{
    RoutingPolicy policy;
    policy.defaultDisposition = Disposition::Tunnel;
    policy.ipRules.push_back(makeIpRule("lan", "10.0.0.0/8", Disposition::Direct));

    const PolicyEvaluator evaluator{policy};
    const auto mapped = net::IpAddress::parse("::ffff:10.0.0.1").value();

    REQUIRE(evaluator.evaluateAddress(mapped).matchedRuleId == "lan");
}

TEST_CASE("domain rules implement the product's example policy",
          "[routing][domain]")
{
    // *.tiktok.com -> VPN, *.youtube.com -> Direct,
    // *.google.com -> Direct, *.facebook.com -> VPN
    RoutingPolicy policy;
    policy.defaultDisposition = Disposition::Direct;
    policy.domainRules.push_back(
        makeDomainRule("tiktok", "*.tiktok.com", Disposition::Tunnel, "hk"));
    policy.domainRules.push_back(makeDomainRule("youtube", "*.youtube.com", Disposition::Direct));
    policy.domainRules.push_back(makeDomainRule("google", "*.google.com", Disposition::Direct));
    policy.domainRules.push_back(
        makeDomainRule("facebook", "*.facebook.com", Disposition::Tunnel, "hk"));

    const PolicyEvaluator evaluator{policy};

    REQUIRE(evaluator.evaluateDomain("www.tiktok.com").tunnelId == "hk");
    REQUIRE(evaluator.evaluateDomain("api.v2.tiktok.com").disposition == Disposition::Tunnel);
    REQUIRE(evaluator.evaluateDomain("www.youtube.com").disposition == Disposition::Direct);
    REQUIRE(evaluator.evaluateDomain("mail.google.com").disposition == Disposition::Direct);
    REQUIRE(evaluator.evaluateDomain("cdn.facebook.com").disposition == Disposition::Tunnel);
    REQUIRE(evaluator.evaluateDomain("example.org").matchedRuleId.empty());
}

TEST_CASE("a wildcard does not match the apex", "[routing][domain][security]")
{
    RoutingPolicy policy;
    policy.defaultDisposition = Disposition::Direct;
    policy.domainRules.push_back(makeDomainRule("corp", "*.corp.com", Disposition::Tunnel));

    const PolicyEvaluator evaluator{policy};

    REQUIRE(evaluator.evaluateDomain("intranet.corp.com").disposition == Disposition::Tunnel);
    REQUIRE(evaluator.evaluateDomain("corp.com").matchedRuleId.empty());
    // The bug this guards against: "*.corp.com" must not capture "evilcorp.com".
    REQUIRE(evaluator.evaluateDomain("evilcorp.com").matchedRuleId.empty());
}

TEST_CASE("the most specific domain rule wins", "[routing][domain]")
{
    RoutingPolicy policy;
    policy.defaultDisposition = Disposition::Direct;
    policy.domainRules.push_back(makeDomainRule("broad", "*.example.com", Disposition::Tunnel));
    policy.domainRules.push_back(
        makeDomainRule("narrow", "*.internal.example.com", Disposition::Direct));

    const PolicyEvaluator evaluator{policy};

    REQUIRE(evaluator.evaluateDomain("a.internal.example.com").matchedRuleId == "narrow");
    REQUIRE(evaluator.evaluateDomain("a.public.example.com").matchedRuleId == "broad");
}

TEST_CASE("domain matching is case-insensitive and dot-tolerant",
          "[routing][domain]")
{
    RoutingPolicy policy;
    policy.domainRules.push_back(makeDomainRule("t", "*.tiktok.com", Disposition::Tunnel));

    const PolicyEvaluator evaluator{policy};

    REQUIRE(evaluator.evaluateDomain("WWW.TikTok.COM").matchedRuleId == "t");
    REQUIRE(evaluator.evaluateDomain("www.tiktok.com.").matchedRuleId == "t");
}

TEST_CASE("exact domain rules honour includeSubdomains", "[routing][domain]")
{
    RoutingPolicy policy;
    policy.defaultDisposition = Disposition::Direct;

    auto exact = makeDomainRule("exact", "example.com", Disposition::Tunnel);
    exact.includeSubdomains = false;
    policy.domainRules.push_back(exact);

    PolicyEvaluator evaluator{policy};

    REQUIRE(evaluator.evaluateDomain("example.com").matchedRuleId == "exact");
    REQUIRE(evaluator.evaluateDomain("www.example.com").matchedRuleId.empty());

    policy.domainRules[0].includeSubdomains = true;
    evaluator.setPolicy(policy);
    REQUIRE(evaluator.evaluateDomain("www.example.com").matchedRuleId == "exact");
}

TEST_CASE("application rules implement per-app tunnels", "[routing][app]")
{
    // TikTok -> Hong Kong, Steam -> Japan, Discord -> Singapore, Chrome direct.
    RoutingPolicy policy;
    policy.defaultDisposition = Disposition::Direct;
    policy.applicationRules.push_back(
        makeAppRule("tiktok", "C:\\Program Files\\TikTok LIVE Studio\\studio.exe",
                    Disposition::Tunnel, "hk"));
    policy.applicationRules.push_back(
        makeAppRule("steam", "C:\\Program Files (x86)\\Steam\\steam.exe", Disposition::Tunnel,
                    "jp"));
    policy.applicationRules.push_back(
        makeAppRule("discord", "*\\Discord.exe", Disposition::Tunnel, "sg"));

    const PolicyEvaluator evaluator{policy};

    REQUIRE(evaluator.evaluateApplication("C:\\Program Files\\TikTok LIVE Studio\\studio.exe")
                .tunnelId == "hk");
    REQUIRE(evaluator.evaluateApplication("C:\\Program Files (x86)\\Steam\\steam.exe")
                .tunnelId == "jp");
    REQUIRE(evaluator.evaluateApplication("C:\\Users\\me\\AppData\\Local\\Discord\\Discord.exe")
                .tunnelId == "sg");
    REQUIRE(evaluator.evaluateApplication("C:\\Program Files\\Google\\Chrome\\chrome.exe")
                .disposition == Disposition::Direct);
}

TEST_CASE("application matching is case-insensitive", "[routing][app]")
{
    RoutingPolicy policy;
    policy.applicationRules.push_back(
        makeAppRule("np", "c:\\windows\\notepad.exe", Disposition::Tunnel, "hk"));

    const PolicyEvaluator evaluator{policy};
    REQUIRE(evaluator.evaluateApplication("C:\\Windows\\Notepad.exe").matchedRuleId == "np");
}

TEST_CASE("an exact application path beats a glob", "[routing][app]")
{
    RoutingPolicy policy;
    policy.applicationRules.push_back(makeAppRule("glob", "*\\chrome.exe", Disposition::Tunnel,
                                                  "hk"));
    policy.applicationRules.push_back(
        makeAppRule("exact", "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                    Disposition::Direct));

    const PolicyEvaluator evaluator{policy};
    const auto decision =
        evaluator.evaluateApplication("C:\\Program Files\\Google\\Chrome\\chrome.exe");

    REQUIRE(decision.matchedRuleId == "exact");
    REQUIRE(decision.disposition == Disposition::Direct);
}

TEST_CASE("policy validation catches unusable rules", "[routing][validation]")
{
    const std::vector<Id> tunnels{"hk", "jp"};

    SECTION("a valid policy passes")
    {
        RoutingPolicy policy;
        policy.defaultTunnelId = "hk";
        policy.ipRules.push_back(makeIpRule("a", "10.0.0.0/8", Disposition::Tunnel, "jp"));
        policy.domainRules.push_back(makeDomainRule("b", "*.example.com", Disposition::Direct));
        REQUIRE(policy.validate(tunnels).isOk());
    }

    SECTION("a rule without an id is rejected")
    {
        RoutingPolicy policy;
        policy.ipRules.push_back(makeIpRule("", "10.0.0.0/8", Disposition::Direct));
        REQUIRE(policy.validate(tunnels).code() == ErrorCode::InvalidArgument);
    }

    SECTION("duplicate ids are rejected")
    {
        RoutingPolicy policy;
        policy.ipRules.push_back(makeIpRule("dup", "10.0.0.0/8", Disposition::Direct));
        policy.domainRules.push_back(makeDomainRule("dup", "*.a.com", Disposition::Direct));
        REQUIRE(policy.validate(tunnels).code() == ErrorCode::AlreadyExists);
    }

    SECTION("a rule targeting an unknown tunnel is rejected")
    {
        RoutingPolicy policy;
        policy.ipRules.push_back(makeIpRule("a", "10.0.0.0/8", Disposition::Tunnel, "nowhere"));
        REQUIRE(policy.validate(tunnels).code() == ErrorCode::NotFound);
    }

    SECTION("a catch-all domain rule is rejected")
    {
        RoutingPolicy policy;
        policy.domainRules.push_back(makeDomainRule("all", "*", Disposition::Direct));
        REQUIRE(policy.validate(tunnels).isError());
    }

    SECTION("an application rule without a path is rejected")
    {
        RoutingPolicy policy;
        policy.applicationRules.push_back(makeAppRule("a", "", Disposition::Direct));
        REQUIRE(policy.validate(tunnels).isError());
    }

    SECTION("a malformed country code is rejected")
    {
        RoutingPolicy policy;
        CountryRule rule;
        rule.id          = "c";
        rule.countryCode = "JPN";
        rule.disposition = Disposition::Direct;
        policy.countryRules.push_back(rule);
        REQUIRE(policy.validate(tunnels).isError());
    }

    SECTION("an unknown default tunnel is rejected")
    {
        RoutingPolicy policy;
        policy.defaultTunnelId = "nowhere";
        REQUIRE(policy.validate(tunnels).code() == ErrorCode::NotFound);
    }
}
