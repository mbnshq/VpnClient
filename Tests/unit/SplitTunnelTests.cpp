#include <NovaVPN/SplitTunnel/ProcessRegistry.h>
#include <NovaVPN/SplitTunnel/SplitTunnelEngine.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::splittunnel;

namespace {

AppBinding app(std::string path, std::string tunnel = "", bool enabled = true)
{
    AppBinding binding;
    binding.imagePath = std::move(path);
    binding.displayName = binding.imagePath;
    binding.tunnelId = std::move(tunnel);
    binding.enabled = enabled;
    return binding;
}

} // namespace

TEST_CASE("include mode tunnels only the listed apps", "[splittunnel][classify]")
{
    // ☑ TikTok, ☑ Discord tunnelled; Chrome (unlisted) direct.
    SplitTunnelConfig config;
    config.enabled = true;
    config.mode = SplitMode::Include;
    config.applications = {
        app("C:\\Apps\\TikTok LIVE Studio\\studio.exe", "hk"),
        app("C:\\Apps\\Discord\\Discord.exe", "sg"),
    };

    SplitTunnelClassifier classifier{config};

    REQUIRE(classifier.classify("C:\\Apps\\TikTok LIVE Studio\\studio.exe").disposition ==
            routing::Disposition::Tunnel);
    REQUIRE(classifier.classify("C:\\Apps\\TikTok LIVE Studio\\studio.exe").tunnelId == "hk");
    REQUIRE(classifier.classify("C:\\Apps\\Discord\\Discord.exe").tunnelId == "sg");

    // Chrome is not listed -> direct.
    REQUIRE(classifier.classify("C:\\Program Files\\Google\\Chrome\\chrome.exe").disposition ==
            routing::Disposition::Direct);
}

TEST_CASE("exclude mode tunnels everything except the listed apps",
          "[splittunnel][classify]")
{
    SplitTunnelConfig config;
    config.mode = SplitMode::Exclude;
    config.applications = { app("C:\\Games\\Steam\\steam.exe") };

    SplitTunnelClassifier classifier{config};

    // Steam is excluded -> direct.
    REQUIRE(classifier.classify("C:\\Games\\Steam\\steam.exe").disposition ==
            routing::Disposition::Direct);
    // Everything else is tunnelled.
    REQUIRE(classifier.classify("C:\\Apps\\Whatsapp\\whatsapp.exe").disposition ==
            routing::Disposition::Tunnel);
}

TEST_CASE("a disabled app binding is ignored", "[splittunnel][classify]")
{
    SplitTunnelConfig config;
    config.mode = SplitMode::Include;
    config.applications = { app("C:\\Apps\\X\\x.exe", "hk", /*enabled=*/false) };

    SplitTunnelClassifier classifier{config};
    // Disabled binding + include mode -> falls to the default (direct).
    REQUIRE(classifier.classify("C:\\Apps\\X\\x.exe").disposition ==
            routing::Disposition::Direct);
}

TEST_CASE("an explicit IP rule overrides the app decision",
          "[splittunnel][classify]")
{
    SplitTunnelConfig config;
    config.mode = SplitMode::Include; // apps default to direct
    routing::IpRule ipRule;
    ipRule.id = "pin";
    ipRule.range = net::IpRange::parse("203.0.113.0/24").value();
    ipRule.disposition = routing::Disposition::Tunnel;
    ipRule.tunnelId = "jp";
    config.ipRules.push_back(ipRule);

    SplitTunnelClassifier classifier{config};

    // Chrome would be direct by app policy, but the pinned IP range tunnels it.
    auto decision = classifier.classify("C:\\chrome.exe",
                                        net::IpAddress::parse("203.0.113.9").value());
    REQUIRE(decision.disposition == routing::Disposition::Tunnel);
    REQUIRE(decision.tunnelId == "jp");

    // A remote outside the pinned range follows the app policy (direct).
    REQUIRE(classifier.classify("C:\\chrome.exe",
                                net::IpAddress::parse("8.8.8.8").value())
                .disposition == routing::Disposition::Direct);
}

TEST_CASE("setConfig re-evaluates against the new rules", "[splittunnel][classify]")
{
    SplitTunnelClassifier classifier{SplitTunnelConfig{}};

    SplitTunnelConfig include;
    include.mode = SplitMode::Include;
    include.applications = { app("C:\\a.exe", "hk") };
    classifier.setConfig(include);
    REQUIRE(classifier.classify("C:\\a.exe").disposition == routing::Disposition::Tunnel);

    SplitTunnelConfig empty;
    empty.mode = SplitMode::Include;
    classifier.setConfig(empty);
    REQUIRE(classifier.classify("C:\\a.exe").disposition == routing::Disposition::Direct);
}

TEST_CASE("split modes round-trip through text", "[splittunnel]")
{
    SplitMode mode = SplitMode::Include;
    REQUIRE(parseSplitMode("exclude", mode));
    REQUIRE(mode == SplitMode::Exclude);
    REQUIRE(parseSplitMode("allowlist", mode));
    REQUIRE(mode == SplitMode::Include);
    REQUIRE_FALSE(parseSplitMode("maybe", mode));
    REQUIRE(toString(SplitMode::Exclude) == "exclude");
}

TEST_CASE("the engine applies config and reports affected processes",
          "[splittunnel][engine]")
{
    auto registry = makeProcessRegistry();
    REQUIRE(registry->start().isOk());
    auto engine = makeSplitTunnelEngine(registry);

    REQUIRE(engine->start().isOk());

    SplitTunnelConfig config;
    config.mode = SplitMode::Include;
    // Match the test binary itself so at least one running process is affected.
    config.applications = { app("*\\novavpn_unit_tests.exe", "hk") };

    auto affected = engine->apply(config);
    REQUIRE(affected.isOk());
    // Our own process should be in the affected set.
    REQUIRE_FALSE(affected.value().empty());

    // recentFlows starts empty and processTraffic works.
    REQUIRE(engine->recentFlows(10).value().empty());
    REQUIRE(engine->processTraffic().isOk());

    engine->stop();
}
