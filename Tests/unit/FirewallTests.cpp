// WFP filter application needs elevation and mutates the machine firewall, so
// the live path is tagged [.integration]. The always-on tests cover the
// mode/policy value logic and that operations on an unopened engine are refused
// cleanly.
#include <NovaVPN/Firewall/FirewallEngine.h>
#include <NovaVPN/Services/ServiceHost.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::firewall;

TEST_CASE("kill switch modes round-trip through text", "[firewall]")
{
    KillSwitchMode mode = KillSwitchMode::Off;
    REQUIRE(parseKillSwitchMode("soft", mode));
    REQUIRE(mode == KillSwitchMode::Soft);
    REQUIRE(parseKillSwitchMode("hard", mode));
    REQUIRE(mode == KillSwitchMode::Hard);
    REQUIRE(parseKillSwitchMode("always", mode));
    REQUIRE(mode == KillSwitchMode::Hard);
    REQUIRE(parseKillSwitchMode("off", mode));
    REQUIRE(mode == KillSwitchMode::Off);
    REQUIRE_FALSE(parseKillSwitchMode("sometimes", mode));

    REQUIRE(toString(KillSwitchMode::Hard) == "hard");
}

TEST_CASE("operations on an unopened engine are refused cleanly", "[firewall]")
{
    auto engine = makeFirewallEngine();

    FirewallPolicy policy;
    policy.mode = KillSwitchMode::Soft;

    REQUIRE(engine->apply(policy).code() == ErrorCode::InvalidState);
    REQUIRE(engine->clear().code() == ErrorCode::InvalidState);
    REQUIRE(engine->reconcile().code() == ErrorCode::InvalidState);
    REQUIRE(engine->activeFilters().status().code() == ErrorCode::InvalidState);
    REQUIRE_FALSE(engine->isEngaged());
    REQUIRE_FALSE(engine->currentPolicy().has_value());
}

TEST_CASE("opening the WFP engine and applying a policy", "[firewall][.integration]")
{
    if (!service::isProcessElevated()) {
        SUCCEED("skipped: WFP requires elevation");
        return;
    }

    auto engine = makeFirewallEngine();
    REQUIRE(engine->open().isOk());
    REQUIRE(engine->open().isOk()); // idempotent

    // A previous crashed run's filters are swept.
    REQUIRE(engine->reconcile().isOk());

    FirewallPolicy policy;
    policy.mode = KillSwitchMode::Soft;
    policy.exceptions.allowLoopback = true;
    policy.exceptions.allowDhcp     = true;
    policy.permittedInterfaceLuids  = {0x1234};
    policy.vpnEndpoints             = {net::Endpoint::parse("203.0.113.9:1194").value()};

    REQUIRE(engine->apply(policy).isOk());
    REQUIRE(engine->isEngaged());
    REQUIRE(engine->currentPolicy().has_value());

    // The filters we added are visible under our provider.
    auto filters = engine->activeFilters();
    REQUIRE(filters.isOk());
    REQUIRE_FALSE(filters.value().empty());

    // Off tears everything down.
    FirewallPolicy off;
    off.mode = KillSwitchMode::Off;
    REQUIRE(engine->apply(off).isOk());
    REQUIRE_FALSE(engine->isEngaged());

    REQUIRE(engine->clear().isOk());
    REQUIRE(engine->activeFilters().value().empty());

    engine->close();
}
