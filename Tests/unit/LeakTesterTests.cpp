// The leak tester inspects the live machine's network configuration through the
// network monitor, so these assert its logic against whatever this machine
// reports: a clean run with no monitor errors, and internal consistency of the
// flags it raises.
#include <NovaVPN/Firewall/FirewallEngine.h>
#include <NovaVPN/Networking/NetworkMonitor.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::firewall;

TEST_CASE("a leak test runs against the live network", "[firewall][leak]")
{
    auto monitor = net::makeNetworkMonitor(nullptr);
    auto tester = makeLeakTester(monitor, {});

    CancellationSource source;
    auto result = tester->run(source.token());
    REQUIRE(result.isOk());

    // Whatever the verdict, the flags are internally consistent: a DNS-leak
    // flag implies at least one observed resolver, and a details line exists
    // for each leak kind that fired.
    if (result.value().dnsLeak)
    {
        REQUIRE_FALSE(result.value().observedResolvers.empty());
    }
    if (result.value().ipv6Leak || result.value().dnsLeak)
    {
        REQUIRE_FALSE(result.value().details.empty());
    }
}

TEST_CASE("a cancelled leak test aborts", "[firewall][leak]")
{
    auto monitor = net::makeNetworkMonitor(nullptr);
    auto tester = makeLeakTester(monitor, {});

    CancellationSource source;
    source.cancel();
    auto result = tester->run(source.token());
    REQUIRE(result.isError());
    REQUIRE(result.status().code() == ErrorCode::Cancelled);
}

TEST_CASE("a leak tester without a monitor reports InvalidState", "[firewall][leak]")
{
    auto tester = makeLeakTester(nullptr, {});
    CancellationSource source;
    REQUIRE(tester->run(source.token()).status().code() == ErrorCode::InvalidState);
}

TEST_CASE("observed resolvers are de-duplicated", "[firewall][leak]")
{
    // Two runs against the same machine must report the same de-duplicated
    // resolver set (it is sorted+uniqued), proving the tidy-up is stable.
    auto monitor = net::makeNetworkMonitor(nullptr);
    auto tester = makeLeakTester(monitor, {});
    CancellationSource source;

    auto first = tester->run(source.token());
    auto second = tester->run(source.token());
    REQUIRE(first.isOk());
    REQUIRE(second.isOk());
    REQUIRE(first.value().observedResolvers.size() ==
            second.value().observedResolvers.size());

    // The resolver list has no adjacent duplicates.
    const auto& resolvers = first.value().observedResolvers;
    for (std::size_t i = 1; i < resolvers.size(); ++i)
    {
        REQUIRE_FALSE(resolvers[i - 1] == resolvers[i]);
    }
}
