// These exercise the monitor against the machine the tests run on, so they
// assert only what every Windows installation guarantees: enumeration works,
// a loopback interface exists, and lifecycle transitions are clean. Underlay
// presence depends on the machine having a network, so it is probed, not
// required.
#include <NovaVPN/Core/EventBus.h>
#include <NovaVPN/Networking/NetworkMonitor.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::net;

TEST_CASE("adapter enumeration succeeds and finds loopback", "[net][monitor]")
{
    auto monitor = makeNetworkMonitor(nullptr);

    const auto adapters = monitor->adapters();
    REQUIRE(adapters.isOk());
    REQUIRE_FALSE(adapters.value().empty());

    bool foundLoopback = false;
    for (const auto& adapter : adapters.value()) {
        if (adapter.type == AdapterType::Loopback) {
            foundLoopback = true;
        }
        // Every adapter must carry a stable id and an index.
        REQUIRE_FALSE(adapter.id.empty());
        REQUIRE(adapter.luid != 0);
    }
    REQUIRE(foundLoopback);
}

TEST_CASE("the underlay is never a loopback or tunnel adapter", "[net][monitor]")
{
    auto monitor = makeNetworkMonitor(nullptr);

    const auto underlay = monitor->underlayAdapter(AddressFamily::IPv4);
    if (underlay.isError()) {
        // A machine without connectivity is a legitimate state; the error must
        // say so rather than fabricating an adapter.
        REQUIRE(underlay.status().code() == ErrorCode::NotFound);
        return;
    }

    REQUIRE(underlay.value().isUp);
    REQUIRE(underlay.value().hasDefaultRouteV4);
    REQUIRE(underlay.value().type != AdapterType::Loopback);
    REQUIRE(underlay.value().type != AdapterType::Tunnel);
}

TEST_CASE("hasUnderlayConnectivity agrees with underlayAdapter", "[net][monitor]")
{
    auto monitor = makeNetworkMonitor(nullptr);

    const bool connected = monitor->hasUnderlayConnectivity();
    const bool v4 = monitor->underlayAdapter(AddressFamily::IPv4).isOk();
    const bool v6 = monitor->underlayAdapter(AddressFamily::IPv6).isOk();
    REQUIRE(connected == (v4 || v6));
}

TEST_CASE("start publishes a baseline event and stop is idempotent",
          "[net][monitor]")
{
    auto bus = EventBus::create();

    std::atomic<int> events{0};
    auto subscription = bus->subscribe<NetworkChangedEvent>(
        [&events](const NetworkChangedEvent&) { ++events; });

    auto monitor = makeNetworkMonitor(bus);
    REQUIRE(monitor->start().isOk());
    REQUIRE(monitor->start().isOk()); // second start is a no-op

    // The worker publishes one baseline snapshot on startup.
    for (int i = 0; i < 100 && events.load() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    REQUIRE(events.load() >= 1);

    monitor->stop();
    monitor->stop(); // idempotent
}
