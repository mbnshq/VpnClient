#include <NovaVPN/Core/EventBus.h>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace nova;

namespace {

struct TunnelUp {
    std::string tunnelId;
};

struct TunnelDown {
    std::string tunnelId;
    int         reason = 0;
};

} // namespace

TEST_CASE("handlers receive events of their own type only", "[eventbus]")
{
    auto bus = EventBus::create();

    std::vector<std::string> up;
    std::vector<std::string> down;

    auto upSub = bus->subscribe<TunnelUp>([&up](const TunnelUp& e) { up.push_back(e.tunnelId); });
    auto downSub =
        bus->subscribe<TunnelDown>([&down](const TunnelDown& e) { down.push_back(e.tunnelId); });

    bus->publish(TunnelUp{"hk-01"});
    bus->publish(TunnelDown{"jp-02", 7});
    bus->publish(TunnelUp{"sg-03"});

    REQUIRE(up == std::vector<std::string>{"hk-01", "sg-03"});
    REQUIRE(down == std::vector<std::string>{"jp-02"});
}

TEST_CASE("every subscriber of a type is invoked", "[eventbus]")
{
    auto bus = EventBus::create();

    int first = 0;
    int second = 0;
    auto a = bus->subscribe<TunnelUp>([&first](const TunnelUp&) { ++first; });
    auto b = bus->subscribe<TunnelUp>([&second](const TunnelUp&) { ++second; });

    REQUIRE(bus->subscriberCount<TunnelUp>() == 2);

    bus->publish(TunnelUp{"hk-01"});

    REQUIRE(first == 1);
    REQUIRE(second == 1);
}

TEST_CASE("a destroyed subscription stops receiving", "[eventbus]")
{
    auto bus = EventBus::create();
    int calls = 0;

    {
        auto subscription = bus->subscribe<TunnelUp>([&calls](const TunnelUp&) { ++calls; });
        bus->publish(TunnelUp{"a"});
        REQUIRE(calls == 1);
        REQUIRE(bus->subscriberCount<TunnelUp>() == 1);
    }

    bus->publish(TunnelUp{"b"});
    REQUIRE(calls == 1);
    REQUIRE(bus->subscriberCount<TunnelUp>() == 0);
}

TEST_CASE("subscriptions are movable", "[eventbus]")
{
    auto bus = EventBus::create();
    int calls = 0;

    auto original = bus->subscribe<TunnelUp>([&calls](const TunnelUp&) { ++calls; });
    auto moved = std::move(original);

    REQUIRE(moved.isActive());
    REQUIRE_FALSE(original.isActive()); // NOLINT - checking the moved-from state

    bus->publish(TunnelUp{"a"});
    REQUIRE(calls == 1);

    moved.reset();
    bus->publish(TunnelUp{"b"});
    REQUIRE(calls == 1);
}

TEST_CASE("publishing with no subscribers is a no-op", "[eventbus]")
{
    auto bus = EventBus::create();
    REQUIRE(bus->subscriberCount<TunnelUp>() == 0);
    bus->publish(TunnelUp{"nobody is listening"});
}

TEST_CASE("a handler may subscribe or unsubscribe during dispatch", "[eventbus]")
{
    // Handlers are dispatched from a snapshot, so mutating the subscriber list
    // from inside a handler must not deadlock or invalidate the iteration.
    auto bus = EventBus::create();

    int outer = 0;
    int inner = 0;
    EventBus::Subscription nested;

    auto subscription = bus->subscribe<TunnelUp>([&](const TunnelUp&) {
        ++outer;
        if (!nested.isActive()) {
            nested = bus->subscribe<TunnelUp>([&inner](const TunnelUp&) { ++inner; });
        }
    });

    bus->publish(TunnelUp{"first"});
    REQUIRE(outer == 1);
    REQUIRE(inner == 0); // registered during dispatch, so not called for this event

    bus->publish(TunnelUp{"second"});
    REQUIRE(outer == 2);
    REQUIRE(inner == 1);
}
