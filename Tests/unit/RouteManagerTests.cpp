// Route-table mutation needs elevation and would alter the machine the tests
// run on, so these cover the pure logic: default-route expansion, the ledger
// serialisation and the recovery paths that never touch the live table.
#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Routing/RouteManager.h>

#include <catch2/catch_test_macros.hpp>

#include <filesystem>

using namespace nova;
using namespace nova::routing;

namespace {

class ScratchDirectory {
public:
    ScratchDirectory()
        : m_path(std::filesystem::temp_directory_path() /
                 ("novavpn-test-" + Uuid::generate().toString()))
    {
        std::filesystem::create_directories(m_path);
    }
    ~ScratchDirectory()
    {
        std::error_code ec;
        std::filesystem::remove_all(m_path, ec);
    }
    [[nodiscard]] std::filesystem::path file(std::string_view name) const
    {
        return m_path / name;
    }

private:
    std::filesystem::path m_path;
};

} // namespace

TEST_CASE("SplitHalves expands to the two half-space routes", "[routing][routes]")
{
    const auto v4 = defaultRouteEntries(DefaultRouteMode::SplitHalves, AddressFamily::IPv4, 7);
    REQUIRE(v4.size() == 2);
    REQUIRE(v4[0].destination.toString() == "0.0.0.0/1");
    REQUIRE(v4[1].destination.toString() == "128.0.0.0/1");
    REQUIRE(v4[0].interfaceIndex == 7);
    REQUIRE_FALSE(v4[0].nextHop.has_value()); // on-link on the tunnel adapter

    const auto v6 = defaultRouteEntries(DefaultRouteMode::SplitHalves, AddressFamily::IPv6, 7);
    REQUIRE(v6.size() == 2);
    REQUIRE(v6[0].destination.toString() == "::/1");
    REQUIRE(v6[1].destination.toString() == "8000::/1");

    // Together the halves cover every address - that is the entire point.
    REQUIRE((v4[0].destination.contains(net::IpAddress::parse("8.8.8.8").value()) ||
             v4[1].destination.contains(net::IpAddress::parse("8.8.8.8").value())));
    REQUIRE((v4[0].destination.contains(net::IpAddress::parse("200.1.2.3").value()) ||
             v4[1].destination.contains(net::IpAddress::parse("200.1.2.3").value())));
}

TEST_CASE("Replace expands to a single default; None to nothing", "[routing][routes]")
{
    const auto replace =
        defaultRouteEntries(DefaultRouteMode::Replace, AddressFamily::IPv4, 3);
    REQUIRE(replace.size() == 1);
    REQUIRE(replace[0].destination.toString() == "0.0.0.0/0");

    REQUIRE(defaultRouteEntries(DefaultRouteMode::None, AddressFamily::IPv4, 3).empty());
}

TEST_CASE("route entries round-trip through the ledger format", "[routing][routes]")
{
    RouteEntry original;
    original.destination    = net::IpRange::parse("10.8.0.0/16").value();
    original.nextHop        = net::IpAddress::parse("192.168.1.1").value();
    original.interfaceIndex = 12;
    original.metric         = 5;

    const auto decoded = routeEntryFromJson(toJson(original));
    REQUIRE(decoded.isOk());
    REQUIRE(decoded.value().destination == original.destination);
    REQUIRE(decoded.value().nextHop == original.nextHop);
    REQUIRE(decoded.value().interfaceIndex == 12);
    REQUIRE(decoded.value().metric == 5);

    // On-link entries have no next hop and must stay that way.
    RouteEntry onLink;
    onLink.destination    = net::IpRange::parse("0.0.0.0/1").value();
    onLink.interfaceIndex = 3;
    const auto decodedOnLink = routeEntryFromJson(toJson(onLink));
    REQUIRE(decodedOnLink.isOk());
    REQUIRE_FALSE(decodedOnLink.value().nextHop.has_value());
}

TEST_CASE("malformed ledger entries are rejected", "[routing][routes]")
{
    REQUIRE(routeEntryFromJson(Json::array()).isError());
    REQUIRE(routeEntryFromJson(Json{{"destination", "not-a-cidr"}}).isError());
    // A missing interface index cannot be reconstructed into a deletable row.
    REQUIRE(routeEntryFromJson(Json{{"destination", "10.0.0.0/8"}}).isError());
    REQUIRE(routeEntryFromJson(
                Json{{"destination", "10.0.0.0/8"}, {"interfaceIndex", 3}, {"nextHop", "junk"}})
                .isError());
}

TEST_CASE("a fresh manager has an empty ledger and reconcile is a no-op",
          "[routing][routes]")
{
    const ScratchDirectory scratch;
    auto manager = makeRouteManager(scratch.file("routes.json"));

    const auto owned = manager->ownedRoutes();
    REQUIRE(owned.isOk());
    REQUIRE(owned.value().empty());

    // No ledger file, nothing recorded: reconcile must succeed silently.
    REQUIRE(manager->reconcile().isOk());
    REQUIRE(manager->removeAllOwnedRoutes().isOk());
}

TEST_CASE("a corrupt ledger degrades to empty instead of failing construction",
          "[routing][routes]")
{
    const ScratchDirectory scratch;
    const auto path = scratch.file("routes.json");

    REQUIRE(nova::file::writeAtomicText(path, "{ not json").isOk());

    auto manager = makeRouteManager(path);
    REQUIRE(manager->ownedRoutes().value().empty());
    REQUIRE(manager->reconcile().isOk());
}

TEST_CASE("the ledger survives a manager restart", "[routing][routes]")
{
    // Written through the public JSON helpers rather than addRoute (which
    // would need elevation); this is exactly what a crashed run leaves behind.
    const ScratchDirectory scratch;
    const auto path = scratch.file("routes.json");

    RouteEntry entry;
    entry.destination    = net::IpRange::parse("203.0.113.7/32").value();
    entry.nextHop        = net::IpAddress::parse("192.168.1.1").value();
    entry.interfaceIndex = 9;

    Json ledger = Json::array();
    ledger.push_back(toJson(entry));
    REQUIRE(nova::json::writeFile(path, ledger).isOk());

    auto manager = makeRouteManager(path);
    const auto owned = manager->ownedRoutes();
    REQUIRE(owned.isOk());
    REQUIRE(owned.value().size() == 1);
    REQUIRE(owned.value()[0].destination.toString() == "203.0.113.7/32");
}
