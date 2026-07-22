#include <NovaVPN/Networking/IpAddress.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::net;

TEST_CASE("IPv4 parsing accepts canonical dotted quads", "[net][ip]")
{
    const auto address = IpAddress::parse("192.168.1.1");
    REQUIRE(address.isOk());
    REQUIRE(address.value().isV4());
    REQUIRE(address.value().toString() == "192.168.1.1");

    REQUIRE(IpAddress::parse("0.0.0.0").value().isUnspecified());
    REQUIRE(IpAddress::parse("255.255.255.255").isOk());
    REQUIRE(IpAddress::parse("  10.0.0.1  ").isOk()); // surrounding space is trimmed
}

TEST_CASE("IPv4 parsing rejects ambiguous and malformed forms", "[net][ip][security]")
{
    // Leading zeros are octal to some resolvers and decimal to others; that
    // ambiguity has produced real SSRF and ACL-bypass bugs, so it is rejected.
    REQUIRE(IpAddress::parse("010.0.0.1").isError());
    REQUIRE(IpAddress::parse("192.168.01.1").isError());

    REQUIRE(IpAddress::parse("256.0.0.1").isError());
    REQUIRE(IpAddress::parse("1.2.3").isError());
    REQUIRE(IpAddress::parse("1.2.3.4.5").isError());
    REQUIRE(IpAddress::parse("1.2.3.").isError());
    REQUIRE(IpAddress::parse("1.2.3.4x").isError());
    REQUIRE(IpAddress::parse("").isError());
    REQUIRE(IpAddress::parse("-1.2.3.4").isError());
}

TEST_CASE("IPv6 parsing handles compression and mixed notation", "[net][ip]")
{
    REQUIRE(IpAddress::parse("::").value().isUnspecified());
    REQUIRE(IpAddress::parse("::1").value().isLoopback());
    REQUIRE(IpAddress::parse("2001:db8::1").isOk());
    REQUIRE(IpAddress::parse("2001:0db8:0000:0000:0000:0000:0000:0001").isOk());
    REQUIRE(IpAddress::parse("fe80::1").value().isLinkLocal());
    REQUIRE(IpAddress::parse("::ffff:192.168.1.1").isOk());
}

TEST_CASE("IPv6 parsing rejects malformed forms", "[net][ip]")
{
    REQUIRE(IpAddress::parse(":::").isError());
    REQUIRE(IpAddress::parse("2001:db8::1::2").isError()); // two compressions
    REQUIRE(IpAddress::parse("2001:db8:").isError());
    REQUIRE(IpAddress::parse("12345::1").isError());
    REQUIRE(IpAddress::parse("2001:db8:0:0:0:0:0:0:1").isError()); // nine groups
    REQUIRE(IpAddress::parse("gggg::1").isError());
}

TEST_CASE("IPv6 formatting follows RFC 5952", "[net][ip]")
{
    REQUIRE(IpAddress::parse("2001:0db8:0000:0000:0000:0000:0000:0001").value().toString() ==
            "2001:db8::1");
    REQUIRE(IpAddress::parse("::").value().toString() == "::");
    REQUIRE(IpAddress::parse("::1").value().toString() == "::1");
    REQUIRE(IpAddress::parse("FE80::ABCD").value().toString() == "fe80::abcd");
}

TEST_CASE("address classification drives leak protection", "[net][ip]")
{
    REQUIRE(IpAddress::parse("127.0.0.1").value().isLoopback());
    REQUIRE(IpAddress::parse("169.254.1.1").value().isLinkLocal());
    REQUIRE(IpAddress::parse("224.0.0.1").value().isMulticast());

    REQUIRE(IpAddress::parse("10.1.2.3").value().isPrivate());
    REQUIRE(IpAddress::parse("172.16.0.1").value().isPrivate());
    REQUIRE(IpAddress::parse("172.32.0.1").value().isPrivate() == false);
    REQUIRE(IpAddress::parse("192.168.0.1").value().isPrivate());
    REQUIRE(IpAddress::parse("100.64.0.1").value().isPrivate()); // CGNAT
    REQUIRE(IpAddress::parse("fd00::1").value().isPrivate());

    REQUIRE(IpAddress::parse("8.8.8.8").value().isGlobalUnicast());
    REQUIRE_FALSE(IpAddress::parse("192.168.1.1").value().isGlobalUnicast());
    REQUIRE_FALSE(IpAddress::parse("::1").value().isGlobalUnicast());
}

TEST_CASE("IPv4-mapped addresses normalise to IPv4", "[net][ip][security]")
{
    // Without normalisation, "::ffff:10.0.0.1" would slip past an IPv4 rule for
    // 10.0.0.0/8 - a genuine split-tunnel bypass.
    const auto mapped = IpAddress::parse("::ffff:10.0.0.1").value();
    REQUIRE(mapped.isV6());

    const auto normalized = mapped.normalized();
    REQUIRE(normalized.isV4());
    REQUIRE(normalized.toString() == "10.0.0.1");

    const auto plain = IpAddress::parse("2001:db8::1").value();
    REQUIRE(plain.normalized() == plain);
}

TEST_CASE("addresses compare and order deterministically", "[net][ip]")
{
    const auto a = IpAddress::parse("10.0.0.1").value();
    const auto b = IpAddress::parse("10.0.0.2").value();

    REQUIRE(a == IpAddress::parse("10.0.0.1").value());
    REQUIRE(a != b);
    REQUIRE(a < b);
    REQUIRE(IpAddress::parse("10.0.0.1").value() < IpAddress::parse("::1").value());
}

TEST_CASE("CIDR parsing masks host bits", "[net][cidr]")
{
    const auto range = IpRange::parse("10.1.2.3/8");
    REQUIRE(range.isOk());
    REQUIRE(range.value().network().toString() == "10.0.0.0");
    REQUIRE(range.value().prefixLength() == 8);
    REQUIRE(range.value().toString() == "10.0.0.0/8");

    // A bare address is a host route.
    REQUIRE(IpRange::parse("192.168.1.1").value().prefixLength() == 32);
    REQUIRE(IpRange::parse("2001:db8::1").value().prefixLength() == 128);
}

TEST_CASE("CIDR parsing rejects impossible prefixes", "[net][cidr]")
{
    REQUIRE(IpRange::parse("10.0.0.0/33").isError());
    REQUIRE(IpRange::parse("2001:db8::/129").isError());
    REQUIRE(IpRange::parse("10.0.0.0/").isError());
    REQUIRE(IpRange::parse("10.0.0.0/abc").isError());
    REQUIRE(IpRange::parse("10.0.0.0/8/8").isError());
}

TEST_CASE("containment respects prefix boundaries", "[net][cidr]")
{
    const auto range = IpRange::parse("192.168.1.0/24").value();

    REQUIRE(range.contains(IpAddress::parse("192.168.1.0").value()));
    REQUIRE(range.contains(IpAddress::parse("192.168.1.255").value()));
    REQUIRE_FALSE(range.contains(IpAddress::parse("192.168.2.1").value()));
    // Cross-family containment is always false.
    REQUIRE_FALSE(range.contains(IpAddress::parse("::1").value()));

    const auto slash23 = IpRange::parse("192.168.0.0/23").value();
    REQUIRE(slash23.contains(IpAddress::parse("192.168.1.5").value()));
    REQUIRE_FALSE(slash23.contains(IpAddress::parse("192.168.2.5").value()));

    // A /0 covers the whole family - this is the default route.
    const auto everything = IpRange::parse("0.0.0.0/0").value();
    REQUIRE(everything.contains(IpAddress::parse("8.8.8.8").value()));
    REQUIRE(everything.contains(IpAddress::parse("10.0.0.1").value()));
}

TEST_CASE("range containment nests correctly", "[net][cidr]")
{
    const auto outer = IpRange::parse("10.0.0.0/8").value();
    const auto inner = IpRange::parse("10.1.0.0/16").value();

    REQUIRE(outer.contains(inner));
    REQUIRE_FALSE(inner.contains(outer));
    REQUIRE(outer.contains(outer));
}

TEST_CASE("lastAddress and netmask are computed correctly", "[net][cidr]")
{
    const auto range = IpRange::parse("192.168.1.0/24").value();
    REQUIRE(range.lastAddress().toString() == "192.168.1.255");
    REQUIRE(range.netmaskV4().has_value());
    REQUIRE(range.netmaskV4()->toString() == "255.255.255.0");

    REQUIRE(IpRange::parse("10.0.0.0/8").value().netmaskV4()->toString() == "255.0.0.0");
    REQUIRE(IpRange::parse("10.0.0.0/31").value().netmaskV4()->toString() == "255.255.255.254");
    REQUIRE_FALSE(IpRange::parse("2001:db8::/32").value().netmaskV4().has_value());
}

TEST_CASE("endpoints parse both address families", "[net][endpoint]")
{
    const auto v4 = Endpoint::parse("1.2.3.4:1194");
    REQUIRE(v4.isOk());
    REQUIRE(v4.value().port() == 1194);
    REQUIRE(v4.value().toString() == "1.2.3.4:1194");

    const auto v6 = Endpoint::parse("[2001:db8::1]:443");
    REQUIRE(v6.isOk());
    REQUIRE(v6.value().port() == 443);
    REQUIRE(v6.value().toString() == "[2001:db8::1]:443");
}

TEST_CASE("endpoint parsing rejects bad input", "[net][endpoint]")
{
    REQUIRE(Endpoint::parse("1.2.3.4").isError());       // no port
    REQUIRE(Endpoint::parse("1.2.3.4:0").isError());     // port 0
    REQUIRE(Endpoint::parse("1.2.3.4:65536").isError()); // out of range
    REQUIRE(Endpoint::parse("1.2.3.4:abc").isError());
    REQUIRE(Endpoint::parse("[2001:db8::1]").isError()); // bracketed, no port
    REQUIRE(Endpoint::parse("").isError());
}

TEST_CASE("host name validation follows RFC 1123", "[net][host]")
{
    REQUIRE(isValidHostName("hk1.example.net"));
    REQUIRE(isValidHostName("a"));
    REQUIRE(isValidHostName("vpn-01.corp.example.com"));
    REQUIRE(isValidHostName("_service.example.com")); // deliberate allowance

    REQUIRE_FALSE(isValidHostName(""));
    REQUIRE_FALSE(isValidHostName(".example.com"));
    REQUIRE_FALSE(isValidHostName("example.com."));
    REQUIRE_FALSE(isValidHostName("a..b"));
    REQUIRE_FALSE(isValidHostName("-bad.example.com"));
    REQUIRE_FALSE(isValidHostName("bad-.example.com"));
    REQUIRE_FALSE(isValidHostName("has space.com"));
    REQUIRE_FALSE(isValidHostName(std::string(64, 'a') + ".com")); // label too long
}

TEST_CASE("HostEndpoint renders for logs", "[net][host]")
{
    HostEndpoint host{"hk1.example.net", 1194, Transport::Udp};
    REQUIRE(host.toString() == "hk1.example.net:1194/udp");
    REQUIRE_FALSE(host.isLiteralAddress());

    HostEndpoint literal{"2001:db8::1", 443, Transport::Tcp};
    REQUIRE(literal.isLiteralAddress());
    REQUIRE(literal.toString() == "[2001:db8::1]:443/tcp");
}
