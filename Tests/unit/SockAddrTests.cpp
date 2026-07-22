#include <NovaVPN/Networking/SockAddr.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::net;

TEST_CASE("IPv4 addresses round-trip through SOCKADDR_INET", "[net][sockaddr]")
{
    const auto original = IpAddress::parse("192.168.1.7").value();
    const SOCKADDR_INET storage = toSockAddr(original, 1194);

    REQUIRE(storage.si_family == AF_INET);
    REQUIRE(::ntohs(storage.Ipv4.sin_port) == 1194);

    const auto back = fromSockAddr(storage);
    REQUIRE(back.isOk());
    REQUIRE(back.value() == original);

    const auto endpoint = endpointFromSockAddr(storage);
    REQUIRE(endpoint.isOk());
    REQUIRE(endpoint.value().port() == 1194);
    REQUIRE(endpoint.value().address() == original);
}

TEST_CASE("IPv6 addresses round-trip through SOCKADDR_INET", "[net][sockaddr]")
{
    const auto original = IpAddress::parse("2001:db8::42").value();
    const SOCKADDR_INET storage = toSockAddr(original, 443);

    REQUIRE(storage.si_family == AF_INET6);
    REQUIRE(::ntohs(storage.Ipv6.sin6_port) == 443);

    const auto back = fromSockAddr(storage);
    REQUIRE(back.isOk());
    REQUIRE(back.value() == original);
    REQUIRE(back.value().toString() == "2001:db8::42");
}

TEST_CASE("a portless conversion carries port zero", "[net][sockaddr]")
{
    const SOCKADDR_INET storage = toSockAddr(IpAddress::loopbackV4());
    REQUIRE(storage.Ipv4.sin_port == 0);
}

TEST_CASE("unsupported families are rejected, not guessed", "[net][sockaddr]")
{
    SOCKADDR_INET bogus{};
    bogus.si_family = AF_UNIX;
    REQUIRE(fromSockAddr(bogus).isError());

    REQUIRE(fromSockAddr(nullptr, 0).isError());

    // A truncated sockaddr must not be read past its length.
    SOCKADDR short4{};
    short4.sa_family = AF_INET;
    REQUIRE(fromSockAddr(&short4, 4).isError());
}

TEST_CASE("the generic SOCKADDR overload validates length", "[net][sockaddr]")
{
    const SOCKADDR_INET storage = toSockAddr(IpAddress::parse("10.0.0.1").value());
    const auto back = fromSockAddr(reinterpret_cast<const SOCKADDR*>(&storage),
                                   sizeof(sockaddr_in));
    REQUIRE(back.isOk());
    REQUIRE(back.value().toString() == "10.0.0.1");
}
