// Resolver tests avoid the public internet: literals never touch the network,
// "localhost" is answered from the hosts file, and ".invalid" is reserved by
// RFC 2606 to never resolve. That keeps the suite deterministic offline.
#include <NovaVPN/Networking/Resolver.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::net;

TEST_CASE("a literal address short-circuits without a query", "[net][resolver]")
{
    auto resolver = makeResolver(nullptr);

    ResolveOptions options;
    options.scope = ResolutionScope::System;
    // Timeout of 1 ms proves no network round trip happens: a real query could
    // not complete, a literal must.
    options.timeout = Milliseconds{1};

    const auto v4 = resolver->resolve("203.0.113.9", options, {});
    REQUIRE(v4.isOk());
    REQUIRE(v4.value().addresses.size() == 1);
    REQUIRE(v4.value().addresses[0].toString() == "203.0.113.9");
    REQUIRE(v4.value().resolverUsed == "literal");

    const auto v6 = resolver->resolve("2001:db8::1", options, {});
    REQUIRE(v6.isOk());
    REQUIRE(v6.value().addresses[0].isV6());
}

TEST_CASE("a literal must match the requested family", "[net][resolver]")
{
    auto resolver = makeResolver(nullptr);

    ResolveOptions options;
    options.family = AddressFamily::IPv6;

    REQUIRE(resolver->resolve("203.0.113.9", options, {}).isError());

    options.family = AddressFamily::IPv4;
    REQUIRE(resolver->resolve("203.0.113.9", options, {}).isOk());
}

TEST_CASE("garbage host names are rejected before any query", "[net][resolver]")
{
    auto resolver = makeResolver(nullptr);

    REQUIRE(resolver->resolve("", {}, {}).isError());
    REQUIRE(resolver->resolve("has space.com", {}, {}).isError());
    REQUIRE(resolver->resolve("bad..dots", {}, {}).isError());
}

TEST_CASE("localhost resolves through the system scope", "[net][resolver]")
{
    auto resolver = makeResolver(nullptr);

    ResolveOptions options;
    options.scope   = ResolutionScope::System;
    options.timeout = Milliseconds{5000};

    const auto resolved = resolver->resolve("localhost", options, {});
    REQUIRE(resolved.isOk());
    REQUIRE_FALSE(resolved.value().addresses.empty());

    for (const auto& address : resolved.value().addresses) {
        REQUIRE(address.isLoopback());
    }
}

TEST_CASE("a name reserved to never exist reports an error, not an empty answer",
          "[net][resolver]")
{
    auto resolver = makeResolver(nullptr);

    ResolveOptions options;
    options.timeout = Milliseconds{5000};

    const auto resolved = resolver->resolve("nonexistent.invalid", options, {});
    REQUIRE(resolved.isError());
}

TEST_CASE("tunnel scope without a bound tunnel is an invalid state",
          "[net][resolver]")
{
    auto resolver = makeResolver(nullptr);

    ResolveOptions options;
    options.scope = ResolutionScope::Tunnel;

    const auto resolved = resolver->resolve("localhost", options, {});
    REQUIRE(resolved.isError());
    REQUIRE(resolved.status().code() == ErrorCode::InvalidState);
}

TEST_CASE("binding and clearing the tunnel scope flushes the cache",
          "[net][resolver]")
{
    auto resolver = makeResolver(nullptr);

    ScopeBinding binding;
    binding.interfaceIndex = 1; // loopback pseudo-interface: harmless target
    resolver->setTunnelBinding(binding);

    // With a binding installed the scope is at least accepted; resolution of
    // localhost goes through the hosts file regardless of pinning.
    ResolveOptions options;
    options.scope   = ResolutionScope::Tunnel;
    options.timeout = Milliseconds{5000};
    const auto bound = resolver->resolve("localhost", options, {});
    REQUIRE(bound.isOk());

    resolver->setTunnelBinding(std::nullopt);
    REQUIRE(resolver->resolve("localhost", options, {}).isError());
}

TEST_CASE("a pre-cancelled token aborts immediately", "[net][resolver]")
{
    auto resolver = makeResolver(nullptr);

    CancellationSource source;
    source.cancel();

    ResolveOptions options;
    options.timeout = Milliseconds{5000};

    const auto resolved = resolver->resolve("localhost", options, source.token());
    REQUIRE(resolved.isError());
    REQUIRE(resolved.status().code() == ErrorCode::Cancelled);
}

TEST_CASE("flushCache and flushSystemCache do not fault", "[net][resolver]")
{
    auto resolver = makeResolver(nullptr);
    resolver->flushCache();
    // System-cache flush needs the DNS client service; either outcome is
    // legitimate here, faulting is not.
    (void)resolver->flushSystemCache();
}
