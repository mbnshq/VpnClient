// NovaVPN - Networking/Resolver.h
// Name resolution contract.
//
// Resolution is a leak surface: if the client resolves a remote gateway through
// the tunnel's own DNS while connecting, or through the ISP resolver while
// connected, it discloses either the destination or the fact of the VPN. The
// implementation therefore has to pin *which* interface a query leaves on,
// which is why NovaVPN owns this rather than calling getaddrinfo() ad hoc.
//
// Implemented in Phase 2.
#pragma once

#include <NovaVPN/Core/Cancellation.h>
#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Networking/IpAddress.h>

#include <memory>
#include <string>
#include <vector>

namespace nova::net {

/// Which path a query must take.
enum class ResolutionScope : u8 {
    /// Force the query out of the physical adapter. Used to resolve the VPN
    /// gateway itself, both before connecting and while reconnecting under a
    /// kill switch.
    Underlay,
    /// Force the query through the tunnel's DNS servers. Used for everything
    /// the user asks for while connected.
    Tunnel,
    /// Whatever the OS would do. Only valid when no tunnel exists and leak
    /// protection is off.
    System,
};

struct ResolveOptions {
    ResolutionScope scope = ResolutionScope::System;
    /// Restrict the answer to one family. Unset resolves both.
    std::optional<AddressFamily> family;
    Milliseconds timeout{5000};
    /// Bypass the local cache (used by the DNS leak test).
    bool         noCache = false;
};

struct ResolvedHost {
    std::string            host;
    std::vector<IpAddress> addresses;
    /// TTL of the shortest record in the answer.
    Seconds                ttl{0};
    /// Which resolver produced the answer, for the diagnostics view.
    std::string            resolverUsed;
    Milliseconds           elapsed{0};
};

class IResolver {
public:
    virtual ~IResolver() = default;

    /// Resolves `host` synchronously, honouring cancellation.
    [[nodiscard]] virtual Result<ResolvedHost> resolve(const std::string& host,
                                                       const ResolveOptions& options,
                                                       const CancellationToken& token) = 0;

    /// Drops cached answers. Called whenever the tunnel comes up or goes down,
    /// because the correct answer for a name changes with the route.
    virtual void flushCache() = 0;

    /// Best-effort flush of the OS resolver cache (DnsFlushResolverCache). Kept
    /// separate because it affects the whole machine, not just NovaVPN.
    [[nodiscard]] virtual Status flushSystemCache() = 0;
};

using ResolverPtr = std::shared_ptr<IResolver>;

} // namespace nova::net
