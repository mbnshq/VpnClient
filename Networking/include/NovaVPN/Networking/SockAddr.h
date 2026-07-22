// NovaVPN - Networking/SockAddr.h
// Conversion between the portable IpAddress/Endpoint value types and the
// Winsock SOCKADDR_INET the OS APIs speak. This is the single place the two
// representations meet; nothing else in the codebase touches sockaddr layout.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Networking/IpAddress.h>

#include <winsock2.h>
#include <ws2ipdef.h>

namespace nova::net {

/// Builds a SOCKADDR_INET. `port` is in host byte order and applies to both
/// families; 0 means "no port" (route table entries, DNS server pins).
[[nodiscard]] SOCKADDR_INET toSockAddr(const IpAddress& address, u16 port = 0) noexcept;

/// Reads the address out of a SOCKADDR_INET. Rejects families other than
/// AF_INET/AF_INET6 rather than guessing.
[[nodiscard]] Result<IpAddress> fromSockAddr(const SOCKADDR_INET& storage);

/// Reads address + port.
[[nodiscard]] Result<Endpoint> endpointFromSockAddr(const SOCKADDR_INET& storage);

/// Same conversion from the generic SOCKADDR the adapter enumeration APIs
/// hand back (validates the reported length before touching the payload).
[[nodiscard]] Result<IpAddress> fromSockAddr(const SOCKADDR* address, int length);

} // namespace nova::net
