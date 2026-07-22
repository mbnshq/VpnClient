#include <NovaVPN/Networking/SockAddr.h>

#include <cstring>

namespace nova::net {

SOCKADDR_INET toSockAddr(const IpAddress& address, u16 port) noexcept
{
    SOCKADDR_INET storage{};

    if (address.isV4()) {
        storage.Ipv4.sin_family = AF_INET;
        storage.Ipv4.sin_port   = ::htons(port);
        std::memcpy(&storage.Ipv4.sin_addr, address.bytes().data(), 4);
    } else {
        storage.Ipv6.sin6_family = AF_INET6;
        storage.Ipv6.sin6_port   = ::htons(port);
        std::memcpy(&storage.Ipv6.sin6_addr, address.bytes().data(), 16);
    }
    return storage;
}

Result<IpAddress> fromSockAddr(const SOCKADDR_INET& storage)
{
    switch (storage.si_family) {
    case AF_INET: {
        std::array<u8, 4> bytes{};
        std::memcpy(bytes.data(), &storage.Ipv4.sin_addr, 4);
        return IpAddress::fromV4(bytes);
    }
    case AF_INET6: {
        std::array<u8, 16> bytes{};
        std::memcpy(bytes.data(), &storage.Ipv6.sin6_addr, 16);
        return IpAddress::fromV6(bytes);
    }
    default:
        return err::invalidArgument("sockaddr has unsupported family " +
                                    std::to_string(storage.si_family));
    }
}

Result<Endpoint> endpointFromSockAddr(const SOCKADDR_INET& storage)
{
    NOVA_ASSIGN_OR_RETURN(auto address, fromSockAddr(storage));

    const u16 rawPort =
        storage.si_family == AF_INET ? storage.Ipv4.sin_port : storage.Ipv6.sin6_port;
    return Endpoint{address, ::ntohs(rawPort)};
}

Result<IpAddress> fromSockAddr(const SOCKADDR* address, int length)
{
    if (address == nullptr) {
        return err::invalidArgument("null sockaddr");
    }

    SOCKADDR_INET storage{};
    if (address->sa_family == AF_INET) {
        if (length < static_cast<int>(sizeof(sockaddr_in))) {
            return err::invalidArgument("sockaddr_in is truncated");
        }
        std::memcpy(&storage.Ipv4, address, sizeof(sockaddr_in));
    } else if (address->sa_family == AF_INET6) {
        if (length < static_cast<int>(sizeof(sockaddr_in6))) {
            return err::invalidArgument("sockaddr_in6 is truncated");
        }
        std::memcpy(&storage.Ipv6, address, sizeof(sockaddr_in6));
    } else {
        return err::invalidArgument("sockaddr has unsupported family " +
                                    std::to_string(address->sa_family));
    }
    return fromSockAddr(storage);
}

} // namespace nova::net
