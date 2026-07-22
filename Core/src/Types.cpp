#include <NovaVPN/Core/Types.h>

namespace nova {

std::string_view toString(ConnectionState state) noexcept
{
    switch (state) {
    case ConnectionState::Disconnected:   return "Disconnected";
    case ConnectionState::Resolving:      return "Resolving";
    case ConnectionState::Connecting:     return "Connecting";
    case ConnectionState::Authenticating: return "Authenticating";
    case ConnectionState::Configuring:    return "Configuring";
    case ConnectionState::Connected:      return "Connected";
    case ConnectionState::Reconnecting:   return "Reconnecting";
    case ConnectionState::Disconnecting:  return "Disconnecting";
    case ConnectionState::Faulted:        return "Faulted";
    }
    return "Unknown";
}

std::string_view toString(Transport transport) noexcept
{
    switch (transport) {
    case Transport::Udp: return "udp";
    case Transport::Tcp: return "tcp";
    }
    return "unknown";
}

std::string_view toString(AddressFamily family) noexcept
{
    switch (family) {
    case AddressFamily::IPv4: return "ipv4";
    case AddressFamily::IPv6: return "ipv6";
    }
    return "unknown";
}

} // namespace nova
