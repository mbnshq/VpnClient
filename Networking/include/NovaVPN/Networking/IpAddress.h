// NovaVPN - Networking/IpAddress.h
// Address value types. Deliberately independent of Winsock so that routing,
// split-tunnel and firewall rules can be parsed, stored and unit-tested without
// touching the network stack.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/Types.h>

#include <array>
#include <compare>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nova::net {

/// An IPv4 or IPv6 address.
class IpAddress final {
public:
    IpAddress() noexcept = default; ///< Unspecified IPv4 address (0.0.0.0).

    [[nodiscard]] static IpAddress fromV4(std::array<u8, 4> octets) noexcept;
    [[nodiscard]] static IpAddress fromV6(std::array<u8, 16> octets) noexcept;

    /// Accepts dotted-quad and every RFC 4291 IPv6 form including "::",
    /// compressed runs and IPv4-mapped ("::ffff:1.2.3.4"). Rejects zone ids,
    /// leading zeros in IPv4 octets (an ambiguity that has caused SSRF bugs in
    /// other products) and any trailing garbage.
    [[nodiscard]] static Result<IpAddress> parse(std::string_view text);
    [[nodiscard]] static bool tryParse(std::string_view text, IpAddress& out) noexcept;

    [[nodiscard]] static IpAddress anyV4() noexcept { return fromV4({0, 0, 0, 0}); }
    [[nodiscard]] static IpAddress anyV6() noexcept { return fromV6({}); }
    [[nodiscard]] static IpAddress loopbackV4() noexcept { return fromV4({127, 0, 0, 1}); }
    [[nodiscard]] static IpAddress loopbackV6() noexcept;

    [[nodiscard]] AddressFamily family() const noexcept { return m_family; }
    [[nodiscard]] bool isV4() const noexcept { return m_family == AddressFamily::IPv4; }
    [[nodiscard]] bool isV6() const noexcept { return m_family == AddressFamily::IPv6; }

    /// 4 bytes for IPv4, 16 for IPv6.
    [[nodiscard]] std::span<const u8> bytes() const noexcept;

    [[nodiscard]] bool isUnspecified() const noexcept;
    [[nodiscard]] bool isLoopback() const noexcept;
    [[nodiscard]] bool isMulticast() const noexcept;
    [[nodiscard]] bool isLinkLocal() const noexcept;
    /// RFC 1918 / RFC 4193 - what "block LAN traffic" acts on.
    [[nodiscard]] bool isPrivate() const noexcept;
    /// Routable on the public internet: not unspecified, loopback, link-local,
    /// multicast or private.
    [[nodiscard]] bool isGlobalUnicast() const noexcept;

    /// "192.168.1.1" / "2001:db8::1" (RFC 5952 canonical form).
    [[nodiscard]] std::string toString() const;

    /// IPv4-mapped IPv6 ("::ffff:a.b.c.d") collapsed to its IPv4 form; other
    /// addresses are returned unchanged. Rules are normalised through this so
    /// that a mapped address cannot bypass an IPv4 rule.
    [[nodiscard]] IpAddress normalized() const;

    friend bool operator==(const IpAddress& a, const IpAddress& b) noexcept;
    friend std::strong_ordering operator<=>(const IpAddress& a, const IpAddress& b) noexcept;

private:
    AddressFamily      m_family = AddressFamily::IPv4;
    std::array<u8, 16> m_bytes{};
};

/// address + prefix length, e.g. 10.0.0.0/8 or 2001:db8::/32.
class IpRange final {
public:
    IpRange() noexcept = default;

    /// Host bits below the prefix are masked off, so 10.1.2.3/8 becomes
    /// 10.0.0.0/8. Returns InvalidArgument when the prefix exceeds the family's
    /// width.
    [[nodiscard]] static Result<IpRange> make(IpAddress address, u8 prefixLength);

    /// Parses "10.0.0.0/8", "2001:db8::/32", or a bare address (implying a /32
    /// or /128 host route).
    [[nodiscard]] static Result<IpRange> parse(std::string_view text);

    [[nodiscard]] const IpAddress& network() const noexcept { return m_network; }
    [[nodiscard]] u8 prefixLength() const noexcept { return m_prefixLength; }
    [[nodiscard]] AddressFamily family() const noexcept { return m_network.family(); }

    [[nodiscard]] bool contains(const IpAddress& address) const noexcept;
    [[nodiscard]] bool contains(const IpRange& other) const noexcept;

    /// Last address in the range (broadcast address for IPv4).
    [[nodiscard]] IpAddress lastAddress() const;

    /// Dotted subnet mask; IPv4 only. Needed by the Windows route APIs.
    [[nodiscard]] std::optional<IpAddress> netmaskV4() const;

    [[nodiscard]] std::string toString() const;

    friend bool operator==(const IpRange& a, const IpRange& b) noexcept;

private:
    IpAddress m_network;
    u8        m_prefixLength = 0;
};

/// address + port.
class Endpoint final {
public:
    Endpoint() noexcept = default;
    Endpoint(IpAddress address, u16 port) noexcept : m_address(address), m_port(port) {}

    /// Parses "1.2.3.4:1194" and "[2001:db8::1]:1194".
    [[nodiscard]] static Result<Endpoint> parse(std::string_view text);

    [[nodiscard]] const IpAddress& address() const noexcept { return m_address; }
    [[nodiscard]] u16 port() const noexcept { return m_port; }

    [[nodiscard]] std::string toString() const;

    friend bool operator==(const Endpoint& a, const Endpoint& b) noexcept;

private:
    IpAddress m_address;
    u16       m_port = 0;
};

/// Host name or literal address plus a port - what a profile's `remote` line
/// yields before resolution.
struct HostEndpoint {
    std::string host;
    u16         port = 0;
    Transport   transport = Transport::Udp;

    [[nodiscard]] bool isLiteralAddress() const noexcept;
    [[nodiscard]] std::string toString() const;
};

/// True when `host` is a syntactically valid DNS name (RFC 1123 with the
/// underscore allowance that real-world VPN endpoints use).
[[nodiscard]] bool isValidHostName(std::string_view host) noexcept;

} // namespace nova::net
