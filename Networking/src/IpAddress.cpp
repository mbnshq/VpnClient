#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Networking/IpAddress.h>

#include <algorithm>
#include <charconv>
#include <cstdio>

namespace nova::net {
namespace {

constexpr u8 kV4Width  = 32;
constexpr u8 kV6Width  = 128;

/// Parses a decimal octet with the strictness the security model requires:
/// no leading zeros ("010" is octal in some resolvers), no signs, no spaces.
bool parseOctet(std::string_view text, u8& out) noexcept
{
    if (text.empty() || text.size() > 3) {
        return false;
    }
    if (text.size() > 1 && text[0] == '0') {
        return false;
    }
    unsigned value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        value = value * 10 + static_cast<unsigned>(c - '0');
    }
    if (value > 255) {
        return false;
    }
    out = static_cast<u8>(value);
    return true;
}

bool parseV4(std::string_view text, std::array<u8, 4>& out) noexcept
{
    std::size_t start = 0;
    for (int i = 0; i < 4; ++i) {
        const std::size_t dot = text.find('.', start);
        const bool last = (i == 3);
        if (last != (dot == std::string_view::npos)) {
            return false;
        }
        const std::string_view piece =
            last ? text.substr(start) : text.substr(start, dot - start);
        if (!parseOctet(piece, out[static_cast<std::size_t>(i)])) {
            return false;
        }
        start = last ? text.size() : dot + 1;
    }
    return true;
}

bool parseHextet(std::string_view text, u16& out) noexcept
{
    if (text.empty() || text.size() > 4) {
        return false;
    }
    unsigned value = 0;
    for (const char c : text) {
        unsigned digit = 0;
        if (c >= '0' && c <= '9') {
            digit = static_cast<unsigned>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = static_cast<unsigned>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            digit = static_cast<unsigned>(c - 'A' + 10);
        } else {
            return false;
        }
        value = (value << 4) | digit;
    }
    out = static_cast<u16>(value);
    return true;
}

/// RFC 4291 textual IPv6, including "::" compression and a trailing IPv4 part.
bool parseV6(std::string_view text, std::array<u8, 16>& out) noexcept
{
    if (text.size() < 2) {
        return false;
    }

    std::array<u16, 8> head{};
    std::array<u16, 8> tail{};
    std::size_t headCount = 0;
    std::size_t tailCount = 0;
    bool seenCompression = false;
    bool inTail = false;

    std::size_t i = 0;
    if (text[0] == ':') {
        if (text[1] != ':') {
            return false;
        }
        seenCompression = true;
        inTail = true;
        i = 2;
        if (i == text.size()) {
            out = {};
            return true; // "::"
        }
    }

    while (i < text.size()) {
        // A trailing IPv4 literal occupies the last two hextets.
        const std::size_t nextColon = text.find(':', i);
        const std::string_view piece =
            nextColon == std::string_view::npos ? text.substr(i) : text.substr(i, nextColon - i);

        if (piece.find('.') != std::string_view::npos) {
            std::array<u8, 4> v4{};
            if (!parseV4(piece, v4)) {
                return false;
            }
            const u16 hi = static_cast<u16>((v4[0] << 8) | v4[1]);
            const u16 lo = static_cast<u16>((v4[2] << 8) | v4[3]);
            auto& target = inTail ? tail : head;
            auto& count  = inTail ? tailCount : headCount;
            if (count + 2 > target.size()) {
                return false;
            }
            target[count++] = hi;
            target[count++] = lo;
            i = (nextColon == std::string_view::npos) ? text.size() : nextColon + 1;
            if (nextColon != std::string_view::npos) {
                return false; // an IPv4 tail must terminate the address
            }
            break;
        }

        if (piece.empty()) {
            // Empty piece means we just crossed "::".
            if (seenCompression) {
                return false;
            }
            seenCompression = true;
            inTail = true;
            ++i; // skip the second colon
            if (i >= text.size()) {
                break;
            }
            continue;
        }

        u16 value = 0;
        if (!parseHextet(piece, value)) {
            return false;
        }
        auto& target = inTail ? tail : head;
        auto& count  = inTail ? tailCount : headCount;
        if (count >= target.size()) {
            return false;
        }
        target[count++] = value;

        if (nextColon == std::string_view::npos) {
            break;
        }
        i = nextColon + 1;
        if (i == text.size()) {
            return false; // trailing single colon
        }
    }

    if (seenCompression) {
        if (headCount + tailCount >= 8) {
            return false; // "::" must stand for at least one zero group
        }
    } else if (headCount != 8 || tailCount != 0) {
        return false;
    }

    std::array<u16, 8> words{};
    for (std::size_t h = 0; h < headCount; ++h) {
        words[h] = head[h];
    }
    for (std::size_t t = 0; t < tailCount; ++t) {
        words[8 - tailCount + t] = tail[t];
    }

    for (std::size_t w = 0; w < words.size(); ++w) {
        out[w * 2]     = static_cast<u8>(words[w] >> 8);
        out[w * 2 + 1] = static_cast<u8>(words[w] & 0xFF);
    }
    return true;
}

std::string formatV4(std::span<const u8> bytes)
{
    char buffer[16]{};
    std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
    return std::string{buffer};
}

/// RFC 5952: lowercase, no leading zeros, longest run of zero groups (length
/// >= 2) compressed to "::".
std::string formatV6(std::span<const u8> bytes)
{
    std::array<u16, 8> words{};
    for (std::size_t i = 0; i < words.size(); ++i) {
        words[i] = static_cast<u16>((bytes[i * 2] << 8) | bytes[i * 2 + 1]);
    }

    std::size_t bestStart = words.size();
    std::size_t bestLength = 0;
    std::size_t runStart = 0;
    std::size_t runLength = 0;
    for (std::size_t i = 0; i < words.size(); ++i) {
        if (words[i] == 0) {
            if (runLength == 0) {
                runStart = i;
            }
            ++runLength;
            if (runLength > bestLength) {
                bestLength = runLength;
                bestStart  = runStart;
            }
        } else {
            runLength = 0;
        }
    }
    if (bestLength < 2) {
        bestStart = words.size();
        bestLength = 0;
    }

    std::string out;
    out.reserve(46);
    for (std::size_t i = 0; i < words.size();) {
        if (i == bestStart) {
            out.append("::");
            i += bestLength;
            continue;
        }
        if (!out.empty() && out.back() != ':') {
            out.push_back(':');
        }
        char buffer[8]{};
        std::snprintf(buffer, sizeof(buffer), "%x", words[i]);
        out.append(buffer);
        ++i;
    }
    if (out.empty()) {
        out = "::";
    }
    return out;
}

} // namespace

// --- IpAddress ------------------------------------------------------------

IpAddress IpAddress::fromV4(std::array<u8, 4> octets) noexcept
{
    IpAddress address;
    address.m_family = AddressFamily::IPv4;
    std::copy(octets.begin(), octets.end(), address.m_bytes.begin());
    return address;
}

IpAddress IpAddress::fromV6(std::array<u8, 16> octets) noexcept
{
    IpAddress address;
    address.m_family = AddressFamily::IPv6;
    address.m_bytes  = octets;
    return address;
}

IpAddress IpAddress::loopbackV6() noexcept
{
    std::array<u8, 16> bytes{};
    bytes[15] = 1;
    return fromV6(bytes);
}

bool IpAddress::tryParse(std::string_view text, IpAddress& out) noexcept
{
    const std::string_view trimmed = str::trim(text);
    if (trimmed.empty()) {
        return false;
    }

    if (trimmed.find(':') != std::string_view::npos) {
        std::array<u8, 16> bytes{};
        if (!parseV6(trimmed, bytes)) {
            return false;
        }
        out = fromV6(bytes);
        return true;
    }

    std::array<u8, 4> octets{};
    if (!parseV4(trimmed, octets)) {
        return false;
    }
    out = fromV4(octets);
    return true;
}

Result<IpAddress> IpAddress::parse(std::string_view text)
{
    IpAddress address;
    if (!tryParse(text, address)) {
        return err::invalidArgument("not a valid IP address: " + std::string{text});
    }
    return address;
}

std::span<const u8> IpAddress::bytes() const noexcept
{
    return isV4() ? std::span<const u8>{m_bytes.data(), 4} : std::span<const u8>{m_bytes};
}

bool IpAddress::isUnspecified() const noexcept
{
    const auto view = bytes();
    return std::all_of(view.begin(), view.end(), [](u8 b) { return b == 0; });
}

bool IpAddress::isLoopback() const noexcept
{
    if (isV4()) {
        return m_bytes[0] == 127; // 127.0.0.0/8
    }
    return *this == loopbackV6();
}

bool IpAddress::isMulticast() const noexcept
{
    if (isV4()) {
        return m_bytes[0] >= 224 && m_bytes[0] <= 239; // 224.0.0.0/4
    }
    return m_bytes[0] == 0xFF; // ff00::/8
}

bool IpAddress::isLinkLocal() const noexcept
{
    if (isV4()) {
        return m_bytes[0] == 169 && m_bytes[1] == 254; // 169.254.0.0/16
    }
    return m_bytes[0] == 0xFE && (m_bytes[1] & 0xC0) == 0x80; // fe80::/10
}

bool IpAddress::isPrivate() const noexcept
{
    if (isV4()) {
        if (m_bytes[0] == 10) {
            return true; // 10/8
        }
        if (m_bytes[0] == 172 && m_bytes[1] >= 16 && m_bytes[1] <= 31) {
            return true; // 172.16/12
        }
        if (m_bytes[0] == 192 && m_bytes[1] == 168) {
            return true; // 192.168/16
        }
        if (m_bytes[0] == 100 && m_bytes[1] >= 64 && m_bytes[1] <= 127) {
            return true; // 100.64/10 carrier-grade NAT
        }
        return false;
    }
    return (m_bytes[0] & 0xFE) == 0xFC; // fc00::/7 unique local
}

bool IpAddress::isGlobalUnicast() const noexcept
{
    return !isUnspecified() && !isLoopback() && !isLinkLocal() && !isMulticast() && !isPrivate();
}

std::string IpAddress::toString() const
{
    return isV4() ? formatV4(bytes()) : formatV6(bytes());
}

IpAddress IpAddress::normalized() const
{
    if (isV4()) {
        return *this;
    }
    // ::ffff:0:0/96 - an IPv4 address wearing an IPv6 costume.
    static constexpr std::array<u8, 12> kMappedPrefix{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    if (std::equal(kMappedPrefix.begin(), kMappedPrefix.end(), m_bytes.begin())) {
        return fromV4({m_bytes[12], m_bytes[13], m_bytes[14], m_bytes[15]});
    }
    return *this;
}

bool operator==(const IpAddress& a, const IpAddress& b) noexcept
{
    return a.m_family == b.m_family && a.m_bytes == b.m_bytes;
}

std::strong_ordering operator<=>(const IpAddress& a, const IpAddress& b) noexcept
{
    if (a.m_family != b.m_family) {
        return a.m_family <=> b.m_family;
    }
    return a.m_bytes <=> b.m_bytes;
}

// --- IpRange --------------------------------------------------------------

Result<IpRange> IpRange::make(IpAddress address, u8 prefixLength)
{
    const u8 width = address.isV4() ? kV4Width : kV6Width;
    if (prefixLength > width) {
        return err::invalidArgument("prefix length " + std::to_string(prefixLength) +
                                    " exceeds the address width");
    }

    // Mask off host bits so equality and containment behave predictably.
    std::array<u8, 16> bytes{};
    const auto source = address.bytes();
    std::copy(source.begin(), source.end(), bytes.begin());

    for (std::size_t i = 0; i < source.size(); ++i) {
        const int bitOffset = static_cast<int>(i) * 8;
        if (bitOffset >= prefixLength) {
            bytes[i] = 0;
        } else if (bitOffset + 8 > prefixLength) {
            const int keep = prefixLength - bitOffset;
            const u8 mask = static_cast<u8>(0xFFu << (8 - keep));
            bytes[i] = static_cast<u8>(bytes[i] & mask);
        }
    }

    IpRange range;
    if (address.isV4()) {
        range.m_network = IpAddress::fromV4({bytes[0], bytes[1], bytes[2], bytes[3]});
    } else {
        range.m_network = IpAddress::fromV6(bytes);
    }
    range.m_prefixLength = prefixLength;
    return range;
}

Result<IpRange> IpRange::parse(std::string_view text)
{
    const std::string_view trimmed = str::trim(text);
    const std::size_t slash = trimmed.find('/');

    if (slash == std::string_view::npos) {
        NOVA_ASSIGN_OR_RETURN(auto address, IpAddress::parse(trimmed));
        return make(address, address.isV4() ? kV4Width : kV6Width);
    }

    NOVA_ASSIGN_OR_RETURN(auto address, IpAddress::parse(trimmed.substr(0, slash)));

    const std::string_view prefixText = trimmed.substr(slash + 1);
    if (prefixText.empty() || prefixText.size() > 3) {
        return err::invalidArgument("invalid prefix length in " + std::string{text});
    }
    unsigned prefix = 0;
    const auto* first = prefixText.data();
    const auto* last  = first + prefixText.size();
    const auto [ptr, ec] = std::from_chars(first, last, prefix);
    if (ec != std::errc{} || ptr != last) {
        return err::invalidArgument("invalid prefix length in " + std::string{text});
    }

    return make(address, static_cast<u8>(prefix));
}

bool IpRange::contains(const IpAddress& address) const noexcept
{
    if (address.family() != m_network.family()) {
        return false;
    }

    const auto candidate = address.bytes();
    const auto network   = m_network.bytes();

    int remaining = m_prefixLength;
    for (std::size_t i = 0; i < network.size() && remaining > 0; ++i) {
        if (remaining >= 8) {
            if (candidate[i] != network[i]) {
                return false;
            }
            remaining -= 8;
        } else {
            const u8 mask = static_cast<u8>(0xFFu << (8 - remaining));
            if ((candidate[i] & mask) != (network[i] & mask)) {
                return false;
            }
            remaining = 0;
        }
    }
    return true;
}

bool IpRange::contains(const IpRange& other) const noexcept
{
    return other.family() == family() && other.m_prefixLength >= m_prefixLength &&
           contains(other.m_network);
}

IpAddress IpRange::lastAddress() const
{
    std::array<u8, 16> bytes{};
    const auto network = m_network.bytes();
    std::copy(network.begin(), network.end(), bytes.begin());

    for (std::size_t i = 0; i < network.size(); ++i) {
        const int bitOffset = static_cast<int>(i) * 8;
        if (bitOffset >= m_prefixLength) {
            bytes[i] = 0xFF;
        } else if (bitOffset + 8 > m_prefixLength) {
            const int keep = m_prefixLength - bitOffset;
            const u8 hostMask = static_cast<u8>(0xFFu >> keep);
            bytes[i] = static_cast<u8>(bytes[i] | hostMask);
        }
    }

    return m_network.isV4() ? IpAddress::fromV4({bytes[0], bytes[1], bytes[2], bytes[3]})
                            : IpAddress::fromV6(bytes);
}

std::optional<IpAddress> IpRange::netmaskV4() const
{
    if (!m_network.isV4()) {
        return std::nullopt;
    }
    std::array<u8, 4> mask{};
    int remaining = m_prefixLength;
    for (auto& byte : mask) {
        if (remaining >= 8) {
            byte = 0xFF;
            remaining -= 8;
        } else if (remaining > 0) {
            byte = static_cast<u8>(0xFFu << (8 - remaining));
            remaining = 0;
        }
    }
    return IpAddress::fromV4(mask);
}

std::string IpRange::toString() const
{
    return m_network.toString() + "/" + std::to_string(m_prefixLength);
}

bool operator==(const IpRange& a, const IpRange& b) noexcept
{
    return a.m_prefixLength == b.m_prefixLength && a.m_network == b.m_network;
}

// --- Endpoint -------------------------------------------------------------

Result<Endpoint> Endpoint::parse(std::string_view text)
{
    const std::string_view trimmed = str::trim(text);
    if (trimmed.empty()) {
        return err::invalidArgument("empty endpoint");
    }

    std::string_view addressText;
    std::string_view portText;

    if (trimmed.front() == '[') {
        const std::size_t close = trimmed.find(']');
        if (close == std::string_view::npos || close + 2 > trimmed.size() ||
            trimmed[close + 1] != ':') {
            return err::invalidArgument("malformed bracketed endpoint: " + std::string{text});
        }
        addressText = trimmed.substr(1, close - 1);
        portText    = trimmed.substr(close + 2);
    } else {
        const std::size_t colon = trimmed.rfind(':');
        if (colon == std::string_view::npos) {
            return err::invalidArgument("endpoint is missing a port: " + std::string{text});
        }
        addressText = trimmed.substr(0, colon);
        portText    = trimmed.substr(colon + 1);
    }

    NOVA_ASSIGN_OR_RETURN(auto address, IpAddress::parse(addressText));

    unsigned port = 0;
    const auto* first = portText.data();
    const auto* last  = first + portText.size();
    const auto [ptr, ec] = std::from_chars(first, last, port);
    if (ec != std::errc{} || ptr != last || port == 0 || port > 65535) {
        return err::invalidArgument("invalid port in " + std::string{text});
    }

    return Endpoint{address, static_cast<u16>(port)};
}

std::string Endpoint::toString() const
{
    if (m_address.isV6()) {
        return "[" + m_address.toString() + "]:" + std::to_string(m_port);
    }
    return m_address.toString() + ":" + std::to_string(m_port);
}

bool operator==(const Endpoint& a, const Endpoint& b) noexcept
{
    return a.m_port == b.m_port && a.m_address == b.m_address;
}

// --- HostEndpoint ---------------------------------------------------------

bool HostEndpoint::isLiteralAddress() const noexcept
{
    IpAddress parsed;
    return IpAddress::tryParse(host, parsed);
}

std::string HostEndpoint::toString() const
{
    std::string out;
    IpAddress parsed;
    if (IpAddress::tryParse(host, parsed) && parsed.isV6()) {
        out = "[" + host + "]";
    } else {
        out = host;
    }
    out.push_back(':');
    out.append(std::to_string(port));
    out.push_back('/');
    out.append(nova::toString(transport));
    return out;
}

bool isValidHostName(std::string_view host) noexcept
{
    if (host.empty() || host.size() > 253) {
        return false;
    }
    if (host.front() == '.' || host.back() == '.') {
        return false;
    }

    std::size_t labelLength = 0;
    for (std::size_t i = 0; i < host.size(); ++i) {
        const char c = host[i];
        if (c == '.') {
            if (labelLength == 0) {
                return false; // empty label
            }
            if (host[i - 1] == '-') {
                return false; // label must not end with a hyphen
            }
            labelLength = 0;
            continue;
        }

        const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                           (c >= '0' && c <= '9');
        // '_' is invalid per RFC 1123 but appears in real SRV-style VPN
        // endpoints, so it is accepted deliberately.
        if (!alnum && c != '-' && c != '_') {
            return false;
        }
        if (labelLength == 0 && c == '-') {
            return false; // label must not start with a hyphen
        }
        if (++labelLength > 63) {
            return false;
        }
    }
    return labelLength > 0 && host.back() != '-';
}

} // namespace nova::net
