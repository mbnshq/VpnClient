#include <NovaVPN/Core/StringUtil.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdio>

namespace nova::str {
namespace {

constexpr char asciiLower(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

constexpr char asciiUpper(char c) noexcept
{
    return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
}

constexpr bool isSpace(char c) noexcept
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

/// Iterative glob matcher with backtracking. O(n*m) worst case but without
/// recursion, so a hostile pattern in a routing rule cannot blow the stack.
bool globMatchImpl(std::string_view pattern, std::string_view text) noexcept
{
    std::size_t p = 0;
    std::size_t t = 0;
    std::size_t starP = std::string_view::npos;
    std::size_t starT = 0;

    while (t < text.size()) {
        if (p < pattern.size() &&
            (pattern[p] == '?' || asciiLower(pattern[p]) == asciiLower(text[t]))) {
            ++p;
            ++t;
        } else if (p < pattern.size() && pattern[p] == '*') {
            starP = p++;
            starT = t;
        } else if (starP != std::string_view::npos) {
            p = starP + 1;
            t = ++starT;
        } else {
            return false;
        }
    }

    while (p < pattern.size() && pattern[p] == '*') {
        ++p;
    }
    return p == pattern.size();
}

} // namespace

std::string toLower(std::string_view text)
{
    std::string out{text};
    std::transform(out.begin(), out.end(), out.begin(), asciiLower);
    return out;
}

std::string toUpper(std::string_view text)
{
    std::string out{text};
    std::transform(out.begin(), out.end(), out.begin(), asciiUpper);
    return out;
}

bool equalsIgnoreCase(std::string_view a, std::string_view b) noexcept
{
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (asciiLower(a[i]) != asciiLower(b[i])) {
            return false;
        }
    }
    return true;
}

bool startsWith(std::string_view text, std::string_view prefix) noexcept
{
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

bool endsWith(std::string_view text, std::string_view suffix) noexcept
{
    return text.size() >= suffix.size() &&
           text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool contains(std::string_view text, std::string_view needle) noexcept
{
    return text.find(needle) != std::string_view::npos;
}

std::string_view trimLeft(std::string_view text) noexcept
{
    std::size_t i = 0;
    while (i < text.size() && isSpace(text[i])) {
        ++i;
    }
    return text.substr(i);
}

std::string_view trimRight(std::string_view text) noexcept
{
    std::size_t end = text.size();
    while (end > 0 && isSpace(text[end - 1])) {
        --end;
    }
    return text.substr(0, end);
}

std::string_view trim(std::string_view text) noexcept
{
    return trimRight(trimLeft(text));
}

std::vector<std::string_view> split(std::string_view text, char delimiter, bool skipEmpty)
{
    std::vector<std::string_view> parts;
    std::size_t start = 0;
    while (true) {
        const std::size_t pos = text.find(delimiter, start);
        std::string_view piece = (pos == std::string_view::npos)
                                     ? text.substr(start)
                                     : text.substr(start, pos - start);
        if (!skipEmpty || !piece.empty()) {
            parts.push_back(piece);
        }
        if (pos == std::string_view::npos) {
            break;
        }
        start = pos + 1;
    }
    return parts;
}

std::vector<std::string_view> splitWhitespace(std::string_view text)
{
    std::vector<std::string_view> parts;
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && isSpace(text[i])) {
            ++i;
        }
        const std::size_t start = i;
        while (i < text.size() && !isSpace(text[i])) {
            ++i;
        }
        if (i > start) {
            parts.push_back(text.substr(start, i - start));
        }
    }
    return parts;
}

std::string join(const std::vector<std::string>& parts, std::string_view separator)
{
    std::string out;
    std::size_t total = 0;
    for (const auto& part : parts) {
        total += part.size() + separator.size();
    }
    out.reserve(total);
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) {
            out.append(separator);
        }
        out.append(parts[i]);
    }
    return out;
}

std::string replaceAll(std::string_view text, std::string_view from, std::string_view to)
{
    if (from.empty()) {
        return std::string{text};
    }
    std::string out;
    out.reserve(text.size());
    std::size_t start = 0;
    while (true) {
        const std::size_t pos = text.find(from, start);
        if (pos == std::string_view::npos) {
            out.append(text.substr(start));
            break;
        }
        out.append(text.substr(start, pos - start));
        out.append(to);
        start = pos + from.size();
    }
    return out;
}

bool globMatch(std::string_view pattern, std::string_view text) noexcept
{
    return globMatchImpl(pattern, text);
}

std::string toHex(const void* data, std::size_t size, bool uppercase)
{
    static constexpr std::array<char, 16> kLower{'0', '1', '2', '3', '4', '5', '6', '7',
                                                 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    static constexpr std::array<char, 16> kUpper{'0', '1', '2', '3', '4', '5', '6', '7',
                                                 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    const auto& table = uppercase ? kUpper : kLower;

    const auto* bytes = static_cast<const unsigned char*>(data);
    std::string out;
    out.resize(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out[i * 2]     = table[bytes[i] >> 4];
        out[i * 2 + 1] = table[bytes[i] & 0x0F];
    }
    return out;
}

bool fromHex(std::string_view hex, std::vector<u8>& out)
{
    if (hex.size() % 2 != 0) {
        return false;
    }
    out.clear();
    out.reserve(hex.size() / 2);

    const auto nibble = [](char c, u8& value) noexcept -> bool {
        if (c >= '0' && c <= '9') {
            value = static_cast<u8>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            value = static_cast<u8>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            value = static_cast<u8>(c - 'A' + 10);
        } else {
            return false;
        }
        return true;
    };

    for (std::size_t i = 0; i < hex.size(); i += 2) {
        u8 hi = 0;
        u8 lo = 0;
        if (!nibble(hex[i], hi) || !nibble(hex[i + 1], lo)) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<u8>((hi << 4) | lo));
    }
    return true;
}

std::string formatBytes(ByteCount bytes)
{
    static constexpr std::array<const char*, 6> kUnits{"B", "KB", "MB", "GB", "TB", "PB"};

    if (bytes < 1024) {
        return std::to_string(bytes) + " B";
    }

    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < kUnits.size()) {
        value /= 1024.0;
        ++unit;
    }

    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), value < 10.0 ? "%.2f %s" : "%.1f %s", value,
                  kUnits[unit]);
    return std::string{buffer};
}

std::string formatBitrate(double bitsPerSecond)
{
    static constexpr std::array<const char*, 5> kUnits{"bps", "Kbps", "Mbps", "Gbps", "Tbps"};

    if (!std::isfinite(bitsPerSecond) || bitsPerSecond < 0.0) {
        bitsPerSecond = 0.0;
    }

    double value = bitsPerSecond;
    std::size_t unit = 0;
    while (value >= 1000.0 && unit + 1 < kUnits.size()) {
        value /= 1000.0;
        ++unit;
    }

    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), value < 10.0 ? "%.2f %s" : "%.1f %s", value,
                  kUnits[unit]);
    return std::string{buffer};
}

std::string formatDuration(Seconds duration)
{
    auto total = duration.count();
    if (total < 0) {
        total = 0;
    }
    const auto hours   = total / 3600;
    const auto minutes = (total % 3600) / 60;
    const auto seconds = total % 60;

    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), "%02lld:%02lld:%02lld", static_cast<long long>(hours),
                  static_cast<long long>(minutes), static_cast<long long>(seconds));
    return std::string{buffer};
}

std::string redact(std::string_view secret)
{
    if (secret.empty()) {
        return "<empty>";
    }
    if (secret.size() <= 4) {
        return std::string(secret.size(), '*');
    }
    std::string out;
    out.reserve(secret.size());
    out.append(secret.substr(0, 2));
    out.append(secret.size() - 4, '*');
    out.append(secret.substr(secret.size() - 2));
    return out;
}

} // namespace nova::str
