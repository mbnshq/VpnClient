// NovaVPN - Core/StringUtil.h
// Small, allocation-conscious text helpers. All NovaVPN strings are UTF-8.
#pragma once

#include <NovaVPN/Core/Types.h>

#include <string>
#include <string_view>
#include <vector>

namespace nova::str {

[[nodiscard]] std::string toLower(std::string_view text);
[[nodiscard]] std::string toUpper(std::string_view text);

[[nodiscard]] bool equalsIgnoreCase(std::string_view a, std::string_view b) noexcept;
[[nodiscard]] bool startsWith(std::string_view text, std::string_view prefix) noexcept;
[[nodiscard]] bool endsWith(std::string_view text, std::string_view suffix) noexcept;
[[nodiscard]] bool contains(std::string_view text, std::string_view needle) noexcept;

[[nodiscard]] std::string_view trim(std::string_view text) noexcept;
[[nodiscard]] std::string_view trimLeft(std::string_view text) noexcept;
[[nodiscard]] std::string_view trimRight(std::string_view text) noexcept;

/// Splits on a single-character delimiter. Empty fields are preserved unless
/// `skipEmpty` is set (which is what .ovpn option parsing wants).
[[nodiscard]] std::vector<std::string_view> split(std::string_view text, char delimiter,
                                                  bool skipEmpty = false);

/// Splits on runs of whitespace - the tokenisation rule used by OpenVPN
/// configuration directives.
[[nodiscard]] std::vector<std::string_view> splitWhitespace(std::string_view text);

[[nodiscard]] std::string join(const std::vector<std::string>& parts, std::string_view separator);

[[nodiscard]] std::string replaceAll(std::string_view text, std::string_view from,
                                      std::string_view to);

/// Glob matcher supporting '*' and '?', used by domain and application rules.
/// Matching is case-insensitive because both host names and Windows paths are.
[[nodiscard]] bool globMatch(std::string_view pattern, std::string_view text) noexcept;

/// Hex encoding for fingerprints and log dumps.
[[nodiscard]] std::string toHex(const void* data, std::size_t size, bool uppercase = false);
[[nodiscard]] bool fromHex(std::string_view hex, std::vector<u8>& out);

/// "1.4 GB", "812 MB" - traffic counters in the dashboard.
[[nodiscard]] std::string formatBytes(ByteCount bytes);
/// "1.4 Mbps" - live speed readouts.
[[nodiscard]] std::string formatBitrate(double bitsPerSecond);
/// "02:14:07" - connection timer.
[[nodiscard]] std::string formatDuration(Seconds duration);

/// Redacts everything but the first and last two characters, for logging
/// tokens and user names without leaking them: "ab****yz".
[[nodiscard]] std::string redact(std::string_view secret);

} // namespace nova::str
