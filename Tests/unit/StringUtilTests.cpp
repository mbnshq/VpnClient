#include <NovaVPN/Core/StringUtil.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::str;

TEST_CASE("case helpers are ASCII-only and total", "[string]")
{
    REQUIRE(toLower("MiXeD-123") == "mixed-123");
    REQUIRE(toUpper("MiXeD-123") == "MIXED-123");
    REQUIRE(equalsIgnoreCase("OpenVPN", "openvpn"));
    REQUIRE_FALSE(equalsIgnoreCase("OpenVPN", "openvpn2"));
    REQUIRE(equalsIgnoreCase("", ""));
}

TEST_CASE("prefix, suffix and substring checks", "[string]")
{
    REQUIRE(startsWith("remote hk1.example.net 1194", "remote"));
    REQUIRE_FALSE(startsWith("re", "remote"));
    REQUIRE(endsWith("profile.ovpn", ".ovpn"));
    REQUIRE(contains("verify-x509-name Server", "x509"));
    REQUIRE(startsWith("anything", ""));
}

TEST_CASE("trim removes every kind of ASCII whitespace", "[string]")
{
    REQUIRE(trim("  \t remote \r\n ") == "remote");
    REQUIRE(trim("") == "");
    REQUIRE(trim("   ") == "");
    REQUIRE(trimLeft("  x  ") == "x  ");
    REQUIRE(trimRight("  x  ") == "  x");
}

TEST_CASE("split preserves empty fields unless asked not to", "[string]")
{
    const auto kept = split("a,,b", ',');
    REQUIRE(kept.size() == 3);
    REQUIRE(kept[1].empty());

    const auto skipped = split("a,,b", ',', /*skipEmpty=*/true);
    REQUIRE(skipped.size() == 2);
    REQUIRE(skipped[1] == "b");

    const auto single = split("abc", ',');
    REQUIRE(single.size() == 1);
    REQUIRE(single[0] == "abc");
}

TEST_CASE("splitWhitespace tokenises an OpenVPN directive", "[string]")
{
    const auto tokens = splitWhitespace("  remote\t hk1.example.net   1194  udp ");
    REQUIRE(tokens.size() == 4);
    REQUIRE(tokens[0] == "remote");
    REQUIRE(tokens[1] == "hk1.example.net");
    REQUIRE(tokens[2] == "1194");
    REQUIRE(tokens[3] == "udp");

    REQUIRE(splitWhitespace("   ").empty());
}

TEST_CASE("join and replaceAll", "[string]")
{
    REQUIRE(join({"a", "b", "c"}, ", ") == "a, b, c");
    REQUIRE(join({}, ", ").empty());
    REQUIRE(replaceAll("a.b.c", ".", "-") == "a-b-c");
    REQUIRE(replaceAll("aaa", "aa", "b") == "ba");
    REQUIRE(replaceAll("abc", "", "-") == "abc");
}

TEST_CASE("globMatch drives domain and application rules", "[string][glob]")
{
    REQUIRE(globMatch("*.tiktok.com", "www.tiktok.com"));
    REQUIRE(globMatch("*.tiktok.com", "a.b.tiktok.com"));
    REQUIRE_FALSE(globMatch("*.tiktok.com", "tiktok.com"));

    REQUIRE(globMatch("C:\\Program Files\\*\\chrome.exe",
                      "C:\\Program Files\\Google\\chrome.exe"));
    REQUIRE(globMatch("c:\\windows\\notepad.exe", "C:\\Windows\\Notepad.exe"));
    REQUIRE(globMatch("?at", "cat"));
    REQUIRE_FALSE(globMatch("?at", "at"));

    REQUIRE(globMatch("*", "anything at all"));
    REQUIRE(globMatch("", ""));
    REQUIRE_FALSE(globMatch("", "x"));
}

TEST_CASE("globMatch does not blow up on adversarial patterns", "[string][glob]")
{
    // The classic catastrophic-backtracking shape. The iterative matcher must
    // return promptly rather than recursing.
    const std::string pattern(40, '*');
    const std::string text(200, 'a');
    REQUIRE(globMatch(pattern, text));
    REQUIRE_FALSE(globMatch(pattern + "b", text));
}

TEST_CASE("hex round-trips", "[string]")
{
    const std::vector<u8> bytes{0x00, 0x0F, 0xA5, 0xFF};
    const std::string hex = toHex(bytes.data(), bytes.size());
    REQUIRE(hex == "000fa5ff");
    REQUIRE(toHex(bytes.data(), bytes.size(), /*uppercase=*/true) == "000FA5FF");

    std::vector<u8> decoded;
    REQUIRE(fromHex(hex, decoded));
    REQUIRE(decoded == bytes);

    REQUIRE_FALSE(fromHex("abc", decoded));   // odd length
    REQUIRE_FALSE(fromHex("zz", decoded));    // not hex
}

TEST_CASE("human-readable formatters", "[string]")
{
    REQUIRE(formatBytes(0) == "0 B");
    REQUIRE(formatBytes(1023) == "1023 B");
    REQUIRE(formatBytes(1024) == "1.00 KB");
    REQUIRE(formatBytes(1536) == "1.50 KB");
    REQUIRE(formatBytes(15ull * 1024 * 1024) == "15.0 MB");

    REQUIRE(formatBitrate(0.0) == "0.00 bps");
    REQUIRE(formatBitrate(1500.0) == "1.50 Kbps");
    REQUIRE(formatBitrate(-1.0) == "0.00 bps");

    REQUIRE(formatDuration(Seconds{0}) == "00:00:00");
    REQUIRE(formatDuration(Seconds{8047}) == "02:14:07");
    REQUIRE(formatDuration(Seconds{-5}) == "00:00:00");
}

TEST_CASE("redact never reveals the middle of a secret", "[string][security]")
{
    REQUIRE(redact("") == "<empty>");
    REQUIRE(redact("ab") == "**");
    REQUIRE(redact("abcd") == "****");
    REQUIRE(redact("abcdef") == "ab**ef");
    REQUIRE(redact("hunter2-very-long-password").find("very") == std::string::npos);
}
