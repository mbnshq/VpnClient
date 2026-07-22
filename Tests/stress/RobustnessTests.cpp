// Fuzz-lite robustness: feed adversarial and random input to every surface that
// parses untrusted data - .ovpn configs, IP/CIDR/endpoint literals, JSON and
// IPC frames - and assert graceful handling: a definite ok/error verdict, never
// a crash, hang, or out-of-bounds read. Input is generated with a fixed seed so
// a failure is reproducible.
#include <NovaVPN/Core/Json.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Networking/IpAddress.h>
#include <NovaVPN/Profiles/OvpnParser.h>
#include <NovaVPN/Services/IpcProtocol.h>

#include <catch2/catch_test_macros.hpp>

#include <random>
#include <string>
#include <vector>

using namespace nova;

namespace {

/// Deterministic PRNG so any failure reproduces.
std::mt19937& rng()
{
    static std::mt19937 engine{0xC0FFEE};
    return engine;
}

std::string randomBytes(std::size_t maxLen)
{
    std::uniform_int_distribution<int> lenDist(0, static_cast<int>(maxLen));
    std::uniform_int_distribution<int> byteDist(0, 255);
    const int len = lenDist(rng());
    std::string out;
    out.reserve(static_cast<std::size_t>(len));
    for (int i = 0; i < len; ++i) {
        out.push_back(static_cast<char>(byteDist(rng())));
    }
    return out;
}

/// Random text from a "dangerous" alphabet biased toward parser metacharacters.
std::string randomText(std::size_t maxLen)
{
    static const std::string alphabet =
        "0123456789.:/[]<>\"'\\ \t\n\r-*abcdefABCDEF{}remote proto udp tcp cipher";
    std::uniform_int_distribution<int> lenDist(0, static_cast<int>(maxLen));
    std::uniform_int_distribution<std::size_t> pick(0, alphabet.size() - 1);
    const int len = lenDist(rng());
    std::string out;
    for (int i = 0; i < len; ++i) {
        out.push_back(alphabet[pick(rng())]);
    }
    return out;
}

} // namespace

TEST_CASE("the .ovpn parser never crashes on adversarial input",
          "[robustness][security]")
{
    for (int i = 0; i < 20000; ++i) {
        const std::string config = randomText(400);
        // No crash, no hang, and a definite verdict either way.
        auto result = profiles::parseOvpn(config, {});
        (void)result.isOk();
    }

    // Some hand-crafted nasties that have broken parsers before.
    const std::vector<std::string> nasties = {
        "<ca>",                          // unterminated block
        "<ca></ca>",                     // empty block
        "remote",                        // directive with no args
        std::string(100000, 'a'),        // one enormous token
        "<<<<>>>>",                       // bracket soup
        "remote \"unterminated quote",   // dangling quote
        "\xEF\xBB\xBF" "client\nremote a 1", // BOM prefix
    };
    for (const auto& nasty : nasties) {
        auto result = profiles::parseOvpn(nasty, {});
        (void)result.isOk(); // must not throw or crash
    }
    SUCCEED("parser survived adversarial input");
}

TEST_CASE("tokeniser never crashes on random lines", "[robustness]")
{
    for (int i = 0; i < 20000; ++i) {
        profiles::OvpnDirective directive;
        (void)profiles::tokenizeOvpnLine(randomText(200), i, directive);
    }
    SUCCEED();
}

TEST_CASE("IP / CIDR / endpoint parsers never crash on random input",
          "[robustness][security]")
{
    for (int i = 0; i < 50000; ++i) {
        const std::string text = i % 2 == 0 ? randomText(60) : randomBytes(20);
        net::IpAddress address;
        (void)net::IpAddress::tryParse(text, address);
        (void)net::IpAddress::parse(text).isOk();
        (void)net::IpRange::parse(text).isOk();
        (void)net::Endpoint::parse(text).isOk();
        (void)net::isValidHostName(text);
    }
    SUCCEED();
}

TEST_CASE("a parsed CIDR always contains its own network address",
          "[robustness][property]")
{
    // Property: for any valid CIDR, the masked network is contained in itself
    // and the last address is >= the network. Fuzz valid ranges to check.
    std::uniform_int_distribution<int> octet(0, 255);
    std::uniform_int_distribution<int> prefix(0, 32);
    for (int i = 0; i < 20000; ++i) {
        const std::string cidr = std::to_string(octet(rng())) + "." +
                                 std::to_string(octet(rng())) + "." +
                                 std::to_string(octet(rng())) + "." +
                                 std::to_string(octet(rng())) + "/" +
                                 std::to_string(prefix(rng()));
        auto range = net::IpRange::parse(cidr);
        if (range.isError()) {
            continue;
        }
        REQUIRE(range.value().contains(range.value().network()));
        REQUIRE(range.value().contains(range.value().lastAddress()));
        REQUIRE(range.value().lastAddress() >= range.value().network());
    }
}

TEST_CASE("JSON parsing never crashes and never throws out", "[robustness]")
{
    for (int i = 0; i < 20000; ++i) {
        const std::string text = i % 2 == 0 ? randomText(300) : randomBytes(100);
        // json::parse is the single boundary that must convert every parse
        // failure to a Status rather than letting an exception escape.
        auto result = json::parse(text);
        (void)result.isOk();
    }
    SUCCEED();
}

TEST_CASE("IPC frame decoding never crashes on garbage frames",
          "[robustness][security]")
{
    for (int i = 0; i < 20000; ++i) {
        const std::string body = randomBytes(200);
        // Length-prefix parsing on random 4 bytes.
        if (body.size() >= 4) {
            (void)ipc::readFrameLength(
                std::span{reinterpret_cast<const u8*>(body.data()), 4});
        }
        // Frame-body parsing + request/response/event decode on garbage.
        auto json = ipc::parseFrame(
            std::span{reinterpret_cast<const u8*>(body.data()), body.size()});
        if (json.isOk()) {
            (void)ipc::decodeRequest(json.value()).isOk();
            (void)ipc::decodeResponse(json.value()).isOk();
            (void)ipc::decodeEvent(json.value()).isOk();
        }
    }
    SUCCEED();
}

TEST_CASE("UUID parsing never crashes on random strings", "[robustness]")
{
    for (int i = 0; i < 20000; ++i) {
        Uuid out;
        (void)Uuid::tryParse(randomText(50), out);
    }
    SUCCEED();
}
