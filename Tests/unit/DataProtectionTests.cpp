#include <NovaVPN/Core/DataProtection.h>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>

using namespace nova;
using namespace nova::crypto;

namespace {

std::span<const u8> bytesOf(std::string_view text)
{
    return std::span{reinterpret_cast<const u8*>(text.data()), text.size()};
}

} // namespace

TEST_CASE("machine-scope seal round-trips", "[crypto][dpapi]")
{
    const std::string secret = "client\nremote hk1.example.net 1194\n";

    auto sealed = seal(secret, ProtectionScope::Machine);
    REQUIRE(sealed.isOk());
    // Ciphertext must not contain the plaintext.
    REQUIRE(std::string(sealed.value().begin(), sealed.value().end()).find("hk1.example.net") ==
            std::string::npos);

    auto opened = unseal(sealed.value());
    REQUIRE(opened.isOk());
    REQUIRE(opened.value().view() == secret);
}

TEST_CASE("user-scope seal round-trips", "[crypto][dpapi]")
{
    const std::string secret = "user data";
    auto sealed = seal(secret, ProtectionScope::User);
    REQUIRE(sealed.isOk());

    auto opened = unseal(sealed.value());
    REQUIRE(opened.isOk());
    REQUIRE(opened.value().view() == secret);
}

TEST_CASE("entropy binds the ciphertext", "[crypto][dpapi][security]")
{
    const std::string secret = "bound secret";
    const std::array<u8, 8> entropy{1, 2, 3, 4, 5, 6, 7, 8};
    const std::array<u8, 8> wrongEntropy{8, 7, 6, 5, 4, 3, 2, 1};

    auto sealed = seal(secret, ProtectionScope::Machine, entropy);
    REQUIRE(sealed.isOk());

    // Correct entropy unseals.
    auto correct = unseal(sealed.value(), entropy);
    REQUIRE(correct.isOk());
    REQUIRE(correct.value().view() == secret);

    // Wrong entropy fails, and as an integrity violation rather than a vague IO
    // error, so a caller can tell tampering/foreign data from a disk problem.
    auto wrong = unseal(sealed.value(), wrongEntropy);
    REQUIRE(wrong.isError());
    REQUIRE(wrong.status().code() == ErrorCode::IntegrityViolation);

    // No entropy at all also fails against an entropy-bound blob.
    REQUIRE(unseal(sealed.value()).isError());
}

TEST_CASE("tampered ciphertext fails to unseal", "[crypto][dpapi][security]")
{
    auto sealed = seal("integrity matters", ProtectionScope::Machine);
    REQUIRE(sealed.isOk());

    auto corrupted = sealed.value();
    corrupted[corrupted.size() / 2] ^= 0xFF; // flip a byte in the middle

    auto opened = unseal(corrupted);
    REQUIRE(opened.isError());
    REQUIRE(opened.status().code() == ErrorCode::IntegrityViolation);
}

TEST_CASE("empty plaintext round-trips", "[crypto][dpapi]")
{
    auto sealed = seal(std::string_view{}, ProtectionScope::Machine);
    REQUIRE(sealed.isOk());

    auto opened = unseal(sealed.value());
    REQUIRE(opened.isOk());
    REQUIRE(opened.value().empty());
}

TEST_CASE("binary payloads round-trip", "[crypto][dpapi]")
{
    std::vector<u8> payload;
    for (int i = 0; i < 256; ++i) {
        payload.push_back(static_cast<u8>(i));
    }

    auto sealed = seal(payload, ProtectionScope::Machine);
    REQUIRE(sealed.isOk());

    auto opened = unseal(sealed.value());
    REQUIRE(opened.isOk());

    const auto view = opened.value().bytes();
    REQUIRE(view.size() == payload.size());
    REQUIRE(std::memcmp(view.data(), payload.data(), payload.size()) == 0);
}
