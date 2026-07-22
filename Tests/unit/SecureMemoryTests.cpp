#include <NovaVPN/Core/SecureMemory.h>

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>

using namespace nova;

TEST_CASE("SecureBuffer allocates zeroed, page-locked memory", "[security][memory]")
{
    SecureBuffer buffer{64};

    REQUIRE(buffer.size() == 64);
    REQUIRE_FALSE(buffer.empty());
    REQUIRE(buffer.data() != nullptr);

    for (const std::byte value : buffer.bytes()) {
        REQUIRE(value == std::byte{0});
    }
}

TEST_CASE("SecureBuffer copies content and is move-only", "[security][memory]")
{
    SecureBuffer original = SecureBuffer::copyFrom(std::string_view{"hunter2"});
    REQUIRE(original.size() == 7);
    REQUIRE(original.view() == "hunter2");

    SecureBuffer moved = std::move(original);
    REQUIRE(moved.view() == "hunter2");
    REQUIRE(original.size() == 0);       // NOLINT - checking the moved-from state
    REQUIRE(original.data() == nullptr);

    const SecureBuffer cloned = moved.clone();
    REQUIRE(cloned.view() == "hunter2");
    REQUIRE(cloned.data() != moved.data());

    static_assert(!std::is_copy_constructible_v<SecureBuffer>,
                  "a secret must never be copied implicitly");
    static_assert(!std::is_copy_assignable_v<SecureBuffer>,
                  "a secret must never be copied implicitly");
}

TEST_CASE("reset zeroes and releases", "[security][memory]")
{
    SecureBuffer buffer = SecureBuffer::copyFrom(std::string_view{"secret"});
    buffer.reset();

    REQUIRE(buffer.empty());
    REQUIRE(buffer.data() == nullptr);
    REQUIRE(buffer.view().empty());

    buffer.reset(); // idempotent
    REQUIRE(buffer.empty());
}

TEST_CASE("an empty SecureBuffer is valid", "[security][memory]")
{
    SecureBuffer buffer;
    REQUIRE(buffer.empty());
    REQUIRE(buffer.size() == 0);
    REQUIRE(buffer.view().empty());
    REQUIRE(buffer.bytes().empty());

    const SecureBuffer zeroSized{0};
    REQUIRE(zeroSized.empty());
}

TEST_CASE("secureZero clears a raw region", "[security][memory]")
{
    unsigned char scratch[16];
    std::memset(scratch, 0xAB, sizeof(scratch));

    secureZero(scratch, sizeof(scratch));
    for (const unsigned char byte : scratch) {
        REQUIRE(byte == 0);
    }

    secureZero(nullptr, 0); // must not fault
}

TEST_CASE("secureClear empties a std::string", "[security][memory]")
{
    std::string secret = "a password that lived in a std::string";
    secureClear(secret);
    REQUIRE(secret.empty());
}

TEST_CASE("constantTimeEquals compares correctly", "[security][memory]")
{
    REQUIRE(constantTimeEquals(std::string_view{"abc"}, std::string_view{"abc"}));
    REQUIRE_FALSE(constantTimeEquals(std::string_view{"abc"}, std::string_view{"abd"}));
    REQUIRE_FALSE(constantTimeEquals(std::string_view{"abc"}, std::string_view{"ab"}));
    REQUIRE(constantTimeEquals(std::string_view{""}, std::string_view{""}));

    // Differing only in the last byte must still compare unequal - a short
    // circuit here would be the timing leak this function exists to avoid.
    const std::string a(1024, 'x');
    std::string b = a;
    b.back() = 'y';
    REQUIRE_FALSE(constantTimeEquals(a, b));
}

TEST_CASE("SecureString wraps a SecureBuffer", "[security][memory]")
{
    SecureString secret{"correct horse battery staple"};

    REQUIRE(secret.size() == 28);
    REQUIRE_FALSE(secret.empty());
    REQUIRE(secret.equals("correct horse battery staple"));
    REQUIRE_FALSE(secret.equals("wrong"));

    SecureString clone = secret.clone();
    REQUIRE(clone.equals("correct horse battery staple"));

    secret.assign("new value");
    REQUIRE(secret.equals("new value"));
    REQUIRE(clone.equals("correct horse battery staple"));

    secret.clear();
    REQUIRE(secret.empty());

    static_assert(!std::is_copy_constructible_v<SecureString>,
                  "a secret must never be copied implicitly");
}
