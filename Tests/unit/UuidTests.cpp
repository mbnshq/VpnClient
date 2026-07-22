#include <NovaVPN/Core/Uuid.h>

#include <catch2/catch_test_macros.hpp>

#include <set>

using namespace nova;

TEST_CASE("generated UUIDs are v4 and unique", "[uuid]")
{
    std::set<std::string> seen;
    for (int i = 0; i < 512; ++i) {
        const Uuid id = Uuid::generate();
        REQUIRE_FALSE(id.isNil());

        const std::string text = id.toString();
        REQUIRE(text.size() == 36);
        REQUIRE(text[14] == '4');                       // version nibble
        REQUIRE((text[19] == '8' || text[19] == '9' ||
                 text[19] == 'a' || text[19] == 'b'));  // variant nibble

        REQUIRE(seen.insert(text).second);
    }
}

TEST_CASE("UUIDs round-trip through text", "[uuid]")
{
    const Uuid original = Uuid::generate();

    Uuid parsed;
    REQUIRE(Uuid::tryParse(original.toString(), parsed));
    REQUIRE(parsed == original);

    // Braces and mixed case are accepted; the canonical form is lowercase.
    Uuid braced;
    REQUIRE(Uuid::tryParse("{550E8400-E29B-41D4-A716-446655440000}", braced));
    REQUIRE(braced.toString() == "550e8400-e29b-41d4-a716-446655440000");
}

TEST_CASE("malformed UUIDs are rejected", "[uuid]")
{
    Uuid out;
    REQUIRE_FALSE(Uuid::tryParse("", out));
    REQUIRE_FALSE(Uuid::tryParse("not-a-uuid", out));
    REQUIRE_FALSE(Uuid::tryParse("550e8400e29b41d4a716446655440000", out)); // no dashes
    REQUIRE_FALSE(Uuid::tryParse("550e8400-e29b-41d4-a716-44665544000", out)); // short
    REQUIRE_FALSE(Uuid::tryParse("550e8400-e29b-41d4-a716-4466554400000", out)); // long
    REQUIRE_FALSE(Uuid::tryParse("550e8400-e29b-41d4-a716-44665544000g", out)); // non-hex
}

TEST_CASE("a default-constructed UUID is nil", "[uuid]")
{
    const Uuid nil;
    REQUIRE(nil.isNil());
    REQUIRE(nil.toString() == "00000000-0000-0000-0000-000000000000");
}

TEST_CASE("randomBytes fills the whole span", "[uuid][random]")
{
    std::array<u8, 64> buffer{};
    REQUIRE(randomBytes(buffer).isOk());

    // A 64-byte all-zero draw has probability 2^-512; treating it as failure is
    // safe and catches a silently non-functioning CSPRNG.
    bool anyNonZero = false;
    for (const u8 byte : buffer) {
        anyNonZero = anyNonZero || byte != 0;
    }
    REQUIRE(anyNonZero);

    REQUIRE(randomBytes({}).isOk());
}

TEST_CASE("randomBelow stays in range and rejects a zero bound", "[uuid][random]")
{
    for (int i = 0; i < 256; ++i) {
        const auto value = randomBelow(10);
        REQUIRE(value.isOk());
        REQUIRE(value.value() < 10);
    }

    const auto single = randomBelow(1);
    REQUIRE(single.isOk());
    REQUIRE(single.value() == 0);

    REQUIRE(randomBelow(0).isError());
}
