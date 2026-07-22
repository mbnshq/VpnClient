// These generate a real ECDSA P-256 keypair with CNG, sign a payload and verify
// it through the same path the updater uses - so the signature, hash and
// manifest logic are exercised end to end without any network or fixtures.
#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Updater/Updater.h>

#include <catch2/catch_test_macros.hpp>

#include <Windows.h>
#include <bcrypt.h>

#include <array>
#include <filesystem>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

using namespace nova;
using namespace nova::updater;

namespace {

/// A freshly generated ECDSA P-256 key, exposing the SPKI-ish public blob and a
/// signing operation, so the test can produce genuine signatures.
struct TestKey {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;

    TestKey()
    {
        REQUIRE(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) == 0);
        REQUIRE(BCryptGenerateKeyPair(alg, &key, 256, 0) == 0);
        REQUIRE(BCryptFinalizeKeyPair(key, 0) == 0);
    }
    ~TestKey()
    {
        if (key) BCryptDestroyKey(key);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    }

    /// The public key as an uncompressed point (0x04 || X || Y), which the
    /// verifier accepts as the tail of an SPKI.
    std::vector<u8> publicPoint() const
    {
        struct Blob {
            BCRYPT_ECCKEY_BLOB header;
            u8 xy[64];
        } blob{};
        ULONG written = 0;
        REQUIRE(BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                reinterpret_cast<PUCHAR>(&blob), sizeof(blob), &written, 0) == 0);
        std::vector<u8> out;
        out.push_back(0x04);
        out.insert(out.end(), blob.xy, blob.xy + 64);
        return out;
    }

    std::vector<u8> sign(std::span<const u8> payload) const
    {
        // Hash first (the verifier verifies over SHA-256 of the payload).
        auto digest = sha256(payload);
        REQUIRE(digest.isOk());

        ULONG needed = 0;
        REQUIRE(BCryptSignHash(key, nullptr, digest.value().data(),
                               static_cast<ULONG>(digest.value().size()), nullptr, 0, &needed,
                               0) == 0);
        std::vector<u8> signature(needed);
        ULONG written = 0;
        REQUIRE(BCryptSignHash(key, nullptr, digest.value().data(),
                               static_cast<ULONG>(digest.value().size()), signature.data(),
                               needed, &written, 0) == 0);
        signature.resize(written);
        return signature;
    }
};

std::span<const u8> bytes(std::string_view s)
{
    return std::span{reinterpret_cast<const u8*>(s.data()), s.size()};
}

} // namespace

TEST_CASE("a valid manifest signature verifies", "[updater][signature]")
{
    TestKey signer;
    auto verifier = makeSignatureVerifier(signer.publicPoint());
    REQUIRE(verifier.isOk());

    const std::string payload = R"({"version":"1.2.3"})";
    const auto signature = signer.sign(bytes(payload));

    REQUIRE(verifier.value()->verifyManifest(bytes(payload), signature).isOk());
}

TEST_CASE("a tampered payload fails verification", "[updater][signature][security]")
{
    TestKey signer;
    auto verifier = makeSignatureVerifier(signer.publicPoint()).value();

    const std::string payload = R"({"version":"1.2.3"})";
    const auto signature = signer.sign(bytes(payload));

    const std::string tampered = R"({"version":"9.9.9"})";
    const Status status = verifier->verifyManifest(bytes(tampered), signature);
    REQUIRE(status.isError());
    REQUIRE(status.code() == ErrorCode::SignatureInvalid);
}

TEST_CASE("a signature from a different key fails", "[updater][signature][security]")
{
    TestKey signer;
    TestKey attacker;
    auto verifier = makeSignatureVerifier(signer.publicPoint()).value();

    const std::string payload = R"({"version":"1.2.3"})";
    const auto attackerSig = attacker.sign(bytes(payload));

    REQUIRE(verifier->verifyManifest(bytes(payload), attackerSig).isError());
}

TEST_CASE("a wrong-length signature is rejected", "[updater][signature]")
{
    TestKey signer;
    auto verifier = makeSignatureVerifier(signer.publicPoint()).value();
    std::vector<u8> shortSig(10, 0);
    REQUIRE(verifier->verifyManifest(bytes("x"), shortSig).isError());
}

TEST_CASE("SHA-256 matches known vectors", "[updater][hash]")
{
    // SHA-256("") and SHA-256("abc") are standard test vectors.
    auto empty = sha256(std::span<const u8>{});
    REQUIRE(empty.isOk());
    REQUIRE(str::toHex(empty.value().data(), 32) ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    auto abc = sha256(bytes("abc"));
    REQUIRE(abc.isOk());
    REQUIRE(str::toHex(abc.value().data(), 32) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("verifyHash checks a file against an expected digest",
          "[updater][hash]")
{
    const auto path = std::filesystem::temp_directory_path() /
                      ("novavpn-hash-" + Uuid::generate().toString() + ".bin");
    REQUIRE(file::writeAtomicText(path, "abc").isOk());

    TestKey key; // any verifier instance; verifyHash needs no key
    auto verifier = makeSignatureVerifier(key.publicPoint()).value();

    REQUIRE(verifier
                ->verifyHash(path,
                             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .isOk());

    // A wrong hash is a checksum mismatch.
    const Status wrong = verifier->verifyHash(
        path, "0000000000000000000000000000000000000000000000000000000000000000");
    REQUIRE(wrong.code() == ErrorCode::ChecksumMismatch);

    // A malformed expected hash is an argument error.
    REQUIRE(verifier->verifyHash(path, "notahash").code() == ErrorCode::InvalidArgument);

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST_CASE("Authenticode verification accepts a signed OS binary and rejects an "
          "unsigned file",
          "[updater][authenticode]")
{
    TestKey key;
    auto verifier = makeSignatureVerifier(key.publicPoint()).value();

    // A Windows system DLL is Authenticode/catalog-signed.
    const std::filesystem::path signed_ =
        std::filesystem::path{"C:\\Windows\\System32\\kernel32.dll"};
    if (std::filesystem::exists(signed_)) {
        REQUIRE(verifier->verifyAuthenticode(signed_).isOk());
    }

    // An arbitrary unsigned file must fail.
    const auto unsigned_ = std::filesystem::temp_directory_path() /
                           ("novavpn-unsigned-" + Uuid::generate().toString() + ".bin");
    REQUIRE(file::writeAtomicText(unsigned_, "not a signed binary").isOk());
    REQUIRE(verifier->verifyAuthenticode(unsigned_).isError());

    std::error_code ec;
    std::filesystem::remove(unsigned_, ec);
}

TEST_CASE("version comparison orders by numeric components", "[updater][version]")
{
    REQUIRE(compareVersions("1.2.3", "1.2.3") == 0);
    REQUIRE(compareVersions("1.2.3", "1.2.4") < 0);
    REQUIRE(compareVersions("1.3.0", "1.2.9") > 0);
    REQUIRE(compareVersions("2.0.0", "1.9.9") > 0);
    REQUIRE(compareVersions("1.0.0.5", "1.0.0.4") > 0);
    REQUIRE(compareVersions("0.1.0", "1.0.0") < 0);
}

TEST_CASE("manifest parsing extracts the release and rejects malformed input",
          "[updater][manifest]")
{
    const std::string manifest = R"({
        "version": "1.4.2",
        "releaseNotes": "Fixes",
        "securityUpdate": true,
        "full": { "url": "https://example.net/pkg.msi",
                  "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                  "size": 12345 }
    })";

    auto release = parseManifest(manifest, Channel::Stable);
    REQUIRE(release.isOk());
    REQUIRE(release.value().version == "1.4.2");
    REQUIRE(release.value().isSecurityUpdate);
    REQUIRE(release.value().fullPackageSize == 12345);
    REQUIRE(release.value().channel == Channel::Stable);

    // Missing the required version field.
    REQUIRE(parseManifest(R"({"full":{"url":"x","sha256":"y"}})", Channel::Stable).isError());
    // A package hash that is not 64 hex chars.
    REQUIRE(parseManifest(R"({"version":"1.0.0","full":{"url":"x","sha256":"short"}})",
                          Channel::Stable)
                .isError());
    // Not JSON at all.
    REQUIRE(parseManifest("{ broken", Channel::Stable).isError());
}

TEST_CASE("channels round-trip through text", "[updater]")
{
    Channel channel = Channel::Stable;
    REQUIRE(parseChannel("beta", channel));
    REQUIRE(channel == Channel::Beta);
    REQUIRE(parseChannel("nightly", channel));
    REQUIRE(channel == Channel::Dev);
    REQUIRE(toString(Channel::Stable) == "stable");
    REQUIRE_FALSE(parseChannel("weekly", channel));
}
