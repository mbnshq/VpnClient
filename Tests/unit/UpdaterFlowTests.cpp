// The updater's check/download/stage flow, driven with a canned HTTP fetcher
// and a real generated signing key, so the whole verify-before-trust path runs
// offline. Mirrors how the real updater behaves against a feed.
#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Updater/Updater.h>

#include <catch2/catch_test_macros.hpp>

#include <Windows.h>
#include <bcrypt.h>

#include <filesystem>
#include <map>

#pragma comment(lib, "bcrypt.lib")

using namespace nova;
using namespace nova::updater;

namespace {

/// Generated ECDSA key exposing the public point and a signing operation,
/// matching SignatureVerifierTests.
struct SigningKey
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;

    SigningKey()
    {
        BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0);
        BCryptGenerateKeyPair(alg, &key, 256, 0);
        BCryptFinalizeKeyPair(key, 0);
    }
    ~SigningKey()
    {
        if (key) BCryptDestroyKey(key);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    }

    std::vector<u8> publicPoint() const
    {
        struct Blob { BCRYPT_ECCKEY_BLOB header; u8 xy[64]; } blob{};
        ULONG w = 0;
        BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                        reinterpret_cast<PUCHAR>(&blob), sizeof(blob), &w, 0);
        std::vector<u8> pt;
        pt.push_back(0x04);
        pt.insert(pt.end(), blob.xy, blob.xy + 64);
        return pt;
    }

    std::vector<u8> sign(const std::string& payload) const
    {
        auto digest = sha256(std::span{reinterpret_cast<const u8*>(payload.data()),
                                       payload.size()});
        ULONG needed = 0;
        BCryptSignHash(key, nullptr, digest.value().data(),
                       (ULONG)digest.value().size(), nullptr, 0, &needed, 0);
        std::vector<u8> sig(needed);
        ULONG w = 0;
        BCryptSignHash(key, nullptr, digest.value().data(),
                       (ULONG)digest.value().size(), sig.data(), needed, &w, 0);
        sig.resize(w);
        return sig;
    }
};

/// Canned fetcher: serves a fixed map of URL -> bytes for get(), and copies a
/// fixed package for download().
class FakeFetcher final : public IHttpFetcher
{
public:
    std::map<std::string, std::vector<u8>> Responses;
    std::vector<u8> Package;

    Result<std::vector<u8>> get(const std::string& url, const CancellationToken&) override
    {
        auto it = Responses.find(url);
        if (it == Responses.end())
        {
            return Status{ErrorCode::UpdateDownload, "404 " + url};
        }
        return it->second;
    }

    Status download(const std::string& url, const std::filesystem::path& dest,
                    std::function<void(u64, u64)> onProgress, const CancellationToken&) override
    {
        (void)url;
        onProgress((u64)Package.size(), (u64)Package.size());
        return nova::file::writeAtomic(dest, Package);
    }
};

std::vector<u8> bytesOf(const std::string& s)
{
    return std::vector<u8>{s.begin(), s.end()};
}

struct Fixture
{
    SigningKey signer;
    std::shared_ptr<FakeFetcher> fetcher = std::make_shared<FakeFetcher>();
    std::filesystem::path stagingDir;

    Fixture()
    {
        stagingDir = std::filesystem::temp_directory_path() /
                     ("novavpn-upd-" + Uuid::generate().toString());
        std::filesystem::create_directories(stagingDir);
    }
    ~Fixture()
    {
        std::error_code ec;
        std::filesystem::remove_all(stagingDir, ec);
    }

    /// Publishes a manifest for `version` whose package hash covers `package`,
    /// signed with the real key. Uses a Windows system DLL as the "package" so
    /// Authenticode verification passes.
    ReleaseInfo Publish(const std::string& version, const std::string& packageUrl,
                        const std::vector<u8>& package)
    {
        auto hash = sha256(package).value();
        const std::string hashHex = str::toHex(hash.data(), 32);

        const std::string manifest =
            "{\"version\":\"" + version + "\",\"full\":{\"url\":\"" + packageUrl +
            "\",\"sha256\":\"" + hashHex + "\",\"size\":" + std::to_string(package.size()) +
            "}}";

        fetcher->Responses["https://feed.test/stable/manifest.json"] = bytesOf(manifest);
        fetcher->Responses["https://feed.test/stable/manifest.json.sig"] = signer.sign(manifest);
        fetcher->Package = package;

        ReleaseInfo info;
        info.version = version;
        info.fullPackageUrl = packageUrl;
        info.fullPackageSha256 = hashHex;
        return info;
    }

    UpdaterPtr Make(const std::string& currentVersion)
    {
        UpdaterConfig config;
        config.feedBaseUrl = "https://feed.test/";
        config.stagingDir = stagingDir;
        config.currentVersion = currentVersion;
        auto verifier = makeSignatureVerifier(signer.publicPoint()).value();
        return makeUpdater(fetcher, verifier, config);
    }
};

std::vector<u8> systemDllBytes()
{
    // A signed OS binary, so Authenticode verification of the "package" passes.
    return nova::file::readAll("C:\\Windows\\System32\\kernel32.dll").value();
}

} // namespace

TEST_CASE("check finds a newer signed release", "[updater][flow]")
{
    Fixture f;
    auto package = systemDllBytes();
    f.Publish("2.0.0", "https://feed.test/stable/pkg.msi", package);

    auto updater = f.Make("1.0.0");
    CancellationSource src;
    auto release = updater->check(Channel::Stable, src.token());
    REQUIRE(release.isOk());
    REQUIRE(release.value().version == "2.0.0");
}

TEST_CASE("check reports up-to-date when not newer", "[updater][flow]")
{
    Fixture f;
    f.Publish("1.0.0", "https://feed.test/stable/pkg.msi", systemDllBytes());

    auto updater = f.Make("1.0.0");
    CancellationSource src;
    auto release = updater->check(Channel::Stable, src.token());
    REQUIRE(release.isError());
    REQUIRE(release.status().code() == ErrorCode::UpdateUnavailable);
}

TEST_CASE("a manifest with a bad signature is refused", "[updater][flow][security]")
{
    Fixture f;
    f.Publish("2.0.0", "https://feed.test/stable/pkg.msi", systemDllBytes());
    // Tamper with the manifest after it was signed.
    f.fetcher->Responses["https://feed.test/stable/manifest.json"] =
        bytesOf("{\"version\":\"9.9.9\",\"full\":{\"url\":\"x\",\"sha256\":\"" +
                std::string(64, 'a') + "\"}}");

    auto updater = f.Make("1.0.0");
    CancellationSource src;
    auto release = updater->check(Channel::Stable, src.token());
    REQUIRE(release.isError());
    REQUIRE(release.status().code() == ErrorCode::SignatureInvalid);
}

TEST_CASE("download verifies hash and Authenticode then stages", "[updater][flow]")
{
    Fixture f;
    auto package = systemDllBytes();
    auto release = f.Publish("2.0.0", "https://feed.test/stable/pkg.msi", package);

    auto updater = f.Make("1.0.0");
    CancellationSource src;

    bool progressSeen = false;
    const Status status = updater->download(
        release, [&](const UpdateProgress&) { progressSeen = true; }, src.token());
    REQUIRE(status.isOk());
    REQUIRE(progressSeen);
    REQUIRE(updater->progress().stage == UpdateStage::ReadyToInstall);
}

TEST_CASE("download rejects a package whose hash does not match", "[updater][flow][security]")
{
    Fixture f;
    auto release = f.Publish("2.0.0", "https://feed.test/stable/pkg.msi", systemDllBytes());
    // Serve a different package than the manifest hash covers.
    f.fetcher->Package = bytesOf("this is not the package the manifest describes");

    auto updater = f.Make("1.0.0");
    CancellationSource src;
    const Status status = updater->download(release, nullptr, src.token());
    REQUIRE(status.isError());
    REQUIRE(status.code() == ErrorCode::ChecksumMismatch);
}

TEST_CASE("installStaged refuses without a staged package and defers to the installer",
          "[updater][flow]")
{
    Fixture f;
    auto updater = f.Make("1.0.0");

    // Nothing staged yet.
    REQUIRE(updater->installStaged().code() == ErrorCode::InvalidState);

    // After a successful download, install is NotImplemented (needs the MSI)
    // rather than pretending to install.
    auto release = f.Publish("2.0.0", "https://feed.test/stable/pkg.msi", systemDllBytes());
    CancellationSource src;
    REQUIRE(updater->download(release, nullptr, src.token()).isOk());
    REQUIRE(updater->installStaged().code() == ErrorCode::NotImplemented);

    REQUIRE(updater->discardStaged().isOk());
    REQUIRE(updater->installStaged().code() == ErrorCode::InvalidState);
}
