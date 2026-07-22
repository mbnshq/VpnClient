// NovaVPN - Updater/Updater.h
// Automatic updates with delta packages and signature verification.
//
// Threat model: the updater runs as SYSTEM and installs code. It is therefore
// the highest-value target in the product, and the rules are absolute:
//   * the manifest is fetched over TLS with certificate pinning,
//   * the manifest is signed; the signature is verified against a public key
//     compiled into the binary, before a single field is parsed for meaning,
//   * the package hash comes from the verified manifest, never from the server
//     response headers,
//   * the downloaded package is Authenticode-verified against the product
//     certificate before execution,
//   * a delta is applied to a copy, and the result is hash-checked against the
//     manifest's full-image hash before anything is replaced,
//   * downgrades are refused unless explicitly allowed by policy.
//
// Implemented in Phase 7.
#pragma once

#include <NovaVPN/Core/Cancellation.h>
#include <NovaVPN/Core/Result.h>

#include <array>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace nova::updater {

enum class Channel : u8 { Stable, Beta, Dev };

[[nodiscard]] std::string_view toString(Channel channel) noexcept;
[[nodiscard]] bool parseChannel(std::string_view text, Channel& out) noexcept;

/// One available release, as described by the signed manifest.
struct ReleaseInfo {
    std::string version;      ///< "1.4.2"
    u64         ordinal = 0;  ///< Comparable form; see version::kOrdinal.
    Channel     channel = Channel::Stable;
    std::string releaseNotes; ///< Markdown, shown in the update dialog.
    SystemTime  publishedAt{};
    std::string fullPackageUrl;
    std::string fullPackageSha256;
    u64         fullPackageSize = 0;
    /// Delta from a specific base version, when one is offered.
    std::string deltaFromVersion;
    std::string deltaPackageUrl;
    std::string deltaPackageSha256;
    u64         deltaPackageSize = 0;
    /// True when the release fixes a security issue; such updates are applied
    /// even if the user has automatic updates set to "notify only".
    bool        isSecurityUpdate = false;
    /// Minimum version that can upgrade directly to this one.
    std::string minimumUpgradeFrom;
};

enum class UpdateStage : u8 {
    Idle,
    CheckingManifest,
    VerifyingManifest,
    Downloading,
    VerifyingPackage,
    ApplyingDelta,
    Staging,
    ReadyToInstall,
    Installing,
    Failed,
};

struct UpdateProgress {
    UpdateStage stage = UpdateStage::Idle;
    /// 0.0 - 1.0 within the current stage; -1 when indeterminate.
    double      fraction = -1.0;
    u64         bytesDownloaded = 0;
    u64         bytesTotal = 0;
    std::string detail;
};

class IUpdater {
public:
    virtual ~IUpdater() = default;

    /// Fetches and verifies the manifest. Returns Unavailable when the current
    /// build is already the newest on the channel.
    [[nodiscard]] virtual Result<ReleaseInfo> check(Channel channel,
                                                    const CancellationToken& token) = 0;

    /// Downloads (delta when possible), verifies and stages the package.
    /// Does not restart anything - staging is deliberately separate from
    /// installing so the user chooses when the tunnel drops.
    [[nodiscard]] virtual Status download(const ReleaseInfo& release,
                                          std::function<void(const UpdateProgress&)> onProgress,
                                          const CancellationToken& token) = 0;

    /// Launches the staged installer and exits. The service is restarted by the
    /// installer; an active tunnel is torn down cleanly first, and the kill
    /// switch state is preserved across the restart.
    [[nodiscard]] virtual Status installStaged() = 0;

    /// Removes staged packages (disk hygiene, or after a failed apply).
    [[nodiscard]] virtual Status discardStaged() = 0;

    [[nodiscard]] virtual UpdateProgress progress() const = 0;
};

using UpdaterPtr = std::shared_ptr<IUpdater>;

/// Signature and hash verification, separated so it can be unit-tested against
/// known-good and tampered fixtures without any network.
class ISignatureVerifier {
public:
    virtual ~ISignatureVerifier() = default;

    /// Verifies a detached ECDSA-P256/SHA-256 signature over `payload` against
    /// the verifier's public key. (ECDSA P-256 rather than Ed25519 because it
    /// is natively and reliably supported by Windows CNG across all supported
    /// OS builds.) The signature is the raw r||s form, 64 bytes.
    [[nodiscard]] virtual Status verifyManifest(std::span<const u8> payload,
                                                std::span<const u8> signature) const = 0;

    /// Verifies the file's Authenticode signature chains to the product
    /// certificate and that the certificate was valid at signing time.
    [[nodiscard]] virtual Status verifyAuthenticode(
        const std::filesystem::path& file) const = 0;

    /// Compares a file's SHA-256 against `expectedHex` in constant time.
    [[nodiscard]] virtual Status verifyHash(const std::filesystem::path& file,
                                            std::string_view expectedHex) const = 0;
};

/// Creates a signature verifier bound to a SubjectPublicKeyInfo (DER) ECDSA
/// P-256 public key. The production build passes the key compiled into the
/// binary; tests pass a generated key.
[[nodiscard]] Result<std::shared_ptr<ISignatureVerifier>> makeSignatureVerifier(
    std::span<const u8> publicKeyDer);

/// SHA-256 of a byte span (used by the manifest and hash paths).
[[nodiscard]] Result<std::array<u8, 32>> sha256(std::span<const u8> data);

/// SHA-256 of a file, streamed so a large package is not read whole into memory.
[[nodiscard]] Result<std::array<u8, 32>> sha256File(const std::filesystem::path& path);

/// Parses and validates a release manifest document (already signature-checked
/// by the caller). Reports a precise error for a malformed or downgrade
/// manifest.
[[nodiscard]] Result<ReleaseInfo> parseManifest(std::string_view json, Channel channel);

/// Compares two dotted version strings by their version::ordinal form.
/// Returns <0, 0 or >0.
[[nodiscard]] int compareVersions(std::string_view a, std::string_view b);

/// Fetches bytes from an https URL. Abstracted so the updater's verify/stage
/// logic is testable offline with a canned fetcher; the production
/// implementation is WinHTTP with certificate pinning.
class IHttpFetcher {
public:
    virtual ~IHttpFetcher() = default;

    /// GETs `url` into memory (manifests, signatures - small).
    [[nodiscard]] virtual Result<std::vector<u8>> get(const std::string& url,
                                                      const CancellationToken& token) = 0;

    /// Downloads `url` to `destination`, reporting progress. Used for packages.
    [[nodiscard]] virtual Status download(const std::string& url,
                                          const std::filesystem::path& destination,
                                          std::function<void(u64, u64)> onProgress,
                                          const CancellationToken& token) = 0;
};

using HttpFetcherPtr = std::shared_ptr<IHttpFetcher>;

/// WinHTTP-backed fetcher with certificate pinning against the pinned leaf
/// public-key SHA-256 set (empty = no pinning, for internal test servers).
[[nodiscard]] HttpFetcherPtr makeWinHttpFetcher(std::vector<std::string> pinnedKeySha256 = {});

/// Configuration for the updater.
struct UpdaterConfig {
    std::string           feedBaseUrl;   ///< e.g. "https://updates.example.net/"
    std::filesystem::path stagingDir;    ///< where packages are downloaded
    std::string           currentVersion;///< this build's version
    bool                  allowDowngrade = false;
};

/// Creates the updater over a fetcher, a signature verifier and a config. The
/// verifier holds the pinned manifest-signing key; the fetcher does transport.
[[nodiscard]] UpdaterPtr makeUpdater(HttpFetcherPtr fetcher,
                                     std::shared_ptr<ISignatureVerifier> verifier,
                                     UpdaterConfig config);

} // namespace nova::updater
