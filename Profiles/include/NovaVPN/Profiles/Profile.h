// NovaVPN - Profiles/Profile.h
// The connection profile: everything the user imported or configured about one
// server, plus the metadata the UI organises them by.
//
// Secrets are deliberately *not* stored here. A profile holds a reference to a
// credential in the Windows Credential Manager; the plaintext exists only in a
// SecureString held by the connecting tunnel, for as long as the handshake
// needs it. See docs/SECURITY.md.
#pragma once

#include <NovaVPN/Core/Json.h>
#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/Types.h>
#include <NovaVPN/Networking/IpAddress.h>

#include <optional>
#include <string>
#include <vector>

namespace nova::profiles {

/// How the server authenticates the client.
enum class AuthMethod : u8 {
    /// Client certificate only (cert + key in the profile).
    Certificate,
    /// Username/password only (auth-user-pass).
    UserPassword,
    /// Both - the common enterprise setup.
    CertificateAndPassword,
    /// Password plus a one-time code appended or requested interactively.
    UserPasswordTotp,
    /// Static key (peer-to-peer OpenVPN without TLS).
    StaticKey,
};

[[nodiscard]] std::string_view toString(AuthMethod method) noexcept;
[[nodiscard]] bool parseAuthMethod(std::string_view text, AuthMethod& out) noexcept;

/// Underlying tunnel implementation. OpenVPN is Phase 3; the rest arrive
/// through the plugin API and are listed here so the model does not need a
/// breaking change later.
enum class EngineKind : u8 {
    OpenVpn,
    WireGuard,
    Plugin, ///< Provided by a loaded plugin; see `engineId`.
};

[[nodiscard]] std::string_view toString(EngineKind kind) noexcept;
[[nodiscard]] bool parseEngineKind(std::string_view text, EngineKind& out) noexcept;

/// One `remote` entry. A profile may list several; the engine tries them in
/// order (or shuffled, when the profile says so).
struct RemoteEntry {
    std::string host;
    u16         port = 1194;
    Transport   transport = Transport::Udp;
    /// Optional friendly label shown in the server picker.
    std::string label;

    [[nodiscard]] Status validate() const;
};

/// Reference to material held outside the profile.
///
/// `credentialTarget` is the Windows Credential Manager target name; the blob
/// itself never appears in the database or in an exported profile unless the
/// user explicitly asks to include secrets.
struct CredentialRef {
    std::string credentialTarget;
    /// Cached user name for display and pre-fill. Never the password.
    std::string userName;
    bool        savePassword = false;
    /// Prompt for a one-time code at connect time.
    bool        requiresTotp = false;
};

/// PKI material. Paths point into the profile directory; inline PEM is stored
/// encrypted in the profile blob.
struct CertificateSet {
    std::string caPem;            ///< Server CA chain (public, safe to store).
    std::string certificatePem;   ///< Client certificate (public).
    /// Credential Manager target holding the private key, or empty when the key
    /// lives in the Windows certificate store / on a smart card.
    std::string privateKeyTarget;
    /// Thumbprint of a certificate in the Windows store (CAPI/CNG path).
    std::string storeThumbprint;
    std::string tlsAuthKeyTarget; ///< tls-auth / tls-crypt key reference.
    /// 0 = tls-auth, 1 = tls-crypt, 2 = tls-crypt-v2.
    int         tlsWrapMode = 0;
    /// Expected server certificate subject/EKU checks (verify-x509-name).
    std::string verifyX509Name;
    std::string peerFingerprintSha256;
};

/// DNS behaviour for this profile, overriding the global setting.
struct ProfileDnsSettings {
    bool                   useServerPushed = true;
    std::vector<net::IpAddress> servers;
    std::vector<std::string>    searchDomains;
    bool                   blockOutsideDns = true;
    std::optional<bool>    dohEnabled;
    std::string            dohTemplate;
};

/// Everything about the profile that is not connection-critical but that the
/// UI organises around.
struct ProfileMetadata {
    std::string              country;      ///< ISO 3166-1 alpha-2, e.g. "HK".
    std::string              city;
    std::string              notes;
    std::vector<std::string> tags;
    bool                     favorite = false;
    /// Relative path (under the profile directory) of the tile image, or a
    /// well-known flag identifier.
    std::string              imageRef;
    SystemTime               createdAt{};
    SystemTime               modifiedAt{};
    SystemTime               lastConnectedAt{};
    u64                      connectCount = 0;
    /// Cumulative traffic, for the "most used" sort.
    ByteCount                totalBytesSent = 0;
    ByteCount                totalBytesReceived = 0;
};

/// Behaviour switches per profile.
struct ProfileOptions {
    bool                autoConnect = false;
    bool                autoReconnect = true;
    bool                shuffleRemotes = false;
    /// Send all traffic through the tunnel (redirect-gateway).
    bool                redirectGateway = true;
    bool                blockIpv6 = true;
    std::optional<u32>  mtu;
    std::optional<u32>  keepaliveIntervalSeconds;
    std::optional<u32>  keepaliveTimeoutSeconds;
    /// Compression is off by default: LZO/LZ4 with a VPN is a known oracle
    /// (VORACLE), so enabling it is an explicit, per-profile decision.
    bool                allowCompression = false;
    std::string         cipherOverride;
    std::string         authDigestOverride;
    /// HTTP/SOCKS proxy to reach the remote through.
    std::string         proxyUrl;
};

/// A complete connection profile.
struct Profile {
    Id                       id;          ///< UUID; stable for the profile's life.
    std::string              name;        ///< User-visible, unique per install.
    EngineKind               engine = EngineKind::OpenVpn;
    /// Plugin identifier when engine == Plugin.
    std::string              engineId;
    std::vector<RemoteEntry> remotes;
    AuthMethod               authMethod = AuthMethod::CertificateAndPassword;
    CredentialRef            credentials;
    CertificateSet           certificates;
    ProfileDnsSettings       dns;
    ProfileOptions           options;
    ProfileMetadata          metadata;

    /// The original imported configuration, verbatim. Kept so the engine can be
    /// handed exactly what the administrator shipped, and so re-import after an
    /// upgrade is lossless. Stored encrypted at rest.
    std::string              sourceConfig;
    /// SHA-256 of sourceConfig, for change detection on re-import.
    std::string              sourceHash;

    /// Rejects a profile that could not connect or that would be unsafe:
    /// no remotes, malformed host/port, auth method without the material it
    /// needs, or a DNS override with no servers.
    [[nodiscard]] Status validate() const;

    /// Primary remote, or nullopt when the profile has none.
    [[nodiscard]] std::optional<RemoteEntry> primaryRemote() const;

    /// "Hong Kong 01 (hk1.example.net:1194/udp)" for logs and notifications.
    [[nodiscard]] std::string displaySummary() const;
};

/// JSON round-trip. `includeSecrets` controls whether credential *references*
/// and the source configuration are emitted - export-to-file uses false so a
/// shared profile cannot carry another user's key material.
[[nodiscard]] Json toJson(const Profile& profile, bool includeSecrets);
[[nodiscard]] Result<Profile> fromJson(const Json& value);

} // namespace nova::profiles
