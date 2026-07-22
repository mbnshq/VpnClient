// NovaVPN - Tunnel/Engine.h
// The protocol-engine plugin ABI.
//
// Everything protocol-specific lives behind IVpnEngine: OpenVPN in Phase 3,
// then WireGuard, Shadowsocks, V2Ray, Hysteria2 and the rest as plugins. The
// Tunnel above this interface deals only in "packets in, packets out, session
// facts, state changes" and therefore never needs to change when a protocol is
// added.
//
// ABI stability: plugins are separate DLLs, so the boundary is C-compatible
// (see NOVA_ENGINE_ABI_VERSION and the factory signature at the bottom). Data
// crossing it uses plain structs and UTF-8 strings, never STL containers.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/SecureMemory.h>
#include <NovaVPN/Logs/LogRecord.h>
#include <NovaVPN/Networking/Statistics.h>
#include <NovaVPN/Profiles/Profile.h>
#include <NovaVPN/Tunnel/Tunnel.h>

#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>

namespace nova::tunnel {

/// Callbacks the engine uses to talk back to its host. All are invoked on the
/// engine's own thread and must return promptly.
struct EngineHost {
    /// The engine produced a decrypted IP packet destined for the adapter.
    std::function<void(std::span<const u8>)> onPacketFromServer;
    /// Progress and lifecycle.
    std::function<void(ConnectionState, const Status&)> onStateChanged;
    /// Server handed us our addressing/DNS/routes.
    std::function<void(const TunnelSessionInfo&)> onSessionEstablished;
    /// Interactive authentication is required.
    std::function<void(const AuthChallenge&)> onChallenge;
    /// Engine-level log line (already redacted by the engine).
    std::function<void(logs::Level, const std::string&)> onLog;
    /// Counter snapshot for the dashboard.
    std::function<void(const net::TrafficCounters&)> onCounters;
};

/// Configuration handed to an engine at start. Derived from the profile but
/// resolved: host names already resolved, credentials already fetched.
struct EngineConfig {
    Id                        tunnelId;
    profiles::Profile         profile;
    ConnectCredentials        credentials;
    /// Interface index of the adapter the engine writes decrypted packets to.
    u32                       adapterInterfaceIndex = 0;
    /// Interface index the encrypted transport must bind to (the underlay), so
    /// the engine's own socket cannot be captured by its own default route.
    u32                       underlayInterfaceIndex = 0;
    /// Pre-resolved endpoints, in the order to try.
    std::vector<net::Endpoint> resolvedRemotes;
};

class IVpnEngine {
public:
    virtual ~IVpnEngine() = default;

    /// Stable identifier, e.g. "openvpn", "wireguard".
    [[nodiscard]] virtual std::string_view engineId() const noexcept = 0;
    [[nodiscard]] virtual std::string version() const = 0;

    /// Validates the profile against what this engine supports, before any
    /// network activity. Returning an error here is how an engine rejects, for
    /// example, a TCP-only profile it cannot serve.
    [[nodiscard]] virtual Status validate(const profiles::Profile& profile) const = 0;

    [[nodiscard]] virtual Status start(EngineConfig config, EngineHost host,
                                       const CancellationToken& token) = 0;

    /// Graceful stop; sends the protocol's close notification when it has one.
    [[nodiscard]] virtual Status stop() = 0;

    /// Hands an IP packet read from the adapter to the engine for encryption
    /// and transmission.
    [[nodiscard]] virtual Status sendPacket(std::span<const u8> packet) = 0;

    /// Supplies an answer to a challenge raised through EngineHost::onChallenge.
    [[nodiscard]] virtual Status provideCredential(ChallengeKind kind, SecureString value) = 0;

    /// Forces renegotiation of the data channel keys.
    [[nodiscard]] virtual Status renegotiate() = 0;
};

using VpnEnginePtr = std::shared_ptr<IVpnEngine>;

/// Registry of built-in and plugin-provided engines.
class IEngineRegistry {
public:
    virtual ~IEngineRegistry() = default;

    [[nodiscard]] virtual Result<VpnEnginePtr> create(std::string_view engineId) = 0;
    [[nodiscard]] virtual std::vector<std::string> availableEngines() const = 0;

    /// Loads plugin DLLs from the install directory's `plugins` folder. Each is
    /// Authenticode-verified against the product certificate before loading;
    /// unsigned plugins are rejected unless the machine is in developer mode.
    [[nodiscard]] virtual Status loadPlugins(const std::filesystem::path& directory) = 0;
};

using EngineRegistryPtr = std::shared_ptr<IEngineRegistry>;

/// ABI version of the plugin boundary. A plugin reporting a different major
/// version is refused.
inline constexpr u32 kEngineAbiVersion = 1;

/// C entry point every engine plugin must export:
///
///     extern "C" __declspec(dllexport)
///     nova::u32 NovaVpnEngineAbiVersion();
///
///     extern "C" __declspec(dllexport)
///     nova::tunnel::IVpnEngine* NovaVpnCreateEngine(const char* engineId);
///
/// The host owns the returned pointer and destroys it through the virtual
/// destructor before unloading the module.
using EngineAbiVersionFn = u32 (*)();
using EngineFactoryFn    = IVpnEngine* (*)(const char*);

/// A built-in engine factory registered in-process (as opposed to a plugin DLL).
using BuiltinEngineFactory = std::function<VpnEnginePtr()>;

/// Creates the standard registry. Built-in engines are registered by the
/// service at startup via registerBuiltin(); plugins are discovered from disk
/// with loadPlugins(). `requireSignedPlugins` mirrors the Wintun policy: a
/// plugin whose Authenticode signature does not verify is refused unless the
/// machine is explicitly in developer mode.
[[nodiscard]] EngineRegistryPtr makeEngineRegistry(bool requireSignedPlugins = true);

/// Extended registry surface used by the service to install built-in engines.
class IMutableEngineRegistry : public IEngineRegistry {
public:
    /// Registers a built-in engine under `engineId`. Replacing an existing id
    /// is refused so a plugin can never shadow a built-in.
    [[nodiscard]] virtual Status registerBuiltin(std::string engineId,
                                                 BuiltinEngineFactory factory) = 0;
};

} // namespace nova::tunnel
