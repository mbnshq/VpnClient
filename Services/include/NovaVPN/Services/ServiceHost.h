// NovaVPN - Services/ServiceHost.h
// Windows service plumbing: registration, the SCM control dispatcher and the
// lifecycle hooks the service body implements.
//
// Why a service at all: creating adapters, editing the route table and
// programming WFP all require SYSTEM. Putting them in the UI process would mean
// prompting for elevation on every action and leaving an elevated GUI running.
// Instead the privileged work lives here and the UI is an ordinary user process
// talking over a named pipe.
#pragma once

#include <NovaVPN/Core/Result.h>

#include <functional>
#include <memory>
#include <string>

namespace nova::service {

/// Fixed identity of the service, used by the installer, the UI and the
/// updater alike.
inline constexpr std::string_view kServiceName        = "NovaVPNService";
inline constexpr std::string_view kServiceDisplayName = "NovaVPN Connection Service";
inline constexpr std::string_view kServiceDescription =
    "Manages NovaVPN tunnels, routing, split tunnelling and network protection. "
    "Stopping this service disconnects any active VPN connection.";

/// What the service body must provide. Implemented by NovaVpnService in
/// Services/src/ServiceMain.cpp; kept as an interface so the same body can be
/// hosted in a console process for debugging.
class IServiceBody {
public:
    virtual ~IServiceBody() = default;

    /// Called once before the service reports Running. Long initialisation is
    /// allowed: the host reports Start_Pending with a checkpoint while it runs.
    [[nodiscard]] virtual Status onStart() = 0;

    /// Blocks until stop() is requested. The host reports Running for the
    /// duration.
    virtual void run() = 0;

    /// Signals run() to return. Called from the SCM control handler, so it must
    /// be non-blocking and safe to call from another thread.
    virtual void requestStop() noexcept = 0;

    /// Unwinds all network state. Called after run() returns, and also from the
    /// shutdown handler, where only a few seconds are available.
    virtual void onStop() noexcept = 0;

    /// Machine is going to sleep - tunnels are torn down but the kill switch is
    /// held so nothing leaks between resume and reconnect.
    virtual void onSuspend() noexcept {}

    /// Machine resumed; reconnect anything that was connected.
    virtual void onResume() noexcept {}

    /// A user logged on/off. Used to re-advertise the pipe and to apply the
    /// per-user auto-connect profile.
    virtual void onSessionChange(u32 eventType, u32 sessionId) noexcept
    {
        (void)eventType;
        (void)sessionId;
    }
};

/// Runs `body` under the SCM. Returns only when the service has stopped.
[[nodiscard]] Status runAsService(std::shared_ptr<IServiceBody> body);

/// Runs `body` in the foreground with Ctrl+C mapped to requestStop(), for
/// debugging without installing anything.
[[nodiscard]] Status runAsConsole(std::shared_ptr<IServiceBody> body);

/// Service control operations, used by the installer and by `NovaVPNService.exe
/// --install`.
[[nodiscard]] Status installService(const std::string& executablePath);
[[nodiscard]] Status uninstallService();
[[nodiscard]] Status startService();
[[nodiscard]] Status stopService();
[[nodiscard]] Result<bool> isServiceInstalled();
[[nodiscard]] Result<bool> isServiceRunning();

/// True when the current process token is an elevated administrator.
[[nodiscard]] bool isProcessElevated() noexcept;

} // namespace nova::service
