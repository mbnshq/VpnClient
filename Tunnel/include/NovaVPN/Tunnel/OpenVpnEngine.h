// NovaVPN - Tunnel/OpenVpnEngine.h
// Factory for the OpenVPN3-backed protocol engine.
//
// The engine is built only when NOVAVPN_BUILD_OPENVPN_ENGINE is ON (it compiles
// OpenVPN3 Core, which needs the vcpkg dependency set). When the option is off,
// a stub factory is linked instead so the rest of the product builds and links
// unchanged; makeOpenVpnEngine() then returns a NotImplemented error and
// isOpenVpnEngineAvailable() returns false.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Tunnel/Engine.h>

namespace nova::tunnel {

/// Engine id under which the OpenVPN engine registers.
inline constexpr std::string_view kOpenVpnEngineId = "openvpn";

/// True when this build includes the OpenVPN engine.
[[nodiscard]] bool isOpenVpnEngineAvailable() noexcept;

/// Creates an OpenVPN engine instance, or NotImplemented when the engine was
/// not compiled into this build.
[[nodiscard]] Result<VpnEnginePtr> makeOpenVpnEngine();

/// Registers the OpenVPN engine as a built-in, if available. A no-op that
/// succeeds when the engine is not compiled in, so the service startup path is
/// identical either way.
[[nodiscard]] Status registerOpenVpnEngine(IMutableEngineRegistry& registry);

} // namespace nova::tunnel
