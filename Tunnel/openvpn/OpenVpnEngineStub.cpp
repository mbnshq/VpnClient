// NovaVPN - Tunnel/openvpn/OpenVpnEngineStub.cpp
// Linked when NOVAVPN_BUILD_OPENVPN_ENGINE is OFF. Keeps the factory symbols
// defined so the service and tests build identically whether or not the engine
// was compiled in.
#include <NovaVPN/Tunnel/OpenVpnEngine.h>

namespace nova::tunnel {

bool isOpenVpnEngineAvailable() noexcept
{
    return false;
}

Result<VpnEnginePtr> makeOpenVpnEngine()
{
    return err::notImplemented(
        "this build does not include the OpenVPN engine "
        "(configure with -DNOVAVPN_BUILD_OPENVPN_ENGINE=ON and the vcpkg toolchain)");
}

Status registerOpenVpnEngine(IMutableEngineRegistry&)
{
    // No engine to register; startup treats this as success so the code path is
    // the same in both build configurations.
    return Status::ok();
}

} // namespace nova::tunnel
