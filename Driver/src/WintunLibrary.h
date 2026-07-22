// NovaVPN - Driver/WintunLibrary.h (internal)
// Dynamically-bound entry points of wintun.dll.
//
// Wintun is loaded at runtime rather than import-linked so the service can
// start, report a precise DriverMissing/DriverVersion error and let the updater
// repair the install, instead of failing at the loader with a message the user
// cannot act on. The DLL is loaded only from the application directory and its
// Authenticode signature is verified before the first call.
#pragma once

#include <NovaVPN/Core/Result.h>

#include <Windows.h>
#include <wintun.h>

namespace nova::driver {

/// The Wintun function table, resolved once at load().
struct WintunApi {
    WINTUN_CREATE_ADAPTER_FUNC*             createAdapter = nullptr;
    WINTUN_OPEN_ADAPTER_FUNC*               openAdapter = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC*              closeAdapter = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC*           getAdapterLuid = nullptr;
    WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* getRunningDriverVersion = nullptr;
    WINTUN_DELETE_DRIVER_FUNC*              deleteDriver = nullptr;
    WINTUN_SET_LOGGER_FUNC*                 setLogger = nullptr;
    WINTUN_START_SESSION_FUNC*              startSession = nullptr;
    WINTUN_END_SESSION_FUNC*                endSession = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC*        getReadWaitEvent = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC*             receivePacket = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC*     releaseReceivePacket = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC*       allocateSendPacket = nullptr;
    WINTUN_SEND_PACKET_FUNC*                sendPacket = nullptr;
};

/// Loads wintun.dll from the application directory, verifies its signature and
/// resolves the function table. Idempotent: repeated calls return the same
/// module. The module is intentionally never freed - Wintun must outlive every
/// adapter, and the process exits soon after the last one closes.
[[nodiscard]] Result<const WintunApi*> loadWintun();

} // namespace nova::driver
