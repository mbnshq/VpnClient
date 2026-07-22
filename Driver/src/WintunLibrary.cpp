#include "WintunLibrary.h"

#include <NovaVPN/Core/Paths.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Logger.h>

#include <Windows.h>
#include <wintrust.h>
#include <softpub.h> // WINTRUST_ACTION_GENERIC_VERIFY_V2

#include <mutex>
#include <type_traits>

#pragma comment(lib, "wintrust.lib")

using nova::logs::Channel;

namespace nova::driver {
namespace {

std::once_flag g_loadOnce;
WintunApi      g_api{};
Status         g_loadStatus{ErrorCode::DriverMissing, "wintun not loaded"};
HMODULE        g_module = nullptr;

/// Bridges Wintun's own log callback into the NovaVPN logger.
VOID CALLBACK wintunLog(WINTUN_LOGGER_LEVEL level, DWORD64 /*timestamp*/, LPCWSTR message)
{
    const std::string text = win::toUtf8(message != nullptr ? message : L"");
    switch (level) {
    case WINTUN_LOG_INFO:
        NOVA_LOG_DEBUG(Channel::Driver, "wintun").field("msg", text);
        break;
    case WINTUN_LOG_WARN:
        NOVA_LOG_WARN(Channel::Driver, "wintun").field("msg", text);
        break;
    case WINTUN_LOG_ERR:
        NOVA_LOG_ERROR(Channel::Driver, "wintun").field("msg", text);
        break;
    default:
        break;
    }
}

/// Verifies the file's embedded Authenticode signature chains to a trusted
/// root. This is what stops a wintun.dll planted next to the binary from being
/// loaded into the SYSTEM service.
Status verifyAuthenticode(const std::wstring& path)
{
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct       = sizeof(fileInfo);
    fileInfo.pcwszFilePath  = path.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData{};
    trustData.cbStruct            = sizeof(trustData);
    trustData.dwUIChoice          = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice       = WTD_CHOICE_FILE;
    trustData.pFile               = &fileInfo;
    trustData.dwStateAction       = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags         = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_NONE;

    const LONG result = ::WinVerifyTrust(nullptr, &action, &trustData);

    // Always close the state, whatever the verdict.
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(nullptr, &action, &trustData);

    if (result != ERROR_SUCCESS) {
        return Status{ErrorCode::SignatureInvalid,
                      "wintun.dll signature verification failed",
                      static_cast<u32>(result)};
    }
    return Status::ok();
}

Status doLoad()
{
    // The DLL must sit beside our executable; searching anywhere else would
    // reintroduce the planted-DLL risk the signature check guards against.
    auto directory = paths::executableDirectory();
    if (directory.isError()) {
        return directory.status();
    }
    const std::wstring dllPath = (directory.value() / L"wintun.dll").wstring();

    if (::GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return Status{ErrorCode::DriverMissing,
                      "wintun.dll is not present next to the executable"};
    }

    NOVA_RETURN_IF_ERROR(verifyAuthenticode(dllPath));

    HMODULE module = ::LoadLibraryExW(dllPath.c_str(), nullptr,
                                      LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                          LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module == nullptr) {
        return win::lastError("LoadLibraryEx(wintun.dll)");
    }

    const auto resolve = [module](auto& target, const char* name) -> bool {
        target = reinterpret_cast<std::remove_reference_t<decltype(target)>>(
            ::GetProcAddress(module, name));
        return target != nullptr;
    };

    const bool ok =
        resolve(g_api.createAdapter, "WintunCreateAdapter") &&
        resolve(g_api.openAdapter, "WintunOpenAdapter") &&
        resolve(g_api.closeAdapter, "WintunCloseAdapter") &&
        resolve(g_api.getAdapterLuid, "WintunGetAdapterLUID") &&
        resolve(g_api.getRunningDriverVersion, "WintunGetRunningDriverVersion") &&
        resolve(g_api.deleteDriver, "WintunDeleteDriver") &&
        resolve(g_api.setLogger, "WintunSetLogger") &&
        resolve(g_api.startSession, "WintunStartSession") &&
        resolve(g_api.endSession, "WintunEndSession") &&
        resolve(g_api.getReadWaitEvent, "WintunGetReadWaitEvent") &&
        resolve(g_api.receivePacket, "WintunReceivePacket") &&
        resolve(g_api.releaseReceivePacket, "WintunReleaseReceivePacket") &&
        resolve(g_api.allocateSendPacket, "WintunAllocateSendPacket") &&
        resolve(g_api.sendPacket, "WintunSendPacket");

    if (!ok) {
        ::FreeLibrary(module);
        g_api = WintunApi{};
        return Status{ErrorCode::DriverVersion,
                      "wintun.dll is missing an expected export (version mismatch?)"};
    }

    g_api.setLogger(wintunLog);
    g_module = module;

    NOVA_LOG_INFO(Channel::Driver, "wintun loaded")
        .field("version", static_cast<u32>(g_api.getRunningDriverVersion()));
    return Status::ok();
}

} // namespace

Result<const WintunApi*> loadWintun()
{
    std::call_once(g_loadOnce, [] { g_loadStatus = doLoad(); });
    if (g_loadStatus.isError()) {
        return g_loadStatus;
    }
    return &g_api;
}

} // namespace nova::driver
