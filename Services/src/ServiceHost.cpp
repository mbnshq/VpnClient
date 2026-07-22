#include <NovaVPN/Core/Handle.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Services/ServiceHost.h>

#include <Windows.h>
#include <WtsApi32.h>

#include <atomic>
#include <mutex>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")

using nova::logs::Channel;

namespace nova::service {
namespace {

struct ScHandleTraits {
    using value_type = SC_HANDLE;
    static value_type invalid() noexcept { return nullptr; }
    static void close(value_type handle) noexcept { ::CloseServiceHandle(handle); }
};
using ScHandle = win::UniqueResource<ScHandleTraits>;

/// SCM interaction is inherently process-global, and so is the dispatcher's
/// callback contract: ServiceMain and the control handler receive no context
/// pointer. This block is the only global state in the service, and it is
/// written exactly once during startup.
struct DispatcherState {
    std::shared_ptr<IServiceBody> body;
    SERVICE_STATUS_HANDLE         statusHandle = nullptr;
    SERVICE_STATUS                status{};
    std::mutex                    statusMutex;
    std::atomic<bool>             consoleStopRequested{false};
};

DispatcherState& state()
{
    static DispatcherState instance;
    return instance;
}

void reportStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHintMs)
{
    auto& s = state();
    std::lock_guard lock{s.statusMutex};

    static DWORD checkPoint = 1;

    s.status.dwServiceType  = SERVICE_WIN32_OWN_PROCESS;
    s.status.dwCurrentState = currentState;
    s.status.dwWin32ExitCode = win32ExitCode;
    s.status.dwWaitHint      = waitHintMs;

    // Accept controls only once running; accepting them earlier invites the SCM
    // to send a stop before onStart() has built the state that onStop() unwinds.
    s.status.dwControlsAccepted =
        (currentState == SERVICE_START_PENDING)
            ? 0
            : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT |
               SERVICE_ACCEPT_SESSIONCHANGE);

    if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
        s.status.dwCheckPoint = 0;
    } else {
        s.status.dwCheckPoint = checkPoint++;
    }

    if (s.statusHandle != nullptr) {
        ::SetServiceStatus(s.statusHandle, &s.status);
    }
}

DWORD WINAPI controlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context)
{
    (void)context;
    auto& s = state();

    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        // 20 s hint: enough to tear down tunnels, routes and filters without the
        // SCM declaring us hung. Shutdown gives us less in practice, which is
        // why teardown is ordered so that leak-critical work happens first.
        reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 20000);
        if (s.body) {
            s.body->requestStop();
        }
        return NO_ERROR;

    case SERVICE_CONTROL_POWEREVENT:
        if (s.body != nullptr) {
            if (eventType == PBT_APMSUSPEND) {
                s.body->onSuspend();
            } else if (eventType == PBT_APMRESUMEAUTOMATIC ||
                       eventType == PBT_APMRESUMESUSPEND) {
                s.body->onResume();
            }
        }
        return NO_ERROR;

    case SERVICE_CONTROL_SESSIONCHANGE: {
        const auto* notification = static_cast<const WTSSESSION_NOTIFICATION*>(eventData);
        if (s.body != nullptr && notification != nullptr) {
            s.body->onSessionChange(static_cast<u32>(eventType),
                                    static_cast<u32>(notification->dwSessionId));
        }
        return NO_ERROR;
    }

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI serviceMain(DWORD argc, LPWSTR* argv)
{
    (void)argc;
    (void)argv;

    auto& s = state();

    s.statusHandle = ::RegisterServiceCtrlHandlerExW(
        std::wstring{kServiceName.begin(), kServiceName.end()}.c_str(), controlHandler, nullptr);
    if (s.statusHandle == nullptr) {
        NOVA_LOG_FATAL(Channel::Service, "RegisterServiceCtrlHandlerEx failed")
            .status(win::lastError("RegisterServiceCtrlHandlerEx"));
        return;
    }

    reportStatus(SERVICE_START_PENDING, NO_ERROR, 30000);

    const Status started = s.body->onStart();
    if (started.isError()) {
        NOVA_LOG_FATAL(Channel::Service, "service start failed").status(started);
        logs::Logger::instance().flush();
        reportStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    reportStatus(SERVICE_RUNNING, NO_ERROR, 0);
    NOVA_LOG_INFO(Channel::Service, "service running");

    s.body->run();

    reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 20000);
    s.body->onStop();

    NOVA_LOG_INFO(Channel::Service, "service stopped");
    logs::Logger::instance().flush();
    reportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

BOOL WINAPI consoleHandler(DWORD signal)
{
    switch (signal) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT: {
        auto& s = state();
        s.consoleStopRequested.store(true, std::memory_order_release);
        if (s.body) {
            s.body->requestStop();
        }
        return TRUE;
    }
    default:
        return FALSE;
    }
}

Result<ScHandle> openManager(DWORD access)
{
    ScHandle manager{::OpenSCManagerW(nullptr, SERVICES_ACTIVE_DATABASE, access)};
    if (!manager) {
        return win::lastError("OpenSCManager");
    }
    return manager;
}

Result<ScHandle> openService(DWORD managerAccess, DWORD serviceAccess)
{
    NOVA_ASSIGN_OR_RETURN(auto manager, openManager(managerAccess));
    const std::wstring name{kServiceName.begin(), kServiceName.end()};
    ScHandle service{::OpenServiceW(manager.get(), name.c_str(), serviceAccess)};
    if (!service) {
        return win::lastError("OpenService");
    }
    return service;
}

} // namespace

Status runAsService(std::shared_ptr<IServiceBody> body)
{
    if (!body) {
        return err::invalidArgument("service body is null");
    }
    state().body = std::move(body);

    std::wstring name{kServiceName.begin(), kServiceName.end()};
    SERVICE_TABLE_ENTRYW table[] = {{name.data(), serviceMain}, {nullptr, nullptr}};

    if (::StartServiceCtrlDispatcherW(table) == FALSE) {
        return win::lastError("StartServiceCtrlDispatcher");
    }
    return Status::ok();
}

Status runAsConsole(std::shared_ptr<IServiceBody> body)
{
    if (!body) {
        return err::invalidArgument("service body is null");
    }

    auto& s = state();
    s.body = std::move(body);

    ::SetConsoleCtrlHandler(consoleHandler, TRUE);

    NOVA_RETURN_IF_ERROR(s.body->onStart());
    NOVA_LOG_INFO(Channel::Service, "running in console mode - press Ctrl+C to stop");

    s.body->run();
    s.body->onStop();

    ::SetConsoleCtrlHandler(consoleHandler, FALSE);
    logs::Logger::instance().flush();
    return Status::ok();
}

Status installService(const std::string& executablePath)
{
    NOVA_ASSIGN_OR_RETURN(auto manager, openManager(SC_MANAGER_CREATE_SERVICE));

    const std::wstring name        = win::toWide(std::string{kServiceName});
    const std::wstring displayName = win::toWide(std::string{kServiceDisplayName});
    // Quote the path: an unquoted path with spaces is the classic
    // unquoted-service-path privilege-escalation bug.
    const std::wstring binaryPath  = L"\"" + win::toWide(executablePath) + L"\"";

    ScHandle service{::CreateServiceW(
        manager.get(), name.c_str(), displayName.c_str(), SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binaryPath.c_str(),
        nullptr, nullptr,
        // Depend on the TCP/IP stack and the base filtering engine; without BFE
        // the kill switch cannot be programmed at all.
        L"Tcpip\0BFE\0", nullptr, nullptr)};

    if (!service) {
        const DWORD error = ::GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            return err::alreadyExists("the NovaVPN service is already installed");
        }
        return win::fromWin32(error, "CreateService");
    }

    std::wstring description = win::toWide(std::string{kServiceDescription});
    SERVICE_DESCRIPTIONW descriptionInfo{description.data()};
    ::ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION, &descriptionInfo);

    // Restart on failure: a crashed VPN service must come back, because the
    // kill switch it programmed is still in force.
    SC_ACTION actions[3]{};
    actions[0] = {SC_ACTION_RESTART, 5000};
    actions[1] = {SC_ACTION_RESTART, 15000};
    actions[2] = {SC_ACTION_RESTART, 60000};

    SERVICE_FAILURE_ACTIONSW failureActions{};
    failureActions.dwResetPeriod = 86400; // one day
    failureActions.cActions      = 3;
    failureActions.lpsaActions   = actions;
    ::ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions);

    SERVICE_FAILURE_ACTIONS_FLAG failureFlag{TRUE};
    ::ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failureFlag);

    return Status::ok();
}

Status uninstallService()
{
    auto service = openService(SC_MANAGER_CONNECT, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (service.isError()) {
        if (service.status().code() == ErrorCode::NotFound) {
            return Status::ok(); // already gone
        }
        return std::move(service).status();
    }

    SERVICE_STATUS status{};
    ::ControlService(service.value().get(), SERVICE_CONTROL_STOP, &status);

    if (::DeleteService(service.value().get()) == FALSE) {
        const DWORD error = ::GetLastError();
        if (error != ERROR_SERVICE_MARKED_FOR_DELETE) {
            return win::fromWin32(error, "DeleteService");
        }
    }
    return Status::ok();
}

Status startService()
{
    NOVA_ASSIGN_OR_RETURN(auto service, openService(SC_MANAGER_CONNECT,
                                                    SERVICE_START | SERVICE_QUERY_STATUS));

    if (::StartServiceW(service.get(), 0, nullptr) == FALSE) {
        const DWORD error = ::GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            return Status::ok();
        }
        return win::fromWin32(error, "StartService");
    }
    return Status::ok();
}

Status stopService()
{
    NOVA_ASSIGN_OR_RETURN(auto service,
                          openService(SC_MANAGER_CONNECT, SERVICE_STOP | SERVICE_QUERY_STATUS));

    SERVICE_STATUS status{};
    if (::ControlService(service.get(), SERVICE_CONTROL_STOP, &status) == FALSE) {
        const DWORD error = ::GetLastError();
        if (error == ERROR_SERVICE_NOT_ACTIVE) {
            return Status::ok();
        }
        return win::fromWin32(error, "ControlService(STOP)");
    }
    return Status::ok();
}

Result<bool> isServiceInstalled()
{
    auto service = openService(SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS);
    if (service.isError()) {
        if (service.status().code() == ErrorCode::NotFound) {
            return false;
        }
        return std::move(service).status();
    }
    return true;
}

Result<bool> isServiceRunning()
{
    auto service = openService(SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS);
    if (service.isError()) {
        if (service.status().code() == ErrorCode::NotFound) {
            return false;
        }
        return std::move(service).status();
    }

    SERVICE_STATUS_PROCESS process{};
    DWORD needed = 0;
    if (::QueryServiceStatusEx(service.value().get(), SC_STATUS_PROCESS_INFO,
                               reinterpret_cast<LPBYTE>(&process), sizeof(process),
                               &needed) == FALSE) {
        return win::lastError("QueryServiceStatusEx");
    }
    return process.dwCurrentState == SERVICE_RUNNING;
}

bool isProcessElevated() noexcept
{
    HANDLE rawToken = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &rawToken) == FALSE) {
        return false;
    }

    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    const BOOL ok = ::GetTokenInformation(rawToken, TokenElevation, &elevation,
                                          sizeof(elevation), &size);
    ::CloseHandle(rawToken);

    return ok != FALSE && elevation.TokenIsElevated != 0;
}

} // namespace nova::service
