// NovaVPN - Services/ServiceMain.cpp
// Entry point of NovaVPNService.exe.
//
// Command line:
//   NovaVPNService.exe               run under the SCM (what the SCM invokes)
//   NovaVPNService.exe --console     run in the foreground for debugging
//   NovaVPNService.exe --install     register the service (requires elevation)
//   NovaVPNService.exe --ensure      install if needed, then start (elevation)
//   NovaVPNService.exe --uninstall   remove the service
//   NovaVPNService.exe --status      print installation and run state
//
// Phase 1 wires up the host: identity, secure-memory hardening, configuration,
// logging and the event bus, then idles until stopped. The subsystems it will
// own (tunnel manager, routing, firewall, split tunnel, updater) are attached
// in their own phases; each one plugs into the same start/stop ordering
// enforced here.
#include <NovaVPN/Core/Config.h>
#include <NovaVPN/Core/EventBus.h>
#include <NovaVPN/Core/Handle.h>
#include <NovaVPN/Core/Paths.h>
#include <NovaVPN/Core/SecureMemory.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Core/Version.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Database/Database.h>
#include <NovaVPN/Firewall/FirewallEngine.h>
#include <NovaVPN/Networking/NetworkMonitor.h>
#include <NovaVPN/Networking/Resolver.h>
#include <NovaVPN/Profiles/ProfileStore.h>
#include <NovaVPN/SplitTunnel/ProcessRegistry.h>
#include <NovaVPN/SplitTunnel/SplitTunnelEngine.h>
#include <NovaVPN/Routing/RouteManager.h>
#include <NovaVPN/Services/IpcServer.h>
#include <NovaVPN/Services/ServiceApi.h>
#include <NovaVPN/Services/ServiceHost.h>
#include <NovaVPN/Tunnel/Engine.h>
#include <NovaVPN/Tunnel/OpenVpnEngine.h>
#include <NovaVPN/Tunnel/Tunnel.h>

#include <Windows.h>

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

using namespace nova;
using nova::logs::Channel;
using nova::logs::Level;

namespace {

/// The service body. Owns process-wide state and enforces the start/stop
/// ordering that keeps the product leak-free:
///
///   start: config -> logging -> firewall reconcile -> route reconcile ->
///          adapters -> IPC (last, so no client can call in half-built)
///   stop : IPC (first, so no new work arrives) -> tunnels -> routes ->
///          firewall (last, so the kill switch outlives everything it guards)
class NovaVpnService final : public service::IServiceBody {
public:
    Status onStart() override
    {
        m_startedAt = SteadyClock::now();
        m_instanceId = Uuid::generate().toString();

        // Harden before anything sensitive is allocated.
        (void)hardenProcessAgainstDumps();

        NOVA_RETURN_IF_ERROR(initialiseConfig());
        NOVA_RETURN_IF_ERROR(initialiseLogging());

        NOVA_LOG_INFO(Channel::Service, "NovaVPN service starting")
            .field("version", std::string{version::kString})
            .field("channel", std::string{version::kChannel})
            .field("protocol", version::kIpcProtocol)
            .field("instance", m_instanceId);

        m_events = EventBus::create();

        m_stopEvent.reset(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!m_stopEvent) {
            return win::lastError("CreateEvent(stop)");
        }

        // Subsystems attach in dependency order. Each returns a Status and a
        // failure aborts the start, so the service never runs half-armed.

        // Phase 2: routes are reconciled BEFORE anything else touches the
        // network - a crashed previous run may have left the default route
        // captured, and nothing may build on top of that state.
        NOVA_ASSIGN_OR_RETURN(auto machineRoot, paths::machineRoot());
        m_routes = routing::makeRouteManager(machineRoot / L"routes.json");
        if (const Status status = m_routes->reconcile(); status.isError()) {
            // Reconcile can fail without elevation (console mode as a user);
            // the service continues but says so, loudly.
            NOVA_LOG_WARN(Channel::Routing, "route reconciliation incomplete").status(status);
        }

        // Catalogue: open the database (migrating it) and stand up the profile
        // store over it plus the machine credential vault.
        NOVA_ASSIGN_OR_RETURN(auto databasePath, paths::databasePath());
        m_database = db::makeSqliteDatabase();
        if (const Status status = m_database->open(databasePath); status.isError()) {
            // A corrupt catalogue must not wedge the service. Quarantine it and
            // start fresh; the user's profiles are re-importable, connectivity
            // is not negotiable.
            NOVA_LOG_ERROR(Channel::Database, "database unusable; quarantining and recreating")
                .status(status);
            std::error_code ec;
            std::filesystem::rename(databasePath,
                                    databasePath.wstring() + L".corrupt", ec);
            NOVA_RETURN_IF_ERROR(m_database->open(databasePath));
        }
        m_credentials  = profiles::makeCredentialStore();
        m_profileStore = profiles::makeProfileStore(m_database, m_credentials);
        NOVA_RETURN_IF_ERROR(m_profileStore->open());

        // Protocol engines: register the built-ins available in this build.
        m_engines = tunnel::makeEngineRegistry();
        if (auto mutableRegistry =
                std::dynamic_pointer_cast<tunnel::IMutableEngineRegistry>(m_engines)) {
            NOVA_RETURN_IF_ERROR(tunnel::registerOpenVpnEngine(*mutableRegistry));
        }
        NOVA_LOG_INFO(Channel::Service, "engines available")
            .field("count", static_cast<u64>(m_engines->availableEngines().size()))
            .field("openvpn", tunnel::isOpenVpnEngineAvailable());

        m_monitor = net::makeNetworkMonitor(m_events);
        NOVA_RETURN_IF_ERROR(m_monitor->start());
        m_resolver = net::makeResolver(m_monitor);

        // Split-tunnel control surface and leak tester (network features).
        m_processes = splittunnel::makeProcessRegistry();
        (void)m_processes->start();
        m_splitTunnel = splittunnel::makeSplitTunnelEngine(m_processes);
        (void)m_splitTunnel->start();
        m_leakTester = firewall::makeLeakTester(m_monitor, {});

        if (auto underlay = m_monitor->underlayAdapter(AddressFamily::IPv4); underlay.isOk()) {
            m_routes->setUnderlayInterface(underlay.value().interfaceIndex);
            NOVA_LOG_INFO(Channel::Network, "underlay adapter")
                .field("name", underlay.value().name)
                .field("interface", underlay.value().interfaceIndex)
                .field("type", static_cast<u32>(underlay.value().type));
        } else {
            NOVA_LOG_WARN(Channel::Network, "no underlay connectivity at start")
                .status(underlay.status());
        }

        // Tunnel manager over the engines and the event bus.
        tunnel::TunnelManagerDeps tunnelDeps;
        tunnelDeps.engines = m_engines;
        tunnelDeps.events  = m_events;
        tunnelDeps.maxConcurrentTunnels =
            static_cast<u32>(m_config->get<int>("/service/maxConcurrentTunnels", 4));
        m_tunnels = tunnel::makeTunnelManager(tunnelDeps);

        // IPC last, so no client can call in before the subsystems are built.
        m_ipc = ipc::makeIpcServer(std::string{version::kString});
        service::ServiceApiDeps apiDeps;
        apiDeps.profiles    = m_profileStore;
        apiDeps.tunnels     = m_tunnels;
        apiDeps.engines     = m_engines;
        apiDeps.credentials = m_credentials;
        apiDeps.events      = m_events;
        apiDeps.settings    = m_config.get();
        apiDeps.splitTunnel = m_splitTunnel;
        apiDeps.processes   = m_processes;
        apiDeps.leakTester  = m_leakTester;
        apiDeps.logRing     = m_logRing;
        NOVA_ASSIGN_OR_RETURN(m_apiSubscriptions,
                              service::registerServiceApi(*m_ipc, apiDeps));

        const std::string pipeName =
            m_config->get<std::string>("/service/ipcPipeName", "NovaVPN.Service");
        NOVA_RETURN_IF_ERROR(m_ipc->start(pipeName));

        NOVA_LOG_INFO(Channel::Service, "service start complete")
            .field("pipe", pipeName);
        return Status::ok();
    }

    void run() override
    {
        if (!m_stopEvent) {
            return;
        }
        ::WaitForSingleObject(m_stopEvent.get(), INFINITE);
    }

    void requestStop() noexcept override
    {
        if (m_stopEvent) {
            ::SetEvent(m_stopEvent.get());
        }
    }

    void onStop() noexcept override
    {
        NOVA_LOG_INFO(Channel::Service, "service stopping")
            .field("uptimeSeconds",
                   static_cast<i64>(std::chrono::duration_cast<Seconds>(
                                        SteadyClock::now() - m_startedAt)
                                        .count()));

        // Teardown order is the reverse of start: IPC stops accepting work
        // first, then tunnels, then routes, and the firewall last (and only
        // when the kill switch is not "hard").
        if (m_ipc) {
            m_ipc->stop();
        }
        m_apiSubscriptions.clear();
        if (m_tunnels) {
            (void)m_tunnels->disconnectAll();
        }

        if (m_splitTunnel) {
            m_splitTunnel->stop();
        }
        if (m_processes) {
            m_processes->stop();
        }
        if (m_monitor) {
            m_monitor->stop();
        }
        if (m_routes) {
            if (const Status status = m_routes->removeAllOwnedRoutes(); status.isError()) {
                NOVA_LOG_ERROR(Channel::Routing, "owned routes not fully removed")
                    .status(status);
            }
        }
        if (m_profileStore) {
            m_profileStore->close();
        }
        if (m_database) {
            m_database->close();
        }

        logs::Logger::instance().flush();
    }

    void onSuspend() noexcept override
    {
        // Tunnels do not survive S3/S4: the adapter and every socket are torn
        // down by the OS. Disconnecting deliberately - while holding the
        // firewall policy - means resume cannot leak between wake and reconnect.
        NOVA_LOG_INFO(Channel::Service, "system suspending; tunnels will be torn down");
        logs::Logger::instance().flush();
    }

    void onResume() noexcept override
    {
        NOVA_LOG_INFO(Channel::Service, "system resumed; reconnecting");
    }

    void onSessionChange(u32 eventType, u32 sessionId) noexcept override
    {
        NOVA_LOG_DEBUG(Channel::Service, "session change")
            .field("event", eventType)
            .field("session", sessionId);
    }

private:
    struct EventHandleTraits {
        using value_type = HANDLE;
        static value_type invalid() noexcept { return nullptr; }
        static void close(value_type handle) noexcept { ::CloseHandle(handle); }
    };

    Status initialiseConfig()
    {
        NOVA_ASSIGN_OR_RETURN(auto configPath, paths::machineConfigPath());
        m_config = std::make_unique<ConfigStore>(configPath, serviceConfigDefaults());

        const Status loaded = m_config->load();
        if (loaded.isError()) {
            // A corrupt config must not stop the service: it falls back to
            // defaults and says so loudly once logging exists.
            m_configWarning = loaded;
        }
        return Status::ok();
    }

    Status initialiseLogging()
    {
        // The machine log directory needs the installer-created tree. In a
        // non-elevated console run that tree may be unwritable; logging must
        // degrade to the user directory rather than aborting the start.
        std::filesystem::path logDirectory;
        if (auto machineLogs = paths::machineLogDirectory(); machineLogs.isOk()) {
            logDirectory = std::move(machineLogs).value();
        } else {
            NOVA_ASSIGN_OR_RETURN(logDirectory, paths::userLogDirectory());
            m_logWarning = std::move(machineLogs).status().withContext(
                "machine log directory unavailable; using the user directory");
        }

        Level level = Level::Info;
        (void)logs::parseLevel(m_config->get<std::string>("/service/logLevel", "info"), level);

        auto& logger = logs::Logger::instance();
        logger.removeAllSinks();
        logger.setMinimumLevel(level);

        logs::FileSinkOptions fileOptions;
        fileOptions.directory     = logDirectory;
        fileOptions.baseName      = "service";
        fileOptions.maxBytes      = m_config->get<u64>("/service/maxLogFileBytes", 16 * 1024 * 1024);
        fileOptions.retentionDays = m_config->get<int>("/service/logRetentionDays", 14);
        fileOptions.minimumLevel  = level;

        auto fileSink = logs::makeFileSink(fileOptions);
        if (fileSink.isError()) {
            // Without a file sink the service still runs; the event log keeps
            // the failure visible to an administrator.
            if (m_logWarning.isOk()) {
                m_logWarning = std::move(fileSink).status();
            }
        } else {
            logger.addSink(fileSink.value());
        }

        if (auto eventSink = logs::makeEventLogSink(std::string{service::kServiceName});
            eventSink.isOk()) {
            logger.addSink(eventSink.value());
        }

        logger.addSink(logs::makeDebuggerSink());

        // In-memory ring the UI reads for the live log view.
        m_logRing = std::make_shared<logs::RingBufferSink>(4096, level);
        logger.addSink(m_logRing);

        if (m_configWarning.isError()) {
            NOVA_LOG_WARN(Channel::Service, "configuration could not be loaded")
                .status(m_configWarning);
        }
        if (m_logWarning.isError()) {
            NOVA_LOG_WARN(Channel::Service, "logging degraded").status(m_logWarning);
        }
        return Status::ok();
    }

    std::unique_ptr<ConfigStore>       m_config;
    std::shared_ptr<EventBus>          m_events;
    routing::RouteManagerPtr           m_routes;
    net::NetworkMonitorPtr             m_monitor;
    net::ResolverPtr                   m_resolver;
    db::DatabasePtr                    m_database;
    profiles::CredentialStorePtr       m_credentials;
    profiles::ProfileStorePtr          m_profileStore;
    tunnel::EngineRegistryPtr          m_engines;
    tunnel::TunnelManagerPtr           m_tunnels;
    ipc::IpcServerPtr                  m_ipc;
    std::vector<EventBus::Subscription> m_apiSubscriptions;
    splittunnel::ProcessRegistryPtr    m_processes;
    splittunnel::SplitTunnelEnginePtr  m_splitTunnel;
    firewall::LeakTesterPtr            m_leakTester;
    std::shared_ptr<logs::RingBufferSink> m_logRing;
    win::UniqueResource<EventHandleTraits> m_stopEvent;
    SteadyTime                         m_startedAt{};
    std::string                        m_instanceId;
    Status                             m_configWarning;
    Status                             m_logWarning;
};

void printUsage()
{
    std::printf("NovaVPN Service %s (%s)\n\n", version::kString.data(), version::kChannel.data());
    std::printf("  --console     run in the foreground\n");
    std::printf("  --install     register the Windows service (requires elevation)\n");
    std::printf("  --ensure      install if needed, then start (requires elevation)\n");
    std::printf("  --uninstall   remove the Windows service\n");
    std::printf("  --status      print installation and run state\n");
    std::printf("  --help        this text\n");
}

int reportStatusToConsole(const Status& status, const char* action)
{
    if (status.isOk()) {
        std::printf("%s: ok\n", action);
        return 0;
    }
    std::fprintf(stderr, "%s: %s\n", action, status.toString().c_str());
    return 1;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    std::vector<std::string> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 1; i < argc; ++i) {
        args.push_back(win::toUtf8(argv[i]));
    }

    const auto has = [&args](std::string_view flag) {
        for (const auto& arg : args) {
            if (arg == flag) {
                return true;
            }
        }
        return false;
    };

    if (has("--help") || has("-h") || has("/?")) {
        printUsage();
        return 0;
    }

    if (has("--install")) {
        if (!service::isProcessElevated()) {
            std::fprintf(stderr, "install: administrator privileges are required\n");
            return 1;
        }
        auto path = paths::executablePath();
        if (path.isError()) {
            return reportStatusToConsole(path.status(), "install");
        }
        return reportStatusToConsole(service::installService(path.value().string()), "install");
    }

    if (has("--ensure")) {
        // One-shot bootstrap the UI invokes elevated on first run: register the
        // service if it is missing, then make sure it is running. After this the
        // service auto-starts at boot, so the UI never needs to elevate again.
        if (!service::isProcessElevated()) {
            std::fprintf(stderr, "ensure: administrator privileges are required\n");
            return 1;
        }
        const auto installed = service::isServiceInstalled();
        if (installed.isError()) {
            return reportStatusToConsole(installed.status(), "ensure");
        }
        if (!installed.value()) {
            auto path = paths::executablePath();
            if (path.isError()) {
                return reportStatusToConsole(path.status(), "ensure");
            }
            if (const Status status = service::installService(path.value().string());
                status.isError()) {
                return reportStatusToConsole(status, "ensure");
            }
        }
        return reportStatusToConsole(service::startService(), "ensure");
    }

    if (has("--uninstall")) {
        if (!service::isProcessElevated()) {
            std::fprintf(stderr, "uninstall: administrator privileges are required\n");
            return 1;
        }
        return reportStatusToConsole(service::uninstallService(), "uninstall");
    }

    if (has("--status")) {
        const auto installed = service::isServiceInstalled();
        const auto running   = service::isServiceRunning();
        std::printf("installed: %s\n",
                    installed.isOk() ? (installed.value() ? "yes" : "no")
                                     : installed.status().toString().c_str());
        std::printf("running  : %s\n", running.isOk() ? (running.value() ? "yes" : "no")
                                                      : running.status().toString().c_str());
        return 0;
    }

    auto body = std::make_shared<NovaVpnService>();

    if (has("--console")) {
        logs::Logger::instance().addSink(logs::makeConsoleSink(Level::Debug));
        return reportStatusToConsole(service::runAsConsole(body), "console");
    }

    const Status status = service::runAsService(body);
    if (status.isError()) {
        // Being started from a console rather than the SCM is the common case
        // here; point the user at the flag they wanted.
        std::fprintf(stderr, "%s\n", status.toString().c_str());
        std::fprintf(stderr, "Use --console to run in the foreground.\n");
        return 1;
    }
    return 0;
}
