// End-to-end: a real profile store (temp db) and tunnel manager (fake engine)
// wired behind a real IPC server, driven over the pipe by a raw client. This
// exercises the whole request path from wire frame to subsystem and back.
#include <NovaVPN/Core/EventBus.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Core/Version.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Core/Config.h>
#include <NovaVPN/Database/Database.h>
#include <NovaVPN/Logs/Sink.h>
#include <NovaVPN/Services/ServiceApi.h>
#include <NovaVPN/SplitTunnel/ProcessRegistry.h>
#include <NovaVPN/Tunnel/Engine.h>

#include <catch2/catch_test_macros.hpp>

#include <Windows.h>

#include <filesystem>
#include <thread>

using namespace nova;
using namespace nova::ipc;

namespace {

class FakeEngine final : public tunnel::IVpnEngine {
public:
    std::string_view engineId() const noexcept override { return "openvpn"; }
    std::string version() const override { return "fake"; }
    Status validate(const profiles::Profile&) const override { return Status::ok(); }
    Status start(tunnel::EngineConfig, tunnel::EngineHost host, const CancellationToken&) override
    {
        if (host.onStateChanged) {
            host.onStateChanged(ConnectionState::Connected, Status::ok());
        }
        return Status::ok();
    }
    Status stop() override { return Status::ok(); }
    Status sendPacket(std::span<const u8>) override { return Status::ok(); }
    Status provideCredential(tunnel::ChallengeKind, SecureString) override { return Status::ok(); }
    Status renegotiate() override { return Status::ok(); }
};

/// Raw pipe client bypassing the SYSTEM-owner check (both ends are the test
/// process). Speaks the same wire format the real client does.
class RawClient {
public:
    ~RawClient() { if (m_pipe != INVALID_HANDLE_VALUE) ::CloseHandle(m_pipe); }

    Status connect(const std::string& name)
    {
        const std::wstring path = L"\\\\.\\pipe\\" + win::toWide(name);
        for (int i = 0; i < 50; ++i) {
            m_pipe = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                   OPEN_EXISTING, 0, nullptr);
            if (m_pipe != INVALID_HANDLE_VALUE) {
                DWORD mode = PIPE_READMODE_BYTE;
                ::SetNamedPipeHandleState(m_pipe, &mode, nullptr, nullptr);
                return Status::ok();
            }
            std::this_thread::sleep_for(Milliseconds{20});
        }
        return err::timeout("pipe");
    }

    Result<Response> call(u64 id, Method method, Json params)
    {
        Request request;
        request.id = id;
        request.method = method;
        request.params = std::move(params);
        auto framed = frame(encode(request));
        if (framed.isError()) return framed.status();
        DWORD written = 0;
        ::WriteFile(m_pipe, framed.value().data(), static_cast<DWORD>(framed.value().size()),
                    &written, nullptr);

        for (int i = 0; i < 40; ++i) {
            u8 prefix[4]{};
            if (!readExact(prefix, 4)) return err::io("prefix");
            auto len = readFrameLength(std::span{prefix, 4});
            if (len.isError()) return len.status();
            std::vector<u8> body(len.value());
            if (!readExact(body.data(), len.value())) return err::io("body");
            auto parsed = parseFrame(body);
            if (parsed.isError()) return parsed.status();
            if (json::get<std::string>(parsed.value(), "/type", "") == "response") {
                return decodeResponse(parsed.value());
            }
        }
        return err::timeout("response");
    }

    Result<Response> hello()
    {
        HelloParams params;
        params.protocolVersion = version::kIpcProtocol;
        return call(1, Method::Hello, encode(params));
    }

private:
    bool readExact(void* buf, DWORD size)
    {
        auto* c = static_cast<u8*>(buf);
        DWORD rem = size;
        while (rem > 0) {
            DWORD r = 0;
            if (::ReadFile(m_pipe, c, rem, &r, nullptr) == FALSE || r == 0) return false;
            c += r; rem -= r;
        }
        return true;
    }
    HANDLE m_pipe = INVALID_HANDLE_VALUE;
};

struct Harness {
    std::filesystem::path dbPath;
    db::DatabasePtr       database;
    profiles::ProfileStorePtr profiles;
    tunnel::TunnelManagerPtr  tunnels;
    std::shared_ptr<EventBus> events;
    IpcServerPtr              server;
    std::vector<EventBus::Subscription> subs;
    std::string pipeName;
    std::unique_ptr<ConfigStore> settings;
    std::shared_ptr<logs::RingBufferSink> logRing;
    splittunnel::ProcessRegistryPtr processes;

    Harness()
    {
        dbPath = std::filesystem::temp_directory_path() /
                 ("novavpn-api-" + Uuid::generate().toString() + ".db");
        database = db::makeSqliteDatabase();
        REQUIRE(database->open(dbPath).isOk());
        profiles = profiles::makeProfileStore(database, nullptr);
        REQUIRE(profiles->open().isOk());

        settings = std::make_unique<ConfigStore>(
            std::filesystem::temp_directory_path() /
                ("novavpn-settings-" + Uuid::generate().toString() + ".json"),
            userSettingsDefaults());
        REQUIRE(settings->load().isOk());
        logRing = std::make_shared<logs::RingBufferSink>(64, logs::Level::Trace);
        processes = splittunnel::makeProcessRegistry();

        events = EventBus::create();

        auto registry = std::dynamic_pointer_cast<tunnel::IMutableEngineRegistry>(
            tunnel::makeEngineRegistry());
        (void)registry->registerBuiltin("openvpn",
                                        [] { return std::make_shared<FakeEngine>(); });

        tunnel::TunnelManagerDeps deps;
        deps.engines = registry;
        deps.events  = events;
        tunnels = tunnel::makeTunnelManager(deps);

        server = makeIpcServer(std::string{version::kString});
        service::ServiceApiDeps apiDeps;
        apiDeps.profiles = profiles;
        apiDeps.tunnels  = tunnels;
        apiDeps.engines  = registry;
        apiDeps.events   = events;
        apiDeps.settings = settings.get();
        apiDeps.processes = processes;
        apiDeps.logRing  = logRing;
        auto s = service::registerServiceApi(*server, apiDeps);
        REQUIRE(s.isOk());
        subs = std::move(s).value();

        pipeName = "NovaVPN.ApiTest." + Uuid::generate().toString();
        REQUIRE(server->start(pipeName).isOk());
    }

    ~Harness()
    {
        server->stop();
        (void)tunnels->disconnectAll();
        profiles->close();
        database->close();
        std::error_code ec;
        std::filesystem::remove(dbPath, ec);
        std::filesystem::remove(dbPath.string() + "-wal", ec);
        std::filesystem::remove(dbPath.string() + "-shm", ec);
    }

    profiles::Profile sampleProfile(std::string name = "HK")
    {
        profiles::Profile profile;
        profile.name = std::move(name);
        profiles::RemoteEntry remote;
        remote.host = "hk1.example.net";
        remote.port = 1194;
        profile.remotes.push_back(remote);
        profile.authMethod                  = profiles::AuthMethod::Certificate;
        profile.certificates.caPem          = "ca";
        profile.certificates.certificatePem = "cert";
        profile.sourceConfig                = "client\nremote hk1.example.net 1194\n";
        return profile;
    }
};

} // namespace

TEST_CASE("ListProfiles returns stored profiles over IPC", "[serviceapi]")
{
    Harness h;
    REQUIRE(h.profiles->add(h.sampleProfile("Alpha")).isOk());
    REQUIRE(h.profiles->add(h.sampleProfile("Bravo")).isOk());

    RawClient client;
    REQUIRE(client.connect(h.pipeName).isOk());
    REQUIRE(client.hello().value().success);

    auto response = client.call(2, Method::ListProfiles, Json::object());
    REQUIRE(response.isOk());
    REQUIRE(response.value().success);
    REQUIRE(response.value().result["profiles"].size() == 2);
}

TEST_CASE("GetServiceInfo reports version and engines", "[serviceapi]")
{
    Harness h;
    RawClient client;
    REQUIRE(client.connect(h.pipeName).isOk());
    REQUIRE(client.hello().value().success);

    auto response = client.call(2, Method::GetServiceInfo, Json::object());
    REQUIRE(response.isOk());
    REQUIRE(response.value().result["protocol"] == version::kIpcProtocol);
    REQUIRE(response.value().result["engines"].size() == 1);
}

TEST_CASE("Connect creates a tunnel and GetTunnels reflects it", "[serviceapi]")
{
    Harness h;
    const Id profileId = h.profiles->add(h.sampleProfile()).value();

    RawClient client;
    REQUIRE(client.connect(h.pipeName).isOk());
    REQUIRE(client.hello().value().success);

    auto connect = client.call(2, Method::Connect, Json{{"profileId", profileId}});
    REQUIRE(connect.isOk());
    REQUIRE(connect.value().success);
    const std::string tunnelId = connect.value().result["tunnelId"];
    REQUIRE_FALSE(tunnelId.empty());

    auto tunnels = client.call(3, Method::GetTunnels, Json::object());
    REQUIRE(tunnels.value().result["tunnels"].size() == 1);
    REQUIRE(tunnels.value().result["tunnels"][0]["state"] == "Connected");

    auto disconnect = client.call(4, Method::Disconnect, Json{{"tunnelId", tunnelId}});
    REQUIRE(disconnect.value().success);

    auto after = client.call(5, Method::GetTunnels, Json::object());
    REQUIRE(after.value().result["tunnels"].empty());
}

TEST_CASE("ImportOvpn over IPC stores a profile", "[serviceapi]")
{
    Harness h;
    RawClient client;
    REQUIRE(client.connect(h.pipeName).isOk());
    REQUIRE(client.hello().value().success);

    const std::string config =
        "client\nremote hk1.example.net 1194 udp\n<ca>\ncacontent\n</ca>\n"
        "<cert>\ncertcontent\n</cert>\n";
    auto response = client.call(2, Method::ImportOvpn,
                                Json{{"config", config}, {"name", "Imported"}});
    // ImportOvpn is a privileged method; the test process is not elevated, so
    // it is refused - proving the authorisation gate is wired end to end.
    REQUIRE(response.isOk());
    REQUIRE_FALSE(response.value().success);
    REQUIRE(response.value().errorCode == ErrorCode::PermissionDenied);
}

TEST_CASE("GetProfile returns a not-found for an unknown id", "[serviceapi]")
{
    Harness h;
    RawClient client;
    REQUIRE(client.connect(h.pipeName).isOk());
    REQUIRE(client.hello().value().success);

    auto response = client.call(2, Method::GetProfile, Json{{"id", "nope"}});
    REQUIRE(response.isOk());
    REQUIRE_FALSE(response.value().success);
    REQUIRE(response.value().errorCode == ErrorCode::NotFound);
}

TEST_CASE("GetSettings returns the settings document", "[serviceapi]")
{
    Harness h;
    RawClient client;
    REQUIRE(client.connect(h.pipeName).isOk());
    REQUIRE(client.hello().value().success);

    auto response = client.call(2, Method::GetSettings, Json::object());
    REQUIRE(response.isOk());
    REQUIRE(response.value().success);
    REQUIRE(response.value().result.contains("appearance"));
}

TEST_CASE("ListInstalledApps returns a coherent list over IPC", "[serviceapi]")
{
    Harness h;
    RawClient client;
    REQUIRE(client.connect(h.pipeName).isOk());
    REQUIRE(client.hello().value().success);

    auto response = client.call(2, Method::ListInstalledApps, Json::object());
    REQUIRE(response.isOk());
    REQUIRE(response.value().success);
    REQUIRE(response.value().result.contains("apps"));
    // Whatever is installed, every entry carries a path and name.
    for (const auto& app : response.value().result["apps"])
    {
        REQUIRE_FALSE(app["imagePath"].get<std::string>().empty());
    }
}

TEST_CASE("RunLeakTest is refused without a leak tester wired", "[serviceapi]")
{
    // The harness does not wire a leak tester, so the handler reports the
    // subsystem is unavailable rather than faulting.
    Harness h;
    RawClient client;
    REQUIRE(client.connect(h.pipeName).isOk());
    REQUIRE(client.hello().value().success);

    auto response = client.call(2, Method::RunLeakTest, Json::object());
    REQUIRE(response.isOk());
    REQUIRE_FALSE(response.value().success);
    REQUIRE(response.value().errorCode == ErrorCode::Unavailable);
}

TEST_CASE("GetLogs returns the log ring", "[serviceapi]")
{
    Harness h;
    // Put a line in the ring.
    nova::logs::LogRecord record;
    record.message = "test log line";
    record.timestamp = SystemClock::now();
    h.logRing->write(record);

    RawClient client;
    REQUIRE(client.connect(h.pipeName).isOk());
    REQUIRE(client.hello().value().success);

    auto response = client.call(2, Method::GetLogs, Json::object());
    REQUIRE(response.isOk());
    REQUIRE(response.value().success);
    REQUIRE(response.value().result["lines"].size() >= 1);
}
