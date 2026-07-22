// Cross-subsystem integration: exercise real subsystems together along the
// paths the product actually takes, rather than one unit in isolation. No
// network or elevation required - these use the data layer, the routing/split
// policy and the tunnel manager with a fake engine.
#include <NovaVPN/Core/EventBus.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Database/Database.h>
#include <NovaVPN/Profiles/OvpnParser.h>
#include <NovaVPN/Profiles/ProfileStore.h>
#include <NovaVPN/Routing/RoutingRules.h>
#include <NovaVPN/SplitTunnel/SplitTunnelEngine.h>
#include <NovaVPN/Tunnel/Engine.h>
#include <NovaVPN/Tunnel/Tunnel.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>

using namespace nova;

namespace {

class FakeEngine final : public tunnel::IVpnEngine {
public:
    std::string_view engineId() const noexcept override { return "openvpn"; }
    std::string version() const override { return "fake"; }
    Status validate(const profiles::Profile&) const override { return Status::ok(); }
    Status start(tunnel::EngineConfig cfg, tunnel::EngineHost host,
                 const CancellationToken&) override
    {
        m_profileName = cfg.profile.name;
        if (host.onStateChanged) {
            host.onStateChanged(ConnectionState::Connected, Status::ok());
        }
        return Status::ok();
    }
    Status stop() override { return Status::ok(); }
    Status sendPacket(std::span<const u8>) override { return Status::ok(); }
    Status provideCredential(tunnel::ChallengeKind, SecureString) override { return Status::ok(); }
    Status renegotiate() override { return Status::ok(); }
    std::string m_profileName;
};

struct DbScope {
    std::filesystem::path path;
    db::DatabasePtr database;
    DbScope()
        : path(std::filesystem::temp_directory_path() /
               ("novavpn-int-" + Uuid::generate().toString() + ".db"))
    {
        database = db::makeSqliteDatabase();
        REQUIRE(database->open(path).isOk());
    }
    ~DbScope()
    {
        database->close();
        std::error_code ec;
        std::filesystem::remove(path, ec);
        std::filesystem::remove(path.string() + "-wal", ec);
        std::filesystem::remove(path.string() + "-shm", ec);
    }
};

constexpr const char* kOvpn = R"(client
dev tun
proto udp
remote hk1.example.net 1194 udp
cipher AES-256-GCM
<ca>
-----BEGIN CERTIFICATE-----
MIIBfakeca
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIICfakecert
-----END CERTIFICATE-----
</cert>
)";

} // namespace

TEST_CASE("import a .ovpn, store it, then connect it through the manager",
          "[integration]")
{
    DbScope db;
    auto store = profiles::makeProfileStore(db.database, nullptr);
    REQUIRE(store->open().isOk());

    // 1. Import the config (the parser + store path).
    auto report = store->importOvpnText(kOvpn, "Hong Kong");
    REQUIRE(report.isOk());
    const Id profileId = report.value().profile.id;

    // 2. It is now retrievable with its remote intact.
    auto stored = store->get(profileId);
    REQUIRE(stored.isOk());
    REQUIRE(stored.value().remotes.size() == 1);
    REQUIRE(stored.value().remotes[0].host == "hk1.example.net");

    // 3. Connect it through the tunnel manager over a fake engine.
    auto bus = EventBus::create();
    auto registry = std::dynamic_pointer_cast<tunnel::IMutableEngineRegistry>(
        tunnel::makeEngineRegistry());
    auto engine = std::make_shared<FakeEngine>();
    (void)registry->registerBuiltin("openvpn", [engine] { return engine; });

    tunnel::TunnelManagerDeps deps;
    deps.engines = registry;
    deps.events = bus;
    auto manager = tunnel::makeTunnelManager(deps);

    std::vector<ConnectionState> observed;
    auto sub = bus->subscribe<tunnel::TunnelStateChanged>(
        [&observed](const tunnel::TunnelStateChanged& e) { observed.push_back(e.current); });

    auto tunnel = manager->create(stored.value());
    REQUIRE(tunnel.isOk());
    REQUIRE(tunnel.value()->connect(tunnel::ConnectCredentials{}).isOk());

    // 4. The whole chain worked: the engine saw our profile, the tunnel is
    //    Connected, and the state change was published on the bus.
    REQUIRE(engine->m_profileName == "Hong Kong");
    REQUIRE(tunnel.value()->state() == ConnectionState::Connected);
    REQUIRE(std::find(observed.begin(), observed.end(), ConnectionState::Connected) !=
            observed.end());

    // 5. Record the connection back to the store (usage stats path).
    REQUIRE(store->recordConnection(profileId, 1000, 2000).isOk());
    REQUIRE(store->get(profileId).value().metadata.connectCount == 1);

    REQUIRE(manager->disconnectAll().isOk());
}

TEST_CASE("split-tunnel policy and routing agree on the same rules",
          "[integration]")
{
    // A split-tunnel config and a hand-built routing policy expressing the same
    // intent must classify identically - the two policy surfaces are consistent.
    splittunnel::SplitTunnelConfig config;
    config.mode = splittunnel::SplitMode::Include;
    splittunnel::AppBinding tiktok;
    tiktok.imagePath = "C:\\Apps\\TikTok\\studio.exe";
    tiktok.tunnelId = "hk";
    config.applications.push_back(tiktok);

    splittunnel::SplitTunnelClassifier classifier{config};

    routing::RoutingPolicy policy;
    policy.defaultDisposition = routing::Disposition::Direct;
    routing::ApplicationRule rule;
    rule.id = "tiktok";
    rule.executablePath = "C:\\Apps\\TikTok\\studio.exe";
    rule.disposition = routing::Disposition::Tunnel;
    rule.tunnelId = "hk";
    policy.applicationRules.push_back(rule);
    routing::PolicyEvaluator evaluator{policy};

    const auto viaSplit = classifier.classify("C:\\Apps\\TikTok\\studio.exe");
    const auto viaRouting = evaluator.evaluateApplication("C:\\Apps\\TikTok\\studio.exe");

    REQUIRE(viaSplit.disposition == viaRouting.disposition);
    REQUIRE(viaSplit.tunnelId == viaRouting.tunnelId);
    REQUIRE(viaSplit.disposition == routing::Disposition::Tunnel);

    // And an unlisted app is direct on both.
    REQUIRE(classifier.classify("C:\\chrome.exe").disposition == routing::Disposition::Direct);
    REQUIRE(evaluator.evaluateApplication("C:\\chrome.exe").disposition ==
            routing::Disposition::Direct);
}

TEST_CASE("the database survives a reopen with data intact", "[integration]")
{
    const auto path = std::filesystem::temp_directory_path() /
                      ("novavpn-reopen-" + Uuid::generate().toString() + ".db");
    const Id id = Uuid::generate().toString();

    {
        auto db2 = db::makeSqliteDatabase();
        REQUIRE(db2->open(path).isOk());
        auto store = profiles::makeProfileStore(db2, nullptr);
        REQUIRE(store->open().isOk());

        profiles::Profile profile;
        profile.id = id;
        profile.name = "Persistent";
        profiles::RemoteEntry remote;
        remote.host = "hk1.example.net";
        remote.port = 1194;
        profile.remotes.push_back(remote);
        profile.certificates.caPem = "ca";
        profile.authMethod = profiles::AuthMethod::Certificate;
        profile.certificates.certificatePem = "cert";
        REQUIRE(store->add(profile).isOk());
        db2->close();
    }

    // Reopen a fresh database handle over the same file.
    auto reopened = db::makeSqliteDatabase();
    REQUIRE(reopened->open(path).isOk());
    auto store = profiles::makeProfileStore(reopened, nullptr);
    REQUIRE(store->open().isOk());
    REQUIRE(store->getByName("Persistent").isOk());
    reopened->close();

    std::error_code ec;
    std::filesystem::remove(path, ec);
    std::filesystem::remove(path.string() + "-wal", ec);
    std::filesystem::remove(path.string() + "-shm", ec);
}
