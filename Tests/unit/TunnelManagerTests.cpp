// The tunnel manager is exercised with a scripted fake engine, so state
// transitions, events and lifecycle are deterministic without a real server.
#include <NovaVPN/Core/EventBus.h>
#include <NovaVPN/Tunnel/Engine.h>
#include <NovaVPN/Tunnel/Tunnel.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <vector>

using namespace nova;
using namespace nova::tunnel;

namespace {

/// A fake engine that records its lifecycle and lets the test drive the host
/// callbacks - simulating what a real protocol engine would report.
class FakeEngine final : public IVpnEngine {
public:
    std::string_view engineId() const noexcept override { return "openvpn"; }
    std::string version() const override { return "fake"; }

    Status validate(const profiles::Profile& profile) const override
    {
        return profile.remotes.empty()
                   ? Status{ErrorCode::ProfileInvalid, "no remotes"}
                   : Status::ok();
    }

    Status start(EngineConfig config, EngineHost host, const CancellationToken&) override
    {
        m_host = std::move(host);
        m_started = true;
        // Drive straight to Connected with a session, as a real engine would on
        // a successful handshake.
        if (m_host.onStateChanged) {
            m_host.onStateChanged(ConnectionState::Connecting, Status::ok());
        }
        if (m_host.onSessionEstablished) {
            TunnelSessionInfo info;
            info.localAddress = net::IpRange::parse("10.8.0.2/32").value();
            m_host.onSessionEstablished(info);
        }
        if (m_host.onStateChanged) {
            m_host.onStateChanged(ConnectionState::Connected, Status::ok());
        }
        (void)config;
        return Status::ok();
    }

    Status stop() override
    {
        m_stopped = true;
        if (m_host.onStateChanged) {
            m_host.onStateChanged(ConnectionState::Disconnected, Status::ok());
        }
        return Status::ok();
    }

    Status sendPacket(std::span<const u8>) override { return Status::ok(); }
    Status provideCredential(ChallengeKind, SecureString) override { return Status::ok(); }
    Status renegotiate() override { return Status::ok(); }

    bool started() const { return m_started; }
    bool stopped() const { return m_stopped; }

private:
    EngineHost        m_host;
    std::atomic<bool> m_started{false};
    std::atomic<bool> m_stopped{false};
};

profiles::Profile sampleProfile(std::string name = "HK")
{
    profiles::Profile profile;
    profile.name = std::move(name);
    profile.id   = "profile-" + profile.name;
    profiles::RemoteEntry remote;
    remote.host = "hk1.example.net";
    remote.port = 1194;
    profile.remotes.push_back(remote);
    profile.authMethod                  = profiles::AuthMethod::Certificate;
    profile.certificates.caPem          = "ca";
    profile.certificates.certificatePem = "cert";
    return profile;
}

TunnelManagerDeps depsWith(std::shared_ptr<EventBus> bus,
                           std::shared_ptr<FakeEngine> engine = nullptr)
{
    auto registry =
        std::dynamic_pointer_cast<IMutableEngineRegistry>(makeEngineRegistry());
    auto sharedEngine = engine ? engine : std::make_shared<FakeEngine>();
    (void)registry->registerBuiltin("openvpn", [sharedEngine] { return sharedEngine; });

    TunnelManagerDeps deps;
    deps.engines = registry;
    deps.events  = bus;
    return deps;
}

} // namespace

TEST_CASE("a tunnel connects through the engine and reports Connected",
          "[tunnel][manager]")
{
    auto bus = EventBus::create();
    auto engine = std::make_shared<FakeEngine>();
    auto manager = makeTunnelManager(depsWith(bus, engine));

    std::vector<ConnectionState> states;
    auto sub = bus->subscribe<TunnelStateChanged>(
        [&states](const TunnelStateChanged& e) { states.push_back(e.current); });

    auto tunnel = manager->create(sampleProfile());
    REQUIRE(tunnel.isOk());

    REQUIRE(tunnel.value()->connect(ConnectCredentials{}).isOk());
    REQUIRE(engine->started());
    REQUIRE(tunnel.value()->state() == ConnectionState::Connected);
    REQUIRE(tunnel.value()->sessionInfo().has_value());

    // The state stream reached Connected.
    REQUIRE(std::find(states.begin(), states.end(), ConnectionState::Connected) != states.end());
}

TEST_CASE("disconnect stops the engine and clears the session", "[tunnel][manager]")
{
    auto bus = EventBus::create();
    auto engine = std::make_shared<FakeEngine>();
    auto manager = makeTunnelManager(depsWith(bus, engine));

    auto tunnel = manager->create(sampleProfile()).value();
    REQUIRE(tunnel->connect(ConnectCredentials{}).isOk());
    REQUIRE(tunnel->disconnect().isOk());

    REQUIRE(engine->stopped());
    REQUIRE(tunnel->state() == ConnectionState::Disconnected);
    REQUIRE_FALSE(tunnel->sessionInfo().has_value());
    REQUIRE(tunnel->uptime() == Seconds{0});
}

TEST_CASE("connecting an already-connected tunnel is refused", "[tunnel][manager]")
{
    auto bus = EventBus::create();
    auto manager = makeTunnelManager(depsWith(bus));
    auto tunnel = manager->create(sampleProfile()).value();

    REQUIRE(tunnel->connect(ConnectCredentials{}).isOk());
    REQUIRE(tunnel->connect(ConnectCredentials{}).code() == ErrorCode::InvalidState);
}

TEST_CASE("an invalid profile is refused at create", "[tunnel][manager]")
{
    auto bus = EventBus::create();
    auto manager = makeTunnelManager(depsWith(bus));

    profiles::Profile invalid = sampleProfile();
    invalid.remotes.clear();
    REQUIRE(manager->create(invalid).isError());
}

TEST_CASE("the concurrent tunnel limit is enforced", "[tunnel][manager]")
{
    auto bus = EventBus::create();
    auto deps = depsWith(bus);
    deps.maxConcurrentTunnels = 2;
    auto manager = makeTunnelManager(deps);

    REQUIRE(manager->create(sampleProfile("A")).isOk());
    REQUIRE(manager->create(sampleProfile("B")).isOk());
    const auto third = manager->create(sampleProfile("C"));
    REQUIRE(third.isError());
    REQUIRE(third.status().code() == ErrorCode::Unavailable);
}

TEST_CASE("the first tunnel becomes primary; destroy reassigns it",
          "[tunnel][manager]")
{
    auto bus = EventBus::create();
    auto manager = makeTunnelManager(depsWith(bus));

    auto a = manager->create(sampleProfile("A")).value();
    auto b = manager->create(sampleProfile("B")).value();

    REQUIRE(manager->primary().isOk());
    REQUIRE(manager->primary().value()->id() == a->id());

    REQUIRE(manager->setPrimary(b->id()).isOk());
    REQUIRE(manager->primary().value()->id() == b->id());

    // Destroying the primary reassigns primary to a remaining tunnel.
    REQUIRE(manager->destroy(b->id()).isOk());
    REQUIRE(manager->primary().value()->id() == a->id());

    // Destroying the last tunnel leaves no primary.
    REQUIRE(manager->destroy(a->id()).isOk());
    REQUIRE(manager->primary().isError());
}

TEST_CASE("find and all reflect the live tunnel set", "[tunnel][manager]")
{
    auto bus = EventBus::create();
    auto manager = makeTunnelManager(depsWith(bus));

    auto a = manager->create(sampleProfile("A")).value();
    REQUIRE(manager->all().size() == 1);
    REQUIRE(manager->find(a->id()).isOk());
    REQUIRE(manager->find("nope").isError());

    REQUIRE(manager->destroy(a->id()).isOk());
    REQUIRE(manager->all().empty());
}

TEST_CASE("session up/down hooks fire around the session", "[tunnel][manager]")
{
    auto bus = EventBus::create();
    auto deps = depsWith(bus);

    std::atomic<int> up{0};
    std::atomic<int> down{0};
    deps.onSessionUp   = [&up](const Id&, const TunnelSessionInfo&) { ++up; };
    deps.onSessionDown = [&down](const Id&) { ++down; };

    auto manager = makeTunnelManager(deps);
    auto tunnel = manager->create(sampleProfile()).value();

    REQUIRE(tunnel->connect(ConnectCredentials{}).isOk());
    REQUIRE(up.load() == 1);

    REQUIRE(tunnel->disconnect().isOk());
    REQUIRE(down.load() == 1);
}
