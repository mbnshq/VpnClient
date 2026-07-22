#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Tunnel/Engine.h>
#include <NovaVPN/Tunnel/Tunnel.h>

#include <algorithm>
#include <mutex>
#include <unordered_map>

using nova::logs::Channel;

namespace nova::tunnel {
namespace {

/// One tunnel: owns an engine instance and drives it through the connection
/// lifecycle, translating engine callbacks into NovaVPN state and statistics.
class Tunnel final : public ITunnel, public std::enable_shared_from_this<Tunnel> {
public:
    Tunnel(Id id, profiles::Profile profile, TunnelManagerDeps deps)
        : m_id(std::move(id)), m_profile(std::move(profile)), m_deps(std::move(deps))
    {
    }

    ~Tunnel() override
    {
        (void)disconnect();
    }

    const Id& id() const noexcept override { return m_id; }
    const Id& profileId() const noexcept override { return m_profile.id; }

    ConnectionState state() const noexcept override
    {
        return m_state.load(std::memory_order_acquire);
    }

    std::optional<TunnelSessionInfo> sessionInfo() const override
    {
        std::lock_guard lock{m_mutex};
        return m_session;
    }

    net::StatisticsSample statistics() const override
    {
        std::lock_guard lock{m_mutex};
        return m_statistics;
    }

    Seconds uptime() const override
    {
        if (state() != ConnectionState::Connected) {
            return Seconds{0};
        }
        std::lock_guard lock{m_mutex};
        return std::chrono::duration_cast<Seconds>(SteadyClock::now() - m_connectedAt);
    }

    Status connect(ConnectCredentials credentials) override
    {
        std::shared_ptr<IVpnEngine> engine;
        EngineConfig config;
        CancellationToken token;

        // The engine may call the host callbacks synchronously from start(),
        // and those callbacks take m_mutex - so all engine calls happen OUTSIDE
        // the lock. The lock only guards the setup of shared state here.
        {
            std::lock_guard lock{m_mutex};
            if (isTransitional(m_state.load()) ||
                m_state.load() == ConnectionState::Connected) {
                return err::invalidState("tunnel is already connecting or connected");
            }
            if (!m_deps.engines) {
                return err::invalidState("no engine registry configured");
            }

            auto created = m_deps.engines->create(engineIdForProfile());
            if (created.isError()) {
                return std::move(created).status().withContext("creating engine for " + m_id);
            }
            m_engine = created.value();
            engine   = m_engine;

            // validate() does not call back into the host, so it is safe here.
            NOVA_RETURN_IF_ERROR(engine->validate(m_profile).withContext("validating profile"));

            m_cancelSource = std::make_unique<CancellationSource>();
            m_credentials  = std::move(credentials);
            token          = m_cancelSource->token();

            config.tunnelId             = m_id;
            config.profile              = m_profile;
            config.credentials.userName = m_credentials.userName;
            config.credentials.password = m_credentials.password.clone();
            config.credentials.totpCode = m_credentials.totpCode.clone();
        }

        transition(ConnectionState::Connecting, Status::ok(), 1);

        EngineHost host = makeHost();
        if (const Status status = engine->start(std::move(config), std::move(host), token);
            status.isError()) {
            transition(ConnectionState::Faulted, status, 1);
            return status;
        }
        return Status::ok();
    }

    Status disconnect() override
    {
        std::shared_ptr<IVpnEngine> engine;
        {
            std::lock_guard lock{m_mutex};
            if (m_state.load() == ConnectionState::Disconnected) {
                return Status::ok();
            }
            transition(ConnectionState::Disconnecting, Status::ok(), 0);
            if (m_cancelSource) {
                m_cancelSource->cancel();
            }
            engine = m_engine;
        }

        if (engine) {
            (void)engine->stop();
        }

        {
            std::lock_guard lock{m_mutex};
            releaseSessionLocked();
            m_engine.reset();
            transition(ConnectionState::Disconnected, Status::ok(), 0);
        }
        return Status::ok();
    }

    Status reconnect() override
    {
        std::shared_ptr<IVpnEngine> engine;
        {
            std::lock_guard lock{m_mutex};
            engine = m_engine;
        }
        if (!engine) {
            return err::invalidState("tunnel is not connected");
        }
        transition(ConnectionState::Reconnecting, Status::ok(), 0);
        return engine->renegotiate();
    }

    Status answerChallenge(ChallengeKind kind, SecureString answer) override
    {
        std::shared_ptr<IVpnEngine> engine;
        {
            std::lock_guard lock{m_mutex};
            engine = m_engine;
        }
        if (!engine) {
            return err::invalidState("no active session to answer");
        }
        return engine->provideCredential(kind, std::move(answer));
    }

private:
    std::string_view engineIdForProfile() const
    {
        return m_profile.engine == profiles::EngineKind::OpenVpn
                   ? std::string_view{"openvpn"}
                   : std::string_view{m_profile.engineId};
    }

    EngineHost makeHost()
    {
        auto self = weak_from_this();

        EngineHost host;
        host.onStateChanged = [self](ConnectionState state, const Status& reason) {
            if (auto tunnel = self.lock()) {
                tunnel->onEngineState(state, reason);
            }
        };
        host.onSessionEstablished = [self](const TunnelSessionInfo& info) {
            if (auto tunnel = self.lock()) {
                tunnel->onSessionEstablished(info);
            }
        };
        host.onCounters = [self](const net::TrafficCounters& counters) {
            if (auto tunnel = self.lock()) {
                tunnel->onCounters(counters);
            }
        };
        host.onLog = [self](logs::Level level, const std::string& text) {
            (void)level;
            if (auto tunnel = self.lock()) {
                NOVA_LOG_DEBUG(Channel::Engine, "engine").field("tunnel", tunnel->m_id)
                    .field("msg", text);
            }
        };
        host.onChallenge = [self](const AuthChallenge& challenge) {
            if (auto tunnel = self.lock()) {
                tunnel->publishChallenge(challenge);
            }
        };
        return host;
    }

    void onEngineState(ConnectionState state, const Status& reason)
    {
        std::lock_guard lock{m_mutex};
        if (state == ConnectionState::Connected) {
            m_connectedAt = SteadyClock::now();
        }
        if (state == ConnectionState::Disconnected || state == ConnectionState::Faulted) {
            releaseSessionLocked();
        }
        transition(state, reason, 0);
    }

    void onSessionEstablished(const TunnelSessionInfo& info)
    {
        {
            std::lock_guard lock{m_mutex};
            m_session = info;
        }
        if (m_deps.onSessionUp) {
            m_deps.onSessionUp(m_id, info);
        }
        NOVA_LOG_INFO(Channel::Tunnel, "session established")
            .field("tunnel", m_id)
            .field("localAddress", info.localAddress.toString());
    }

    void onCounters(const net::TrafficCounters& counters)
    {
        net::StatisticsSample sample;
        {
            std::lock_guard lock{m_mutex};
            sample.timestamp = SystemClock::now();
            sample.counters  = counters;
            sample.rates     = net::computeRates(m_statistics.counters, counters,
                                             std::chrono::duration_cast<Milliseconds>(
                                                 SteadyClock::now() - m_lastSampleAt));
            m_lastSampleAt   = SteadyClock::now();
            m_statistics     = sample;
        }
        if (m_deps.events) {
            m_deps.events->publish(net::StatisticsTick{m_id, sample});
        }
    }

    void publishChallenge(const AuthChallenge& challenge)
    {
        if (m_deps.events) {
            m_deps.events->publish(challenge);
        }
    }

    /// Caller holds m_mutex.
    void releaseSessionLocked()
    {
        if (m_session.has_value()) {
            if (m_deps.onSessionDown) {
                m_deps.onSessionDown(m_id);
            }
            m_session.reset();
        }
    }

    /// Caller holds m_mutex (except the atomic store, which is safe anywhere).
    void transition(ConnectionState next, const Status& reason, u32 attempt)
    {
        const ConnectionState previous = m_state.exchange(next, std::memory_order_acq_rel);
        if (previous == next) {
            return;
        }

        NOVA_LOG_INFO(Channel::Tunnel, "state")
            .field("tunnel", m_id)
            .field("from", std::string{nova::toString(previous)})
            .field("to", std::string{nova::toString(next)});

        if (m_deps.events) {
            TunnelStateChanged event;
            event.tunnelId  = m_id;
            event.profileId = m_profile.id;
            event.previous  = previous;
            event.current   = next;
            event.reason    = reason;
            event.attempt   = attempt;
            m_deps.events->publish(event);
        }
    }

    Id                              m_id;
    profiles::Profile               m_profile;
    TunnelManagerDeps               m_deps;
    mutable std::mutex              m_mutex;
    std::atomic<ConnectionState>    m_state{ConnectionState::Disconnected};
    std::shared_ptr<IVpnEngine>     m_engine;
    std::unique_ptr<CancellationSource> m_cancelSource;
    ConnectCredentials              m_credentials;
    std::optional<TunnelSessionInfo> m_session;
    net::StatisticsSample           m_statistics;
    SteadyTime                      m_connectedAt{};
    SteadyTime                      m_lastSampleAt = SteadyClock::now();
};

class TunnelManager final : public ITunnelManager {
public:
    explicit TunnelManager(TunnelManagerDeps deps) : m_deps(std::move(deps)) {}

    ~TunnelManager() override
    {
        (void)disconnectAll();
    }

    Result<TunnelPtr> create(const profiles::Profile& profile) override
    {
        NOVA_RETURN_IF_ERROR(profile.validate());

        std::lock_guard lock{m_mutex};
        if (m_tunnels.size() >= m_deps.maxConcurrentTunnels) {
            return Status{ErrorCode::Unavailable,
                          "the concurrent tunnel limit (" +
                              std::to_string(m_deps.maxConcurrentTunnels) + ") is reached"};
        }

        const Id id = Uuid::generate().toString();
        auto tunnel = std::make_shared<Tunnel>(id, profile, m_deps);
        m_tunnels.emplace(id, tunnel);
        if (m_primary.empty()) {
            m_primary = id;
        }
        NOVA_LOG_INFO(Channel::Tunnel, "tunnel created")
            .field("tunnel", id)
            .field("profile", profile.name);
        return TunnelPtr{tunnel};
    }

    Result<TunnelPtr> find(const Id& tunnelId) const override
    {
        std::lock_guard lock{m_mutex};
        const auto it = m_tunnels.find(tunnelId);
        if (it == m_tunnels.end()) {
            return err::notFound("no tunnel with id " + tunnelId);
        }
        return TunnelPtr{it->second};
    }

    std::vector<TunnelPtr> all() const override
    {
        std::lock_guard lock{m_mutex};
        std::vector<TunnelPtr> out;
        out.reserve(m_tunnels.size());
        for (const auto& [id, tunnel] : m_tunnels) {
            out.push_back(tunnel);
        }
        return out;
    }

    Status destroy(const Id& tunnelId) override
    {
        TunnelPtr tunnel;
        {
            std::lock_guard lock{m_mutex};
            const auto it = m_tunnels.find(tunnelId);
            if (it == m_tunnels.end()) {
                return err::notFound("no tunnel with id " + tunnelId);
            }
            tunnel = it->second;
            m_tunnels.erase(it);
            if (m_primary == tunnelId) {
                m_primary = m_tunnels.empty() ? Id{} : m_tunnels.begin()->first;
            }
        }
        return tunnel->disconnect();
    }

    Status disconnectAll() override
    {
        std::vector<TunnelPtr> tunnels;
        {
            std::lock_guard lock{m_mutex};
            for (const auto& [id, tunnel] : m_tunnels) {
                tunnels.push_back(tunnel);
            }
        }
        Status first = Status::ok();
        for (const auto& tunnel : tunnels) {
            if (const Status status = tunnel->disconnect(); status.isError() && first.isOk()) {
                first = status;
            }
        }
        return first;
    }

    Result<TunnelPtr> primary() const override
    {
        std::lock_guard lock{m_mutex};
        if (m_primary.empty()) {
            return err::notFound("no primary tunnel");
        }
        const auto it = m_tunnels.find(m_primary);
        if (it == m_tunnels.end()) {
            return err::notFound("primary tunnel no longer exists");
        }
        return TunnelPtr{it->second};
    }

    Status setPrimary(const Id& tunnelId) override
    {
        std::lock_guard lock{m_mutex};
        if (m_tunnels.find(tunnelId) == m_tunnels.end()) {
            return err::notFound("no tunnel with id " + tunnelId);
        }
        m_primary = tunnelId;
        return Status::ok();
    }

private:
    TunnelManagerDeps m_deps;
    mutable std::mutex m_mutex;
    std::unordered_map<Id, std::shared_ptr<Tunnel>> m_tunnels;
    Id m_primary;
};

} // namespace

TunnelManagerPtr makeTunnelManager(TunnelManagerDeps deps)
{
    return std::make_shared<TunnelManager>(std::move(deps));
}

} // namespace nova::tunnel
