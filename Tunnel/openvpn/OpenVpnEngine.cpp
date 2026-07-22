// NovaVPN - Tunnel/openvpn/OpenVpnEngine.cpp
// The OpenVPN3-backed engine. Compiled only when NOVAVPN_BUILD_OPENVPN_ENGINE
// is ON, alongside OpenVPN3 Core's ClientAPI (ovpncli).
//
// This adapts OpenVPN3's openvpn::ClientAPI::OpenVPNClient to NovaVPN's
// IVpnEngine: our EngineConfig/EngineHost in, OpenVPN3 events and session facts
// out. Validation runs through OpenVPN3's own eval_config so a profile is judged
// by the same parser that will carry it. The connection runs on a dedicated
// worker thread because OpenVPNClient::connect() blocks until the session ends.
//
// Warning hygiene: this translation unit is intentionally kept free of the
// strict first-party warning flags - it includes the OpenVPN3 headers, which do
// not compile clean under /W4 /WX. The boundary is narrow: nothing here leaks
// OpenVPN3 types past the IVpnEngine interface.
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Tunnel/OpenVpnEngine.h>

// OpenVPN3 ClientAPI. The build target supplies the include path and the
// ASIO_STANDALONE/USE_OPENSSL/etc. defines.
#include <client/ovpncli.hpp>

#include <Windows.h>

#include <atomic>
#include <mutex>
#include <optional>
#include <thread>

using nova::logs::Channel;
namespace ovpn = openvpn::ClientAPI;

namespace nova::tunnel {
namespace {

/// Maps an OpenVPN3 event name to a NovaVPN connection state. Names are stable
/// parts of the OpenVPN3 client protocol.
std::optional<ConnectionState> mapEvent(const std::string& name)
{
    if (name == "RESOLVE") return ConnectionState::Resolving;
    if (name == "CONNECTING" || name == "WAIT" || name == "TCP_CONNECT")
        return ConnectionState::Connecting;
    if (name == "GET_CONFIG" || name == "ASSIGN_IP" || name == "ADD_ROUTES")
        return ConnectionState::Configuring;
    if (name == "AUTH") return ConnectionState::Authenticating;
    if (name == "CONNECTED") return ConnectionState::Connected;
    if (name == "RECONNECTING") return ConnectionState::Reconnecting;
    if (name == "DISCONNECTED" || name == "EXITING") return ConnectionState::Disconnected;
    if (name == "AUTH_FAILED" || name == "CERT_VERIFY_FAIL" || name == "TLS_VERSION_MIN" ||
        name == "CONNECTION_TIMEOUT" || name == "INACTIVE_TIMEOUT" || name == "PROXY_ERROR")
        return ConnectionState::Faulted;
    return std::nullopt;
}

/// Translates an OpenVPN3 fatal-event name into a NovaVPN Status.
Status statusForEvent(const std::string& name, const std::string& info)
{
    if (name == "AUTH_FAILED") {
        return Status{ErrorCode::AuthFailed, "authentication failed: " + info};
    }
    if (name == "CERT_VERIFY_FAIL") {
        return Status{ErrorCode::CertificateInvalid, "server certificate rejected: " + info};
    }
    if (name == "CONNECTION_TIMEOUT") {
        return Status{ErrorCode::Timeout, "connection timed out: " + info};
    }
    return Status{ErrorCode::HandshakeFailed, name + ": " + info};
}

/// The OpenVPN3 client subclass. All callbacks arrive on OpenVPN3's own
/// threads; each one marshals into the NovaVPN EngineHost without blocking.
class NovaOpenVpnClient final : public ovpn::OpenVPNClient {
public:
    NovaOpenVpnClient(Id tunnelId, EngineHost host)
        : m_tunnelId(std::move(tunnelId)), m_host(std::move(host))
    {
    }

    void event(const ovpn::Event& event) override
    {
        const std::string name{event.name};

        if (event.error) {
            const Status status = statusForEvent(name, std::string{event.info});
            if (m_host.onStateChanged) {
                m_host.onStateChanged(ConnectionState::Faulted, status);
            }
            return;
        }

        if (const auto state = mapEvent(name); state.has_value()) {
            if (*state == ConnectionState::Connected) {
                publishSession();
            }
            if (m_host.onStateChanged) {
                m_host.onStateChanged(*state, Status::ok());
            }
        }
    }

    void log(const ovpn::LogInfo& info) override
    {
        if (m_host.onLog) {
            // OpenVPN3 has already redacted its own sensitive fields.
            m_host.onLog(logs::Level::Debug, std::string{info.text});
        }
    }

    void acc_event(const ovpn::AppCustomControlMessageEvent&) override {}
    bool pause_on_connection_timeout() override { return false; }

    // NovaVPN performs its own PKI handling before the profile reaches the
    // engine, so external-PKI callbacks are not used.
    void external_pki_cert_request(ovpn::ExternalPKICertRequest& req) override
    {
        req.error        = true;
        req.errorText    = "external PKI is not used by NovaVPN";
        req.invalidAlias = true;
    }
    void external_pki_sign_request(ovpn::ExternalPKISignRequest& req) override
    {
        req.error     = true;
        req.errorText = "external PKI is not used by NovaVPN";
    }

private:
    void publishSession()
    {
        if (!m_host.onSessionEstablished) {
            return;
        }
        const ovpn::ConnectionInfo info = connection_info();
        if (!info.defined) {
            return;
        }

        TunnelSessionInfo session;
        session.connectedAt = SystemClock::now();
        if (auto vpnIp = net::IpAddress::parse(std::string{info.vpnIp4}); vpnIp.isOk()) {
            if (auto range = net::IpRange::make(vpnIp.value(), 32); range.isOk()) {
                session.localAddress = range.value();
            }
        }
        if (auto gw = net::IpAddress::parse(std::string{info.gw4}); gw.isOk()) {
            session.serverVirtualIp = gw.value();
        }
        // The remote we actually reached, for the dashboard.
        if (!info.serverIp.empty() && !info.serverPort.empty()) {
            if (auto ep = net::Endpoint::parse(std::string{info.serverIp} + ":" +
                                               std::string{info.serverPort});
                ep.isOk()) {
                session.remoteEndpoint = ep.value();
            }
        }
        session.peerCertificateSubject = std::string{info.serverHost};
        m_host.onSessionEstablished(session);
    }

    Id         m_tunnelId;
    EngineHost m_host;
};

class OpenVpnEngine final : public IVpnEngine {
public:
    std::string_view engineId() const noexcept override { return kOpenVpnEngineId; }

    std::string version() const override
    {
        return "OpenVPN3 Core";
    }

    Status validate(const profiles::Profile& profile) const override
    {
        if (profile.sourceConfig.empty()) {
            return Status{ErrorCode::ProfileInvalid,
                          "profile has no OpenVPN configuration to validate"};
        }

        ovpn::Config config;
        config.content = profile.sourceConfig;

        // eval_config is OpenVPN3's own parser - the authority on whether the
        // config it will later run is well-formed. OpenVPNClientHelper is the
        // concrete entry point for it (OpenVPNClient itself is abstract).
        ovpn::OpenVPNClientHelper helper;
        const ovpn::EvalConfig eval = helper.eval_config(config);
        if (eval.error) {
            return Status{ErrorCode::ConfigInvalid,
                          "OpenVPN configuration rejected: " + std::string{eval.message}};
        }
        return Status::ok();
    }

    Status start(EngineConfig config, EngineHost host, const CancellationToken& token) override
    {
        std::lock_guard lock{m_mutex};
        if (m_worker.joinable()) {
            return err::invalidState("engine already started");
        }

        m_client = std::make_unique<NovaOpenVpnClient>(config.tunnelId, host);

        ovpn::Config ovpnConfig;
        ovpnConfig.content       = config.profile.sourceConfig;
        ovpnConfig.info          = true;
        ovpnConfig.tunPersist    = false;
        ovpnConfig.guiVersion    = "NovaVPN";
        ovpnConfig.connTimeout   = 60;

        const ovpn::EvalConfig eval = m_client->eval_config(ovpnConfig);
        if (eval.error) {
            m_client.reset();
            return Status{ErrorCode::ConfigInvalid,
                          "OpenVPN configuration rejected: " + std::string{eval.message}};
        }

        // Supply credentials when the profile carries them.
        if (!config.credentials.userName.empty() || !config.credentials.password.empty()) {
            ovpn::ProvideCreds creds;
            creds.username = config.credentials.userName;
            creds.password = std::string{config.credentials.password.view()};
            if (const ovpn::Status status = m_client->provide_creds(creds); status.error) {
                m_client.reset();
                return Status{ErrorCode::CredentialsMissing,
                              "OpenVPN rejected the credentials: " + std::string{status.message}};
            }
        }

        // connect() blocks until the session ends, so it runs on its own thread.
        // Cancellation from the token stops the client, unblocking connect().
        m_cancelReg = token.onCancelled([this] { requestStop(); });

        m_worker = std::thread([this, host] {
            ::SetThreadDescription(::GetCurrentThread(), L"NovaVPN.OpenVPN");
            const ovpn::Status status = m_client->connect();
            if (status.error && host.onStateChanged) {
                host.onStateChanged(
                    ConnectionState::Faulted,
                    Status{ErrorCode::HandshakeFailed,
                           "OpenVPN session ended: " + std::string{status.message}});
            } else if (host.onStateChanged) {
                host.onStateChanged(ConnectionState::Disconnected, Status::ok());
            }
        });
        return Status::ok();
    }

    Status stop() override
    {
        requestStop();

        std::thread worker;
        {
            std::lock_guard lock{m_mutex};
            worker = std::move(m_worker);
        }
        if (worker.joinable()) {
            worker.join();
        }

        std::lock_guard lock{m_mutex};
        m_client.reset();
        m_cancelReg.reset();
        return Status::ok();
    }

    Status sendPacket(std::span<const u8>) override
    {
        // OpenVPN3's ClientAPI owns its transport and tun in this configuration,
        // so packets do not flow through the engine interface.
        return Status::ok();
    }

    Status provideCredential(ChallengeKind, SecureString value) override
    {
        std::lock_guard lock{m_mutex};
        if (!m_client) {
            return err::invalidState("no active OpenVPN session");
        }
        ovpn::ProvideCreds creds;
        creds.response = std::string{value.view()};
        const ovpn::Status status = m_client->provide_creds(creds);
        return status.error
                   ? Status{ErrorCode::AuthFailed, std::string{status.message}}
                   : Status::ok();
    }

    Status renegotiate() override
    {
        std::lock_guard lock{m_mutex};
        if (!m_client) {
            return err::invalidState("no active OpenVPN session");
        }
        m_client->reconnect(0);
        return Status::ok();
    }

private:
    void requestStop()
    {
        std::lock_guard lock{m_mutex};
        if (m_client) {
            m_client->stop();
        }
    }

    mutable std::mutex                 m_mutex;
    std::unique_ptr<NovaOpenVpnClient> m_client;
    std::thread                        m_worker;
    CancellationToken::Registration    m_cancelReg;
};

} // namespace

bool isOpenVpnEngineAvailable() noexcept
{
    return true;
}

Result<VpnEnginePtr> makeOpenVpnEngine()
{
    return VpnEnginePtr{std::make_shared<OpenVpnEngine>()};
}

Status registerOpenVpnEngine(IMutableEngineRegistry& registry)
{
    return registry.registerBuiltin(std::string{kOpenVpnEngineId},
                                    [] { return std::make_shared<OpenVpnEngine>(); });
}

} // namespace nova::tunnel
