#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/Version.h>
#include <NovaVPN/Logs/LogRecord.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Networking/Statistics.h>
#include <NovaVPN/Services/ServiceApi.h>
#include <NovaVPN/Tunnel/Engine.h>

using nova::logs::Channel;
using namespace nova::ipc;

namespace nova::service {
namespace {

Json profileSummaryJson(const profiles::Profile& profile)
{
    // The list view never carries secrets - just what the UI renders per row.
    return Json{{"id", profile.id},
                {"name", profile.name},
                {"country", profile.metadata.country},
                {"city", profile.metadata.city},
                {"favorite", profile.metadata.favorite},
                {"tags", profile.metadata.tags},
                {"connectCount", profile.metadata.connectCount},
                {"engine", std::string{profiles::toString(profile.engine)}}};
}

Json tunnelJson(const tunnel::TunnelPtr& tunnel)
{
    Json value{{"id", tunnel->id()},
               {"profileId", tunnel->profileId()},
               {"state", std::string{nova::toString(tunnel->state())}},
               {"uptimeSeconds", static_cast<i64>(tunnel->uptime().count())}};
    if (auto session = tunnel->sessionInfo(); session.has_value()) {
        value["localAddress"] = session->localAddress.toString();
        value["cipher"]       = session->cipher;
    }
    const auto stats = tunnel->statistics();
    value["bytesSent"]     = stats.counters.bytesSent;
    value["bytesReceived"] = stats.counters.bytesReceived;
    return value;
}

/// A handler that reports Unavailable when its subsystem is missing, so the
/// wiring is null-safe without every handler repeating the check.
template <typename Fn>
RequestHandler guarded(bool available, Fn fn)
{
    if (!available) {
        return [](const RequestContext& ctx) {
            return makeError(ctx.request.id,
                             Status{ErrorCode::Unavailable, "subsystem not available"});
        };
    }
    return fn;
}

} // namespace

Result<std::vector<EventBus::Subscription>> registerServiceApi(IIpcServer& server,
                                                               ServiceApiDeps deps)
{
    const auto set = [&server](Method method, RequestHandler handler) -> Status {
        return server.setHandler(method, std::move(handler));
    };

    // --- profiles ----------------------------------------------------------

    NOVA_RETURN_IF_ERROR(set(Method::ListProfiles, guarded(deps.profiles != nullptr,
        [profiles = deps.profiles](const RequestContext& ctx) {
            profiles::ProfileQuery query;
            query.search = json::get<std::string>(ctx.request.params, "/search", "");
            auto list = profiles->list(query);
            if (list.isError()) {
                return makeError(ctx.request.id, list.status());
            }
            Json rows = Json::array();
            for (const auto& profile : list.value()) {
                rows.push_back(profileSummaryJson(profile));
            }
            return makeSuccess(ctx.request.id, Json{{"profiles", std::move(rows)}});
        })));

    NOVA_RETURN_IF_ERROR(set(Method::GetProfile, guarded(deps.profiles != nullptr,
        [profiles = deps.profiles](const RequestContext& ctx) {
            const Id id = json::get<std::string>(ctx.request.params, "/id", "");
            auto profile = profiles->get(id);
            if (profile.isError()) {
                return makeError(ctx.request.id, profile.status());
            }
            return makeSuccess(ctx.request.id,
                               profiles::toJson(profile.value(), /*includeSecrets=*/false));
        })));

    NOVA_RETURN_IF_ERROR(set(Method::ImportOvpn, guarded(deps.profiles != nullptr,
        [profiles = deps.profiles](const RequestContext& ctx) {
            const std::string text = json::get<std::string>(ctx.request.params, "/config", "");
            const std::string name = json::get<std::string>(ctx.request.params, "/name", "");
            auto report = profiles->importOvpnText(text, name);
            if (report.isError()) {
                return makeError(ctx.request.id, report.status());
            }
            return makeSuccess(ctx.request.id,
                               Json{{"profileId", report.value().profile.id},
                                    {"warnings", report.value().warnings},
                                    {"rejected", report.value().rejectedDirectives}});
        })));

    NOVA_RETURN_IF_ERROR(set(Method::DeleteProfile, guarded(deps.profiles != nullptr,
        [profiles = deps.profiles](const RequestContext& ctx) {
            const Id id = json::get<std::string>(ctx.request.params, "/id", "");
            const Status status = profiles->remove(id);
            return status.isOk() ? makeSuccess(ctx.request.id, Json::object())
                                 : makeError(ctx.request.id, status);
        })));

    NOVA_RETURN_IF_ERROR(set(Method::SetProfileFavorite, guarded(deps.profiles != nullptr,
        [profiles = deps.profiles](const RequestContext& ctx) {
            const Id id = json::get<std::string>(ctx.request.params, "/id", "");
            auto profile = profiles->get(id);
            if (profile.isError()) {
                return makeError(ctx.request.id, profile.status());
            }
            profile.value().metadata.favorite =
                json::get<bool>(ctx.request.params, "/favorite", false);
            const Status status = profiles->update(profile.value());
            return status.isOk() ? makeSuccess(ctx.request.id, Json::object())
                                 : makeError(ctx.request.id, status);
        })));

    // --- connection --------------------------------------------------------

    NOVA_RETURN_IF_ERROR(set(Method::Connect, guarded(
        deps.tunnels != nullptr && deps.profiles != nullptr,
        [tunnels = deps.tunnels, profiles = deps.profiles,
         credentials = deps.credentials](const RequestContext& ctx) {
            const Id profileId = json::get<std::string>(ctx.request.params, "/profileId", "");
            auto profile = profiles->get(profileId);
            if (profile.isError()) {
                return makeError(ctx.request.id, profile.status());
            }

            auto tunnel = tunnels->create(profile.value());
            if (tunnel.isError()) {
                return makeError(ctx.request.id, tunnel.status());
            }

            tunnel::ConnectCredentials creds;
            creds.userName = json::get<std::string>(ctx.request.params, "/username", "");
            if (ctx.request.params.contains("password")) {
                creds.password = SecureString{
                    json::get<std::string>(ctx.request.params, "/password", "")};
            } else if (credentials &&
                       !profile.value().credentials.credentialTarget.empty()) {
                // Pull the stored password from the vault when the request did
                // not carry one.
                if (auto stored =
                        credentials->retrieve(profile.value().credentials.credentialTarget);
                    stored.isOk()) {
                    creds.password = std::move(stored).value();
                }
            }

            const Status status = tunnel.value()->connect(std::move(creds));
            if (status.isError()) {
                (void)tunnels->destroy(tunnel.value()->id());
                return makeError(ctx.request.id, status);
            }
            return makeSuccess(ctx.request.id, Json{{"tunnelId", tunnel.value()->id()}});
        })));

    NOVA_RETURN_IF_ERROR(set(Method::Disconnect, guarded(deps.tunnels != nullptr,
        [tunnels = deps.tunnels](const RequestContext& ctx) {
            const Id tunnelId = json::get<std::string>(ctx.request.params, "/tunnelId", "");
            const Status status = tunnels->destroy(tunnelId);
            return status.isOk() ? makeSuccess(ctx.request.id, Json::object())
                                 : makeError(ctx.request.id, status);
        })));

    NOVA_RETURN_IF_ERROR(set(Method::DisconnectAll, guarded(deps.tunnels != nullptr,
        [tunnels = deps.tunnels](const RequestContext& ctx) {
            const Status status = tunnels->disconnectAll();
            return status.isOk() ? makeSuccess(ctx.request.id, Json::object())
                                 : makeError(ctx.request.id, status);
        })));

    NOVA_RETURN_IF_ERROR(set(Method::GetTunnels, guarded(deps.tunnels != nullptr,
        [tunnels = deps.tunnels](const RequestContext& ctx) {
            Json rows = Json::array();
            for (const auto& tunnel : tunnels->all()) {
                rows.push_back(tunnelJson(tunnel));
            }
            return makeSuccess(ctx.request.id, Json{{"tunnels", std::move(rows)}});
        })));

    NOVA_RETURN_IF_ERROR(set(Method::Reconnect, guarded(deps.tunnels != nullptr,
        [tunnels = deps.tunnels](const RequestContext& ctx) {
            const Id tunnelId = json::get<std::string>(ctx.request.params, "/tunnelId", "");
            auto tunnel = tunnels->find(tunnelId);
            if (tunnel.isError()) {
                return makeError(ctx.request.id, tunnel.status());
            }
            const Status status = tunnel.value()->reconnect();
            return status.isOk() ? makeSuccess(ctx.request.id, Json::object())
                                 : makeError(ctx.request.id, status);
        })));

    // --- settings ----------------------------------------------------------

    NOVA_RETURN_IF_ERROR(set(Method::GetSettings, guarded(deps.settings != nullptr,
        [settings = deps.settings](const RequestContext& ctx) {
            return makeSuccess(ctx.request.id, settings->snapshot());
        })));

    NOVA_RETURN_IF_ERROR(set(Method::SetSettings, guarded(deps.settings != nullptr,
        [settings = deps.settings](const RequestContext& ctx) {
            const Status applied = settings->apply(ctx.request.params);
            if (applied.isError()) {
                return makeError(ctx.request.id, applied);
            }
            (void)settings->save();
            return makeSuccess(ctx.request.id, settings->snapshot());
        })));

    // --- split tunnel ------------------------------------------------------

    NOVA_RETURN_IF_ERROR(set(Method::ListInstalledApps, guarded(deps.processes != nullptr,
        [processes = deps.processes](const RequestContext& ctx) {
            auto apps = processes->installedApplications();
            if (apps.isError()) {
                return makeError(ctx.request.id, apps.status());
            }
            Json rows = Json::array();
            for (const auto& app : apps.value()) {
                rows.push_back(Json{{"imagePath", app.imagePath},
                                    {"displayName", app.displayName},
                                    {"publisher", app.publisher},
                                    {"running", app.isRunning}});
            }
            return makeSuccess(ctx.request.id, Json{{"apps", std::move(rows)}});
        })));

    NOVA_RETURN_IF_ERROR(set(Method::ListProcesses, guarded(deps.processes != nullptr,
        [processes = deps.processes](const RequestContext& ctx) {
            auto running = processes->runningProcesses();
            if (running.isError()) {
                return makeError(ctx.request.id, running.status());
            }
            Json rows = Json::array();
            for (const auto& process : running.value()) {
                rows.push_back(Json{{"pid", process.pid},
                                    {"name", process.displayName},
                                    {"imagePath", process.imagePath}});
            }
            return makeSuccess(ctx.request.id, Json{{"processes", std::move(rows)}});
        })));

    // --- protection --------------------------------------------------------

    NOVA_RETURN_IF_ERROR(set(Method::RunLeakTest, guarded(deps.leakTester != nullptr,
        [leakTester = deps.leakTester](const RequestContext& ctx) {
            CancellationSource source;
            auto result = leakTester->run(source.token());
            if (result.isError()) {
                return makeError(ctx.request.id, result.status());
            }
            return makeSuccess(ctx.request.id,
                               Json{{"dnsLeak", result.value().dnsLeak},
                                    {"ipv6Leak", result.value().ipv6Leak},
                                    {"webRtcLeak", result.value().webRtcLeak},
                                    {"details", result.value().details}});
        })));

    // --- logs --------------------------------------------------------------

    NOVA_RETURN_IF_ERROR(set(Method::GetLogs, guarded(deps.logRing != nullptr,
        [logRing = deps.logRing](const RequestContext& ctx) {
            const auto records = logRing->snapshot();
            Json rows = Json::array();
            for (const auto& record : records) {
                rows.push_back(logs::formatText(record));
            }
            return makeSuccess(ctx.request.id, Json{{"lines", std::move(rows)}});
        })));

    // --- diagnostics -------------------------------------------------------

    NOVA_RETURN_IF_ERROR(set(Method::GetServiceInfo,
        [engines = deps.engines](const RequestContext& ctx) {
            Json info{{"version", std::string{version::kString}},
                      {"channel", std::string{version::kChannel}},
                      {"protocol", version::kIpcProtocol}};
            if (engines) {
                info["engines"] = engines->availableEngines();
            }
            return makeSuccess(ctx.request.id, std::move(info));
        }));

    // --- event forwarding --------------------------------------------------
    // Tunnel state changes and statistics ticks the subsystems publish are
    // broadcast to every connected client, so the UI never polls.
    std::vector<EventBus::Subscription> subscriptions;
    if (deps.events) {
        subscriptions.push_back(deps.events->subscribe<tunnel::TunnelStateChanged>(
            [&server](const tunnel::TunnelStateChanged& e) {
                Event event;
                event.kind    = EventKind::TunnelStateChanged;
                event.payload = Json{{"tunnelId", e.tunnelId},
                                     {"profileId", e.profileId},
                                     {"state", std::string{nova::toString(e.current)}},
                                     {"attempt", e.attempt}};
                if (e.reason.isError()) {
                    event.payload["error"] = e.reason.message();
                }
                server.broadcast(event);
            }));

        subscriptions.push_back(deps.events->subscribe<net::StatisticsTick>(
            [&server](const net::StatisticsTick& tick) {
                Event event;
                event.kind    = EventKind::StatisticsTick;
                event.payload = Json{{"tunnelId", tick.tunnelId},
                                     {"bytesSent", tick.sample.counters.bytesSent},
                                     {"bytesReceived", tick.sample.counters.bytesReceived},
                                     {"upBps", tick.sample.rates.bitsPerSecondUp},
                                     {"downBps", tick.sample.rates.bitsPerSecondDown}};
                server.broadcast(event);
            }));
    }

    NOVA_LOG_INFO(Channel::Ipc, "service API registered");
    return subscriptions;
}

} // namespace nova::service
