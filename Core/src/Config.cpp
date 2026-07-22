#include <NovaVPN/Core/Config.h>
#include <NovaVPN/Core/FileUtil.h>

#include <utility>

namespace nova {
namespace {

/// Service-scope defaults. Every key the service reads must appear here so that
/// a fresh install and a corrupt-file recovery behave identically.
Json makeServiceDefaults()
{
    return Json{
        {"schema", 1},
        {"service",
         {{"logLevel", "info"},
          {"logRetentionDays", 14},
          {"maxLogFileBytes", 16 * 1024 * 1024},
          {"ipcPipeName", "NovaVPN.Service"},
          {"allowMultipleTunnels", true},
          {"maxConcurrentTunnels", 4}}},
        {"connection",
         {{"autoReconnect", true},
          {"reconnectInitialDelayMs", 1000},
          {"reconnectMaxDelayMs", 60000},
          {"reconnectMaxAttempts", 0}, // 0 = unlimited
          {"handshakeTimeoutMs", 30000},
          {"connectTimeoutMs", 60000},
          {"mtu", 1500},
          {"mtuAutoProbe", true}}},
        {"dns",
         {{"leakProtection", true},
          {"mode", "tunnel"}, // tunnel | custom | system
          {"servers", Json::array()},
          {"dohEnabled", false},
          {"dohTemplate", ""},
          {"dotEnabled", false},
          {"dotHost", ""},
          {"blockIpv6Dns", true}}},
        {"firewall",
         {{"killSwitch", "soft"}, // off | soft | hard
          {"blockIpv6", true},
          {"blockLan", false},
          {"allowDhcp", true},
          {"allowLoopback", true},
          {"persistAcrossReboot", true}}},
        {"splitTunnel",
         {{"enabled", false},
          {"mode", "include"}, // include = only listed apps use the VPN
          {"applications", Json::array()},
          {"domainRules", Json::array()},
          {"ipRules", Json::array()}}},
        {"update",
         {{"channel", "stable"},
          {"automatic", true},
          {"checkIntervalHours", 24},
          {"feedUrl", ""},
          {"requireSignature", true}}},
        {"diagnostics",
         {{"debugMode", false}, {"redactLogs", true}, {"crashReports", false}}}};
}

/// User-scope defaults (UI only - nothing here influences tunnel behaviour).
Json makeUserDefaults()
{
    return Json{
        {"schema", 1},
        {"appearance", {{"theme", "system"}, {"accent", "auto"}, {"compactMode", false}}},
        {"language", "system"},
        {"startup",
         {{"autoLaunch", false}, {"startMinimized", false}, {"autoConnectProfileId", ""}}},
        {"notifications",
         {{"enabled", true},
          {"onConnect", true},
          {"onDisconnect", true},
          {"onReconnect", true},
          {"onLeakDetected", true},
          {"onUpdateAvailable", true}}},
        {"dashboard",
         {{"graphWindowSeconds", 120}, {"showLatencyGraph", true}, {"showPacketLoss", true}}},
        {"window", {{"width", 1120}, {"height", 760}, {"maximized", false}}}};
}

} // namespace

const Json& serviceConfigDefaults()
{
    static const Json kDefaults = makeServiceDefaults();
    return kDefaults;
}

const Json& userSettingsDefaults()
{
    static const Json kDefaults = makeUserDefaults();
    return kDefaults;
}

ConfigStore::ConfigStore(std::filesystem::path path, Json defaults)
    : m_path(std::move(path)), m_defaults(std::move(defaults)), m_effective(m_defaults)
{
}

Status ConfigStore::load()
{
    if (!file::exists(m_path)) {
        std::lock_guard lock{m_mutex};
        m_effective = m_defaults;
        return Status::ok();
    }

    auto parsed = json::readFile(m_path);
    if (parsed.isError()) {
        std::lock_guard lock{m_mutex};
        m_effective = m_defaults;
        return std::move(parsed).status().withContext("configuration reset to defaults");
    }

    std::lock_guard lock{m_mutex};
    m_effective = m_defaults;
    json::merge(m_effective, parsed.value());
    return Status::ok();
}

Status ConfigStore::save() const
{
    Json toWrite;
    {
        std::lock_guard lock{m_mutex};
        toWrite = computeDelta(m_defaults, m_effective);
    }
    return json::writeFile(m_path, toWrite);
}

Status ConfigStore::set(std::string_view pointer, Json value)
{
    {
        std::lock_guard lock{m_mutex};
        NOVA_RETURN_IF_ERROR(json::set(m_effective, pointer, std::move(value)));
    }
    notify(pointer);
    return Status::ok();
}

Status ConfigStore::apply(const Json& overlay)
{
    if (!overlay.is_object()) {
        return err::invalidArgument("configuration overlay must be a JSON object");
    }

    std::vector<std::string> changed;
    {
        std::lock_guard lock{m_mutex};
        for (auto it = overlay.begin(); it != overlay.end(); ++it) {
            const Json::json_pointer pointer{"/" + it.key()};

            if (!m_effective.contains(pointer)) {
                changed.push_back(pointer.to_string());
                continue;
            }

            // Compare the *merged* result, not the overlay fragment: an overlay
            // that restates existing values must not fire a change, or every
            // settings-page save would look like a policy change to the
            // subsystems listening here.
            Json merged = m_effective.at(pointer);
            json::merge(merged, *it);
            if (merged != m_effective.at(pointer)) {
                changed.push_back(pointer.to_string());
            }
        }
        json::merge(m_effective, overlay);
    }

    for (const auto& pointer : changed) {
        notify(pointer);
    }
    return Status::ok();
}

Status ConfigStore::reset(std::string_view pointer)
{
    {
        std::lock_guard lock{m_mutex};
        const Json::json_pointer jp{std::string{pointer}};
        if (!m_defaults.contains(jp)) {
            return err::notFound("no default exists for " + std::string{pointer});
        }
        m_effective[jp] = m_defaults[jp];
    }
    notify(pointer);
    return Status::ok();
}

Json ConfigStore::snapshot() const
{
    std::lock_guard lock{m_mutex};
    return m_effective;
}

Json ConfigStore::delta() const
{
    std::lock_guard lock{m_mutex};
    return computeDelta(m_defaults, m_effective);
}

void ConfigStore::onChanged(ChangeHandler handler)
{
    if (!handler) {
        return;
    }
    std::lock_guard lock{m_mutex};
    m_handlers.push_back(std::move(handler));
}

void ConfigStore::notify(std::string_view pointer) const
{
    std::vector<ChangeHandler> snapshot;
    {
        std::lock_guard lock{m_mutex};
        snapshot = m_handlers;
    }
    for (const auto& handler : snapshot) {
        handler(pointer);
    }
}

Json ConfigStore::computeDelta(const Json& defaults, const Json& effective)
{
    if (!defaults.is_object() || !effective.is_object()) {
        return effective;
    }

    Json delta = Json::object();
    for (auto it = effective.begin(); it != effective.end(); ++it) {
        if (!defaults.contains(it.key())) {
            delta[it.key()] = *it;
            continue;
        }

        const Json& base = defaults.at(it.key());
        if (it->is_object() && base.is_object()) {
            Json nested = computeDelta(base, *it);
            if (!nested.empty()) {
                delta[it.key()] = std::move(nested);
            }
        } else if (*it != base) {
            delta[it.key()] = *it;
        }
    }
    return delta;
}

} // namespace nova
