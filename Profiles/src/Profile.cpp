#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Profiles/Profile.h>

#include <algorithm>
#include <array>
#include <chrono>

namespace nova::profiles {
namespace {

struct NamedAuth {
    AuthMethod       method;
    std::string_view name;
};

constexpr std::array<NamedAuth, 5> kAuthMethods{
    {{AuthMethod::Certificate, "certificate"},
     {AuthMethod::UserPassword, "user-password"},
     {AuthMethod::CertificateAndPassword, "certificate-and-password"},
     {AuthMethod::UserPasswordTotp, "user-password-totp"},
     {AuthMethod::StaticKey, "static-key"}}};

struct NamedEngine {
    EngineKind       kind;
    std::string_view name;
};

constexpr std::array<NamedEngine, 3> kEngines{{{EngineKind::OpenVpn, "openvpn"},
                                               {EngineKind::WireGuard, "wireguard"},
                                               {EngineKind::Plugin, "plugin"}}};

i64 toUnixMillis(SystemTime time)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count();
}

SystemTime fromUnixMillis(i64 millis)
{
    return SystemTime{std::chrono::milliseconds{millis}};
}

bool requiresPassword(AuthMethod method) noexcept
{
    return method == AuthMethod::UserPassword || method == AuthMethod::CertificateAndPassword ||
           method == AuthMethod::UserPasswordTotp;
}

bool requiresCertificate(AuthMethod method) noexcept
{
    return method == AuthMethod::Certificate || method == AuthMethod::CertificateAndPassword;
}

} // namespace

std::string_view toString(AuthMethod method) noexcept
{
    for (const auto& entry : kAuthMethods) {
        if (entry.method == method) {
            return entry.name;
        }
    }
    return "unknown";
}

bool parseAuthMethod(std::string_view text, AuthMethod& out) noexcept
{
    for (const auto& entry : kAuthMethods) {
        if (str::equalsIgnoreCase(text, entry.name)) {
            out = entry.method;
            return true;
        }
    }
    return false;
}

std::string_view toString(EngineKind kind) noexcept
{
    for (const auto& entry : kEngines) {
        if (entry.kind == kind) {
            return entry.name;
        }
    }
    return "unknown";
}

bool parseEngineKind(std::string_view text, EngineKind& out) noexcept
{
    for (const auto& entry : kEngines) {
        if (str::equalsIgnoreCase(text, entry.name)) {
            out = entry.kind;
            return true;
        }
    }
    return false;
}

// --- RemoteEntry ----------------------------------------------------------

Status RemoteEntry::validate() const
{
    if (host.empty()) {
        return Status{ErrorCode::ProfileInvalid, "remote host is empty"};
    }

    net::IpAddress literal;
    if (!net::IpAddress::tryParse(host, literal) && !net::isValidHostName(host)) {
        return Status{ErrorCode::ProfileInvalid, "remote host is not a valid name or address: " +
                                                     host};
    }
    if (port == 0) {
        return Status{ErrorCode::ProfileInvalid, "remote port must be between 1 and 65535"};
    }
    return Status::ok();
}

// --- Profile --------------------------------------------------------------

Status Profile::validate() const
{
    if (name.empty()) {
        return Status{ErrorCode::ProfileInvalid, "profile name is empty"};
    }
    if (name.size() > 128) {
        return Status{ErrorCode::ProfileInvalid, "profile name exceeds 128 characters"};
    }
    if (remotes.empty()) {
        return Status{ErrorCode::ProfileInvalid, "profile has no remote servers"};
    }
    if (remotes.size() > 64) {
        return Status{ErrorCode::ProfileInvalid, "profile lists more than 64 remotes"};
    }

    for (const auto& remote : remotes) {
        NOVA_RETURN_IF_ERROR(remote.validate().withContext("profile '" + name + "'"));
    }

    if (engine == EngineKind::Plugin && engineId.empty()) {
        return Status{ErrorCode::ProfileInvalid, "plugin engine selected but no engine id given"};
    }

    if (requiresCertificate(authMethod) && certificates.certificatePem.empty() &&
        certificates.storeThumbprint.empty()) {
        return Status{ErrorCode::ProfileInvalid,
                      "authentication requires a client certificate but none is configured"};
    }
    if (requiresPassword(authMethod) && credentials.credentialTarget.empty() &&
        credentials.userName.empty()) {
        return Status{ErrorCode::CredentialsMissing,
                      "authentication requires credentials but none are configured"};
    }
    if (certificates.caPem.empty() && certificates.peerFingerprintSha256.empty() &&
        authMethod != AuthMethod::StaticKey) {
        // Without a CA or a pinned fingerprint the client cannot authenticate
        // the server, which turns the tunnel into an unauthenticated pipe.
        return Status{ErrorCode::CertificateInvalid,
                      "profile has neither a CA certificate nor a pinned peer fingerprint"};
    }

    if (!dns.useServerPushed && dns.servers.empty()) {
        return Status{ErrorCode::ProfileInvalid,
                      "DNS is set to custom servers but none are listed"};
    }

    if (options.mtu.has_value() && (*options.mtu < 576 || *options.mtu > 9000)) {
        return Status{ErrorCode::ProfileInvalid, "MTU must be between 576 and 9000"};
    }

    return Status::ok();
}

std::optional<RemoteEntry> Profile::primaryRemote() const
{
    if (remotes.empty()) {
        return std::nullopt;
    }
    return remotes.front();
}

std::string Profile::displaySummary() const
{
    std::string out = name;
    if (const auto remote = primaryRemote()) {
        out.append(" (");
        out.append(remote->host);
        out.push_back(':');
        out.append(std::to_string(remote->port));
        out.push_back('/');
        out.append(nova::toString(remote->transport));
        out.push_back(')');
    }
    return out;
}

// --- JSON -----------------------------------------------------------------

Json toJson(const Profile& profile, bool includeSecrets)
{
    Json remotes = Json::array();
    for (const auto& remote : profile.remotes) {
        remotes.push_back(Json{{"host", remote.host},
                               {"port", remote.port},
                               {"transport", nova::toString(remote.transport)},
                               {"label", remote.label}});
    }

    Json dnsServers = Json::array();
    for (const auto& server : profile.dns.servers) {
        dnsServers.push_back(server.toString());
    }

    Json value{
        {"schema", 1},
        {"id", profile.id},
        {"name", profile.name},
        {"engine", nova::profiles::toString(profile.engine)},
        {"engineId", profile.engineId},
        {"remotes", std::move(remotes)},
        {"authMethod", nova::profiles::toString(profile.authMethod)},
        {"certificates",
         {{"caPem", profile.certificates.caPem},
          {"certificatePem", profile.certificates.certificatePem},
          {"storeThumbprint", profile.certificates.storeThumbprint},
          {"tlsWrapMode", profile.certificates.tlsWrapMode},
          {"verifyX509Name", profile.certificates.verifyX509Name},
          {"peerFingerprintSha256", profile.certificates.peerFingerprintSha256}}},
        {"dns",
         {{"useServerPushed", profile.dns.useServerPushed},
          {"servers", std::move(dnsServers)},
          {"searchDomains", profile.dns.searchDomains},
          {"blockOutsideDns", profile.dns.blockOutsideDns},
          {"dohTemplate", profile.dns.dohTemplate}}},
        {"options",
         {{"autoConnect", profile.options.autoConnect},
          {"autoReconnect", profile.options.autoReconnect},
          {"shuffleRemotes", profile.options.shuffleRemotes},
          {"redirectGateway", profile.options.redirectGateway},
          {"blockIpv6", profile.options.blockIpv6},
          {"allowCompression", profile.options.allowCompression},
          {"cipherOverride", profile.options.cipherOverride},
          {"authDigestOverride", profile.options.authDigestOverride},
          {"proxyUrl", profile.options.proxyUrl}}},
        {"metadata",
         {{"country", profile.metadata.country},
          {"city", profile.metadata.city},
          {"notes", profile.metadata.notes},
          {"tags", profile.metadata.tags},
          {"favorite", profile.metadata.favorite},
          {"imageRef", profile.metadata.imageRef},
          {"createdAt", toUnixMillis(profile.metadata.createdAt)},
          {"modifiedAt", toUnixMillis(profile.metadata.modifiedAt)},
          {"lastConnectedAt", toUnixMillis(profile.metadata.lastConnectedAt)},
          {"connectCount", profile.metadata.connectCount},
          {"totalBytesSent", profile.metadata.totalBytesSent},
          {"totalBytesReceived", profile.metadata.totalBytesReceived}}},
        {"sourceHash", profile.sourceHash},
    };

    if (profile.dns.dohEnabled.has_value()) {
        value["dns"]["dohEnabled"] = *profile.dns.dohEnabled;
    }
    if (profile.options.mtu.has_value()) {
        value["options"]["mtu"] = *profile.options.mtu;
    }
    if (profile.options.keepaliveIntervalSeconds.has_value()) {
        value["options"]["keepaliveIntervalSeconds"] = *profile.options.keepaliveIntervalSeconds;
    }
    if (profile.options.keepaliveTimeoutSeconds.has_value()) {
        value["options"]["keepaliveTimeoutSeconds"] = *profile.options.keepaliveTimeoutSeconds;
    }

    if (includeSecrets) {
        // Credential *references* and the verbatim source configuration only
        // travel with the profile inside the machine-protected store, never in
        // a user-initiated export.
        value["credentials"] = Json{{"credentialTarget", profile.credentials.credentialTarget},
                                    {"userName", profile.credentials.userName},
                                    {"savePassword", profile.credentials.savePassword},
                                    {"requiresTotp", profile.credentials.requiresTotp}};
        value["certificates"]["privateKeyTarget"] = profile.certificates.privateKeyTarget;
        value["certificates"]["tlsAuthKeyTarget"] = profile.certificates.tlsAuthKeyTarget;
        value["sourceConfig"] = profile.sourceConfig;
    }

    return value;
}

Result<Profile> fromJson(const Json& value)
{
    if (!value.is_object()) {
        return Status{ErrorCode::ProfileInvalid, "profile document is not a JSON object"};
    }

    Profile profile;
    profile.id   = json::get<std::string>(value, "/id", "");
    profile.name = json::get<std::string>(value, "/name", "");

    const std::string engineText = json::get<std::string>(value, "/engine", "openvpn");
    if (!parseEngineKind(engineText, profile.engine)) {
        return Status{ErrorCode::ProfileInvalid, "unknown engine '" + engineText + "'"};
    }
    profile.engineId = json::get<std::string>(value, "/engineId", "");

    if (value.contains("remotes") && value["remotes"].is_array()) {
        for (const auto& item : value["remotes"]) {
            RemoteEntry remote;
            remote.host  = json::get<std::string>(item, "/host", "");
            remote.port  = static_cast<u16>(json::get<int>(item, "/port", 1194));
            remote.label = json::get<std::string>(item, "/label", "");

            const std::string transport = json::get<std::string>(item, "/transport", "udp");
            remote.transport = str::equalsIgnoreCase(transport, "tcp") ? Transport::Tcp
                                                                       : Transport::Udp;
            profile.remotes.push_back(std::move(remote));
        }
    }

    const std::string authText =
        json::get<std::string>(value, "/authMethod", "certificate-and-password");
    if (!parseAuthMethod(authText, profile.authMethod)) {
        return Status{ErrorCode::ProfileInvalid, "unknown auth method '" + authText + "'"};
    }

    profile.credentials.credentialTarget =
        json::get<std::string>(value, "/credentials/credentialTarget", "");
    profile.credentials.userName = json::get<std::string>(value, "/credentials/userName", "");
    profile.credentials.savePassword = json::get<bool>(value, "/credentials/savePassword", false);
    profile.credentials.requiresTotp = json::get<bool>(value, "/credentials/requiresTotp", false);

    profile.certificates.caPem = json::get<std::string>(value, "/certificates/caPem", "");
    profile.certificates.certificatePem =
        json::get<std::string>(value, "/certificates/certificatePem", "");
    profile.certificates.privateKeyTarget =
        json::get<std::string>(value, "/certificates/privateKeyTarget", "");
    profile.certificates.storeThumbprint =
        json::get<std::string>(value, "/certificates/storeThumbprint", "");
    profile.certificates.tlsAuthKeyTarget =
        json::get<std::string>(value, "/certificates/tlsAuthKeyTarget", "");
    profile.certificates.tlsWrapMode = json::get<int>(value, "/certificates/tlsWrapMode", 0);
    profile.certificates.verifyX509Name =
        json::get<std::string>(value, "/certificates/verifyX509Name", "");
    profile.certificates.peerFingerprintSha256 =
        json::get<std::string>(value, "/certificates/peerFingerprintSha256", "");

    profile.dns.useServerPushed = json::get<bool>(value, "/dns/useServerPushed", true);
    profile.dns.blockOutsideDns = json::get<bool>(value, "/dns/blockOutsideDns", true);
    profile.dns.dohTemplate     = json::get<std::string>(value, "/dns/dohTemplate", "");
    profile.dns.searchDomains =
        json::get<std::vector<std::string>>(value, "/dns/searchDomains", {});
    if (value.contains("dns") && value["dns"].contains("dohEnabled")) {
        profile.dns.dohEnabled = json::get<bool>(value, "/dns/dohEnabled", false);
    }
    for (const auto& server : json::get<std::vector<std::string>>(value, "/dns/servers", {})) {
        auto parsed = net::IpAddress::parse(server);
        if (parsed.isError()) {
            return Status{ErrorCode::ProfileInvalid, "invalid DNS server '" + server + "'"};
        }
        profile.dns.servers.push_back(parsed.value());
    }

    profile.options.autoConnect      = json::get<bool>(value, "/options/autoConnect", false);
    profile.options.autoReconnect    = json::get<bool>(value, "/options/autoReconnect", true);
    profile.options.shuffleRemotes   = json::get<bool>(value, "/options/shuffleRemotes", false);
    profile.options.redirectGateway  = json::get<bool>(value, "/options/redirectGateway", true);
    profile.options.blockIpv6        = json::get<bool>(value, "/options/blockIpv6", true);
    profile.options.allowCompression = json::get<bool>(value, "/options/allowCompression", false);
    profile.options.cipherOverride   = json::get<std::string>(value, "/options/cipherOverride", "");
    profile.options.authDigestOverride =
        json::get<std::string>(value, "/options/authDigestOverride", "");
    profile.options.proxyUrl = json::get<std::string>(value, "/options/proxyUrl", "");

    if (value.contains("options")) {
        const Json& options = value["options"];
        if (options.contains("mtu")) {
            profile.options.mtu = static_cast<u32>(json::get<int>(value, "/options/mtu", 1500));
        }
        if (options.contains("keepaliveIntervalSeconds")) {
            profile.options.keepaliveIntervalSeconds =
                static_cast<u32>(json::get<int>(value, "/options/keepaliveIntervalSeconds", 10));
        }
        if (options.contains("keepaliveTimeoutSeconds")) {
            profile.options.keepaliveTimeoutSeconds =
                static_cast<u32>(json::get<int>(value, "/options/keepaliveTimeoutSeconds", 60));
        }
    }

    profile.metadata.country  = json::get<std::string>(value, "/metadata/country", "");
    profile.metadata.city     = json::get<std::string>(value, "/metadata/city", "");
    profile.metadata.notes    = json::get<std::string>(value, "/metadata/notes", "");
    profile.metadata.tags     = json::get<std::vector<std::string>>(value, "/metadata/tags", {});
    profile.metadata.favorite = json::get<bool>(value, "/metadata/favorite", false);
    profile.metadata.imageRef = json::get<std::string>(value, "/metadata/imageRef", "");
    profile.metadata.createdAt = fromUnixMillis(json::get<i64>(value, "/metadata/createdAt", 0));
    profile.metadata.modifiedAt = fromUnixMillis(json::get<i64>(value, "/metadata/modifiedAt", 0));
    profile.metadata.lastConnectedAt =
        fromUnixMillis(json::get<i64>(value, "/metadata/lastConnectedAt", 0));
    profile.metadata.connectCount = json::get<u64>(value, "/metadata/connectCount", 0);
    profile.metadata.totalBytesSent = json::get<u64>(value, "/metadata/totalBytesSent", 0);
    profile.metadata.totalBytesReceived = json::get<u64>(value, "/metadata/totalBytesReceived", 0);

    profile.sourceConfig = json::get<std::string>(value, "/sourceConfig", "");
    profile.sourceHash   = json::get<std::string>(value, "/sourceHash", "");

    return profile;
}

} // namespace nova::profiles
