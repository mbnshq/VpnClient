#include <NovaVPN/Profiles/Profile.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::profiles;

namespace {

/// A profile that passes validation, used as the baseline every negative case
/// mutates one field of.
Profile makeValidProfile()
{
    Profile profile;
    profile.id     = "550e8400-e29b-41d4-a716-446655440000";
    profile.name   = "Hong Kong 01";
    profile.engine = EngineKind::OpenVpn;

    RemoteEntry remote;
    remote.host      = "hk1.example.net";
    remote.port      = 1194;
    remote.transport = Transport::Udp;
    profile.remotes.push_back(remote);

    profile.authMethod = AuthMethod::CertificateAndPassword;
    profile.credentials.credentialTarget = "NovaVPN/profile/hk-01";
    profile.credentials.userName         = "alice";
    profile.certificates.caPem           = "-----BEGIN CERTIFICATE-----\nMIIB\n";
    profile.certificates.certificatePem  = "-----BEGIN CERTIFICATE-----\nMIIC\n";
    profile.certificates.privateKeyTarget = "NovaVPN/profile/hk-01/key";

    profile.metadata.country = "HK";
    profile.metadata.city    = "Hong Kong";
    profile.metadata.tags    = {"asia", "streaming"};

    return profile;
}

} // namespace

TEST_CASE("auth methods and engines round-trip through text", "[profile]")
{
    AuthMethod method = AuthMethod::Certificate;
    REQUIRE(parseAuthMethod("user-password-totp", method));
    REQUIRE(method == AuthMethod::UserPasswordTotp);
    REQUIRE(toString(AuthMethod::StaticKey) == "static-key");
    REQUIRE_FALSE(parseAuthMethod("magic", method));

    EngineKind engine = EngineKind::OpenVpn;
    REQUIRE(parseEngineKind("wireguard", engine));
    REQUIRE(engine == EngineKind::WireGuard);
    REQUIRE_FALSE(parseEngineKind("carrier-pigeon", engine));
}

TEST_CASE("a well-formed profile validates", "[profile][validation]")
{
    REQUIRE(makeValidProfile().validate().isOk());
}

TEST_CASE("remote validation rejects unusable endpoints", "[profile][validation]")
{
    RemoteEntry remote;
    remote.port = 1194;

    remote.host = "";
    REQUIRE(remote.validate().isError());

    remote.host = "has space.com";
    REQUIRE(remote.validate().isError());

    remote.host = "hk1.example.net";
    REQUIRE(remote.validate().isOk());

    remote.host = "203.0.113.7";
    REQUIRE(remote.validate().isOk());

    remote.port = 0;
    REQUIRE(remote.validate().isError());
}

TEST_CASE("profile validation catches every unusable shape",
          "[profile][validation]")
{
    SECTION("no name")
    {
        Profile profile = makeValidProfile();
        profile.name.clear();
        REQUIRE(profile.validate().code() == ErrorCode::ProfileInvalid);
    }

    SECTION("no remotes")
    {
        Profile profile = makeValidProfile();
        profile.remotes.clear();
        REQUIRE(profile.validate().code() == ErrorCode::ProfileInvalid);
    }

    SECTION("certificate auth without a certificate")
    {
        Profile profile = makeValidProfile();
        profile.authMethod = AuthMethod::Certificate;
        profile.certificates.certificatePem.clear();
        profile.certificates.storeThumbprint.clear();
        REQUIRE(profile.validate().code() == ErrorCode::ProfileInvalid);
    }

    SECTION("password auth without credentials")
    {
        Profile profile = makeValidProfile();
        profile.authMethod = AuthMethod::UserPassword;
        profile.credentials.credentialTarget.clear();
        profile.credentials.userName.clear();
        REQUIRE(profile.validate().code() == ErrorCode::CredentialsMissing);
    }

    SECTION("no way to authenticate the server")
    {
        // Neither a CA nor a pinned fingerprint means the tunnel would accept
        // any peer - an unauthenticated pipe wearing a VPN costume.
        Profile profile = makeValidProfile();
        profile.certificates.caPem.clear();
        profile.certificates.peerFingerprintSha256.clear();
        REQUIRE(profile.validate().code() == ErrorCode::CertificateInvalid);
    }

    SECTION("a pinned fingerprint substitutes for a CA")
    {
        Profile profile = makeValidProfile();
        profile.certificates.caPem.clear();
        profile.certificates.peerFingerprintSha256 = "ab:cd:ef";
        REQUIRE(profile.validate().isOk());
    }

    SECTION("custom DNS with no servers")
    {
        Profile profile = makeValidProfile();
        profile.dns.useServerPushed = false;
        REQUIRE(profile.validate().code() == ErrorCode::ProfileInvalid);
    }

    SECTION("an out-of-range MTU")
    {
        Profile profile = makeValidProfile();
        profile.options.mtu = 100;
        REQUIRE(profile.validate().isError());

        profile.options.mtu = 20000;
        REQUIRE(profile.validate().isError());

        profile.options.mtu = 1420;
        REQUIRE(profile.validate().isOk());
    }

    SECTION("plugin engine without an engine id")
    {
        Profile profile = makeValidProfile();
        profile.engine = EngineKind::Plugin;
        REQUIRE(profile.validate().isError());

        profile.engineId = "wireguard";
        REQUIRE(profile.validate().isOk());
    }
}

TEST_CASE("primaryRemote and displaySummary", "[profile]")
{
    const Profile profile = makeValidProfile();

    REQUIRE(profile.primaryRemote().has_value());
    REQUIRE(profile.primaryRemote()->host == "hk1.example.net");
    REQUIRE(profile.displaySummary() == "Hong Kong 01 (hk1.example.net:1194/udp)");

    Profile empty;
    empty.name = "Empty";
    REQUIRE_FALSE(empty.primaryRemote().has_value());
    REQUIRE(empty.displaySummary() == "Empty");
}

TEST_CASE("profiles round-trip through JSON", "[profile][json]")
{
    Profile original = makeValidProfile();
    original.dns.useServerPushed = false;
    original.dns.servers.push_back(net::IpAddress::parse("10.8.0.1").value());
    original.dns.searchDomains = {"corp.example.com"};
    original.options.mtu = 1420;
    original.options.keepaliveIntervalSeconds = 10;
    original.options.allowCompression = false;
    original.metadata.favorite = true;
    original.metadata.connectCount = 42;
    original.sourceConfig = "client\nremote hk1.example.net 1194 udp\n";
    original.sourceHash = "abc123";

    const Json encoded = toJson(original, /*includeSecrets=*/true);
    const auto decoded = fromJson(encoded);

    REQUIRE(decoded.isOk());
    const Profile& round = decoded.value();

    REQUIRE(round.id == original.id);
    REQUIRE(round.name == original.name);
    REQUIRE(round.engine == original.engine);
    REQUIRE(round.remotes.size() == 1);
    REQUIRE(round.remotes[0].host == "hk1.example.net");
    REQUIRE(round.remotes[0].port == 1194);
    REQUIRE(round.remotes[0].transport == Transport::Udp);
    REQUIRE(round.authMethod == original.authMethod);
    REQUIRE(round.credentials.credentialTarget == original.credentials.credentialTarget);
    REQUIRE(round.certificates.privateKeyTarget == original.certificates.privateKeyTarget);
    REQUIRE(round.dns.useServerPushed == false);
    REQUIRE(round.dns.servers.size() == 1);
    REQUIRE(round.dns.servers[0].toString() == "10.8.0.1");
    REQUIRE(round.dns.searchDomains == original.dns.searchDomains);
    REQUIRE(round.options.mtu.has_value());
    REQUIRE(*round.options.mtu == 1420);
    REQUIRE(round.options.keepaliveIntervalSeconds.has_value());
    REQUIRE(round.metadata.favorite);
    REQUIRE(round.metadata.connectCount == 42);
    REQUIRE(round.metadata.tags == original.metadata.tags);
    REQUIRE(round.sourceConfig == original.sourceConfig);
}

TEST_CASE("export without secrets omits credential references",
          "[profile][json][security]")
{
    const Profile profile = makeValidProfile();
    const Json exported = toJson(profile, /*includeSecrets=*/false);

    REQUIRE_FALSE(exported.contains("credentials"));
    REQUIRE_FALSE(exported.contains("sourceConfig"));
    REQUIRE_FALSE(exported["certificates"].contains("privateKeyTarget"));
    REQUIRE_FALSE(exported["certificates"].contains("tlsAuthKeyTarget"));

    // The public half of the PKI is still there - a shared profile stays usable.
    REQUIRE(exported["certificates"]["caPem"] == profile.certificates.caPem);
    REQUIRE(exported["name"] == profile.name);
}

TEST_CASE("decoding rejects malformed documents", "[profile][json]")
{
    REQUIRE(fromJson(Json::array()).isError());

    Json badEngine = toJson(makeValidProfile(), true);
    badEngine["engine"] = "carrier-pigeon";
    REQUIRE(fromJson(badEngine).isError());

    Json badAuth = toJson(makeValidProfile(), true);
    badAuth["authMethod"] = "vibes";
    REQUIRE(fromJson(badAuth).isError());

    Json badDns = toJson(makeValidProfile(), true);
    badDns["dns"]["servers"] = Json::array({"not-an-ip"});
    REQUIRE(fromJson(badDns).isError());
}

TEST_CASE("decoding a minimal document applies safe defaults",
          "[profile][json]")
{
    const auto decoded = fromJson(Json{{"name", "Minimal"}});

    REQUIRE(decoded.isOk());
    REQUIRE(decoded.value().name == "Minimal");
    REQUIRE(decoded.value().engine == EngineKind::OpenVpn);
    REQUIRE(decoded.value().options.autoReconnect);
    REQUIRE(decoded.value().options.redirectGateway);
    REQUIRE(decoded.value().options.blockIpv6);
    // Compression stays off unless a profile opts in - VORACLE.
    REQUIRE_FALSE(decoded.value().options.allowCompression);
    // A document with no remotes must not be usable.
    REQUIRE(decoded.value().validate().isError());
}
