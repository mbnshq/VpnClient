#include <NovaVPN/Profiles/OvpnParser.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

using namespace nova;
using namespace nova::profiles;

namespace {

bool listContains(const std::vector<std::string>& list, std::string_view value)
{
    return std::any_of(list.begin(), list.end(),
                       [&](const std::string& item) { return item == value; });
}

bool anyContains(const std::vector<std::string>& list, std::string_view needle)
{
    return std::any_of(list.begin(), list.end(), [&](const std::string& item) {
        return item.find(needle) != std::string::npos;
    });
}

// A minimal but realistic inline config. example.net is RFC-reserved.
constexpr const char* kBasicConfig = R"(client
dev tun
proto udp
remote hk1.example.net 1194 udp
remote hk2.example.net 1195
resolv-retry infinite
nobind
persist-key
persist-tun
redirect-gateway def1
cipher AES-256-GCM
auth SHA256
verify-x509-name "Server-01" name
keepalive 10 60
<ca>
-----BEGIN CERTIFICATE-----
MIIBfakecacontent
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIICfakeclientcert
-----END CERTIFICATE-----
</cert>
)";

} // namespace

TEST_CASE("line tokenisation follows OpenVPN quoting rules", "[ovpn][tokenize]")
{
    OvpnDirective directive;

    REQUIRE(tokenizeOvpnLine("remote hk1.example.net 1194 udp", 1, directive));
    REQUIRE(directive.keyword == "remote");
    REQUIRE(directive.args.size() == 3);
    REQUIRE(directive.args[0] == "hk1.example.net");

    // Keyword is lower-cased; arguments keep their case.
    REQUIRE(tokenizeOvpnLine("VERIFY-X509-NAME Server-01", 1, directive));
    REQUIRE(directive.keyword == "verify-x509-name");
    REQUIRE(directive.args[0] == "Server-01");

    // Quoted argument with spaces stays one token.
    REQUIRE(tokenizeOvpnLine(R"(verify-x509-name "CN=My Server" name)", 1, directive));
    REQUIRE(directive.args[0] == "CN=My Server");
    REQUIRE(directive.args[1] == "name");

    // Comments (# and ;) and blank lines produce no directive.
    REQUIRE_FALSE(tokenizeOvpnLine("# a comment", 1, directive));
    REQUIRE_FALSE(tokenizeOvpnLine("   ; also a comment", 1, directive));
    REQUIRE_FALSE(tokenizeOvpnLine("   ", 1, directive));

    // Trailing comment after a directive is stripped.
    REQUIRE(tokenizeOvpnLine("proto udp # inline comment", 1, directive));
    REQUIRE(directive.keyword == "proto");
    REQUIRE(directive.args.size() == 1);
    REQUIRE(directive.args[0] == "udp");
}

TEST_CASE("a basic inline config parses into a usable profile", "[ovpn]")
{
    OvpnParseOptions options;
    options.suggestedName = "Hong Kong";

    const auto report = parseOvpn(kBasicConfig, options);
    REQUIRE(report.isOk());

    const Profile& profile = report.value().profile;
    REQUIRE(profile.name == "Hong Kong");
    REQUIRE(profile.engine == EngineKind::OpenVpn);

    REQUIRE(profile.remotes.size() == 2);
    REQUIRE(profile.remotes[0].host == "hk1.example.net");
    REQUIRE(profile.remotes[0].port == 1194);
    REQUIRE(profile.remotes[0].transport == Transport::Udp);
    // Second remote inherits the port default rule and proto default (udp).
    REQUIRE(profile.remotes[1].host == "hk2.example.net");
    REQUIRE(profile.remotes[1].port == 1195);

    REQUIRE(profile.options.redirectGateway);
    REQUIRE(profile.options.cipherOverride == "AES-256-GCM");
    REQUIRE(profile.options.authDigestOverride == "SHA256");
    REQUIRE(profile.certificates.verifyX509Name == "Server-01");
    REQUIRE(profile.options.keepaliveIntervalSeconds.value() == 10);
    REQUIRE(profile.options.keepaliveTimeoutSeconds.value() == 60);

    REQUIRE(profile.certificates.caPem.find("fakecacontent") != std::string::npos);
    REQUIRE(profile.certificates.certificatePem.find("fakeclientcert") != std::string::npos);

    // The verbatim source is retained for lossless re-import.
    REQUIRE(profile.sourceConfig.find("remote hk1.example.net") != std::string::npos);
}

TEST_CASE("noise directives are reported as ignored, never silently dropped",
          "[ovpn]")
{
    const auto report = parseOvpn(kBasicConfig, {});
    REQUIRE(report.isOk());

    // These are safe-but-irrelevant on Windows/Wintun.
    REQUIRE(listContains(report.value().ignoredDirectives, "nobind"));
    REQUIRE(listContains(report.value().ignoredDirectives, "persist-key"));
    REQUIRE(listContains(report.value().ignoredDirectives, "resolv-retry"));
}

TEST_CASE("dangerous directives are rejected and surfaced", "[ovpn][security]")
{
    const char* hostile = R"(client
remote vpn.example.net 1194
script-security 2
up "/bin/sh -c 'curl evil'"
down /tmp/teardown.sh
plugin /usr/lib/evil.so
tls-verify /tmp/verify.sh
<ca>
-----BEGIN CERTIFICATE-----
MIIBfake
-----END CERTIFICATE-----
</ca>
)";

    const auto report = parseOvpn(hostile, {});
    REQUIRE(report.isOk()); // non-strict: parse succeeds, dangers are reported

    const auto& rejected = report.value().rejectedDirectives;
    REQUIRE(listContains(rejected, "script-security"));
    REQUIRE(listContains(rejected, "up"));
    REQUIRE(listContains(rejected, "down"));
    REQUIRE(listContains(rejected, "plugin"));
    REQUIRE(listContains(rejected, "tls-verify"));

    // None of the dangerous directives may leak into the profile's behaviour.
    const Profile& profile = report.value().profile;
    REQUIRE(profile.options.proxyUrl.empty());
}

TEST_CASE("strict mode fails on the first dangerous directive", "[ovpn][security]")
{
    const char* hostile = R"(client
remote vpn.example.net 1194
up /tmp/x.sh
)";

    OvpnParseOptions options;
    options.strict = true;

    const auto report = parseOvpn(hostile, options);
    REQUIRE(report.isError());
    REQUIRE(report.status().code() == ErrorCode::ProfileInvalid);
}

TEST_CASE("a weak cipher is honoured but flagged", "[ovpn][security]")
{
    const char* config = R"(client
remote vpn.example.net 1194
cipher BF-CBC
<ca>
x
</ca>
)";

    const auto report = parseOvpn(config, {});
    REQUIRE(report.isOk());
    REQUIRE(anyContains(report.value().warnings, "weak cipher"));
}

TEST_CASE("compression is accepted but warned about (VORACLE)",
          "[ovpn][security]")
{
    const char* config = R"(client
remote vpn.example.net 1194
comp-lzo yes
<ca>
x
</ca>
)";

    const auto report = parseOvpn(config, {});
    REQUIRE(report.isOk());
    REQUIRE(report.value().profile.options.allowCompression);
    REQUIRE(anyContains(report.value().warnings, "VORACLE"));
}

TEST_CASE("an inline private key is flagged for secure storage, not left inline",
          "[ovpn][security]")
{
    const char* config = R"(client
remote vpn.example.net 1194
auth-user-pass
<ca>
cacontent
</ca>
<cert>
certcontent
</cert>
<key>
-----BEGIN PRIVATE KEY-----
secretkeymaterial
-----END PRIVATE KEY-----
</key>
)";

    const auto report = parseOvpn(config, {});
    REQUIRE(report.isOk());
    REQUIRE(anyContains(report.value().warnings, "secure store"));

    // The private key must never be serialised into a stored field in the clear.
    const Profile& profile = report.value().profile;
    REQUIRE(profile.certificates.privateKeyTarget.empty());
}

TEST_CASE("a config with no remote is rejected", "[ovpn]")
{
    const char* config = R"(client
dev tun
<ca>
x
</ca>
)";
    REQUIRE(parseOvpn(config, {}).isError());
}

TEST_CASE("an unterminated inline block is a parse error", "[ovpn]")
{
    const char* config = R"(client
remote vpn.example.net 1194
<ca>
-----BEGIN CERTIFICATE-----
never closed
)";
    const auto report = parseOvpn(config, {});
    REQUIRE(report.isError());
    REQUIRE(report.status().code() == ErrorCode::ParseError);
}

TEST_CASE("auth-user-pass sets the auth method and warns about a referenced file",
          "[ovpn]")
{
    const char* config = R"(client
remote vpn.example.net 1194
auth-user-pass secrets.txt
<ca>
x
</ca>
<cert>
y
</cert>
)";
    const auto report = parseOvpn(config, {});
    REQUIRE(report.isOk());
    REQUIRE(report.value().profile.authMethod == AuthMethod::CertificateAndPassword);
    REQUIRE(anyContains(report.value().warnings, "not read")); // file ignored
}

TEST_CASE("username/password-only config (CA, no client cert) imports as UserPassword",
          "[ovpn]")
{
    // The shape most commercial providers ship: auth-user-pass with a server CA
    // and no <cert>/<key>. It must NOT be treated as needing a client
    // certificate - that was the "authentication requires a client certificate"
    // import failure.
    const char* config = R"(client
dev tun
proto tcp
remote vpn.example.net 443
remote-random
resolv-retry infinite
nobind
persist-key
persist-tun
<ca>
cacontent
</ca>
verify-x509-name example name-prefix
remote-cert-tls server
auth-user-pass
auth SHA256
)";
    const auto report = parseOvpn(config, {});
    REQUIRE(report.isOk());
    REQUIRE(report.value().profile.authMethod == AuthMethod::UserPassword);
    // And it is storable as-is (no client certificate demanded).
    REQUIRE(report.value().profile.validate().isOk());
}

TEST_CASE("a side-file reference that escapes the base directory is refused",
          "[ovpn][security]")
{
    // Even though we do not create the file, the traversal attempt must be
    // reported as a warning rather than followed.
    const char* config = R"(client
remote vpn.example.net 1194
ca ../../../../windows/system32/secret.crt
)";

    OvpnParseOptions options;
    options.baseDirectory = std::filesystem::temp_directory_path();

    const auto report = parseOvpn(config, options);
    REQUIRE(report.isOk());
    REQUIRE(anyContains(report.value().warnings, "escapes"));
    // Nothing was loaded into the CA field from the traversal.
    REQUIRE(report.value().profile.certificates.caPem.empty());
}

TEST_CASE("tcp remotes are detected from the proto argument", "[ovpn]")
{
    const char* config = R"(client
proto tcp
remote vpn.example.net 443 tcp-client
<ca>
x
</ca>
)";
    const auto report = parseOvpn(config, {});
    REQUIRE(report.isOk());
    REQUIRE(report.value().profile.remotes[0].transport == Transport::Tcp);
    REQUIRE(report.value().profile.remotes[0].port == 443);
}

TEST_CASE("export round-trips through the parser", "[ovpn]")
{
    // Parse a config, export the profile, re-parse: the essentials survive.
    auto first = parseOvpn(kBasicConfig, {});
    REQUIRE(first.isOk());

    Profile profile = first.value().profile;
    // Give it the credentials validate() needs to accept an export.
    profile.credentials.credentialTarget = "NovaVPN/test";
    profile.credentials.userName = "user";

    const auto exported = exportOvpn(profile);
    REQUIRE(exported.isOk());
    REQUIRE(exported.value().find("remote hk1.example.net 1194 udp") != std::string::npos);
    REQUIRE(exported.value().find("<ca>") != std::string::npos);
    // Private key material is never exported.
    REQUIRE(exported.value().find("PRIVATE KEY") == std::string::npos);

    const auto second = parseOvpn(exported.value(), {});
    REQUIRE(second.isOk());
    REQUIRE(second.value().profile.remotes.size() == 2);
    REQUIRE(second.value().profile.options.cipherOverride == "AES-256-GCM");
}
