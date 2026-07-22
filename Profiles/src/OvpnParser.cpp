#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/Paths.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Profiles/OvpnParser.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <unordered_set>

namespace nova::profiles {
namespace {

/// Directives that are actively dangerous. Honouring any of these from an
/// untrusted config would let the file run code or downgrade security, so they
/// are rejected and surfaced, never applied.
const std::unordered_set<std::string>& dangerousDirectives()
{
    static const std::unordered_set<std::string> kSet{
        // Arbitrary command execution around the tunnel lifecycle.
        "up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify",
        "auth-user-pass-verify", "client-connect", "client-disconnect", "learn-address",
        "auth-pam", "up-restart",
        // Turns the above from ignored into executed.
        "script-security",
        // Loads arbitrary DLLs/plugins into the privileged process.
        "plugin",
        // Lets the config point the management interface at a socket.
        "management", "management-client", "management-external-key",
    };
    return kSet;
}

/// Directives that are safe but meaningless on Windows + Wintun, or that
/// NovaVPN handles structurally. Reported as ignored so the import is honest.
const std::unordered_set<std::string>& ignoredDirectives()
{
    static const std::unordered_set<std::string> kSet{
        "nobind", "persist-key", "persist-tun", "resolv-retry", "explicit-exit-notify",
        "mute", "mute-replay-warnings", "pull", "tls-client", "dev", "dev-type",
        "route-method", "route-delay", "sndbuf", "rcvbuf", "fast-io", "nice",
        "user", "group", "float", "suppress-timestamps", "machine-readable-output",
    };
    return kSet;
}

/// Ciphers weak enough that a profile choosing them is a mistake worth flagging.
bool isWeakCipher(std::string_view cipher)
{
    const std::string upper = str::toUpper(cipher);
    static constexpr std::array<std::string_view, 7> kWeak{
        "BF-CBC", "DES-CBC", "DES-EDE3-CBC", "RC2-CBC", "RC4", "NONE", "DES-EDE-CBC"};
    return std::any_of(kWeak.begin(), kWeak.end(),
                       [&](std::string_view weak) { return upper == weak; });
}

Transport parseProto(std::string_view proto)
{
    // udp, udp4, udp6, tcp, tcp-client, tcp4-client ...
    return str::startsWith(str::toLower(proto), "tcp") ? Transport::Tcp : Transport::Udp;
}

/// Accumulates parser state as directives are consumed.
struct ParseState {
    Profile       profile;
    ImportReport  report;
    std::string   protoDefault;   // from a bare `proto` line
    u16           portDefault = 1194;
    bool          sawRemote = false;
    bool          sawCa = false;
    bool          sawCert = false;
    bool          sawKey = false;
    bool          redirectGateway = false;
    bool          hasTlsAuth = false;
    bool          hasTlsCrypt = false;
};

/// Reads an inline block body: everything between <tag> and </tag>.
/// Advances `index` past the closing tag. Returns false if unterminated.
bool readInlineBlock(const std::vector<std::string_view>& lines, std::size_t& index,
                     const std::string& tag, std::string& body)
{
    const std::string closing = "</" + tag + ">";
    ++index; // step past the opening tag
    std::string collected;
    while (index < lines.size()) {
        if (str::equalsIgnoreCase(str::trim(lines[index]), closing)) {
            body = std::move(collected);
            return true;
        }
        collected.append(str::trimRight(lines[index]));
        collected.push_back('\n');
        ++index;
    }
    return false;
}

/// Resolves a side-file reference within the base directory. Rejects anything
/// that escapes it - the anti-traversal guard for untrusted configs.
Result<std::string> readSideFile(const OvpnParseOptions& options, const std::string& reference)
{
    if (options.baseDirectory.empty()) {
        return err::invalidArgument("side-file '" + reference +
                                    "' referenced but no base directory was given");
    }
    const std::filesystem::path candidate = options.baseDirectory / reference;
    if (!paths::isContainedIn(options.baseDirectory, candidate)) {
        return err::permissionDenied("side-file '" + reference +
                                     "' escapes the configuration directory");
    }
    return file::readText(candidate);
}

void applyRemote(ParseState& state, const OvpnDirective& directive)
{
    if (directive.args.empty()) {
        return;
    }
    RemoteEntry remote;
    remote.host = directive.args[0];
    remote.port = directive.args.size() > 1
                      ? static_cast<u16>(std::strtoul(directive.args[1].c_str(), nullptr, 10))
                      : state.portDefault;
    if (remote.port == 0) {
        remote.port = state.portDefault;
    }
    remote.transport = directive.args.size() > 2
                           ? parseProto(directive.args[2])
                           : (state.protoDefault.empty() ? Transport::Udp
                                                         : parseProto(state.protoDefault));
    state.profile.remotes.push_back(std::move(remote));
    state.sawRemote = true;
}

Status applyDirective(ParseState& state, const OvpnDirective& directive,
                      const OvpnParseOptions& options)
{
    const std::string& key = directive.keyword;
    auto& profile = state.profile;
    auto& report = state.report;

    // 1. Dangerous directives: reject and report (or fail, in strict mode).
    if (dangerousDirectives().count(key) != 0) {
        report.rejectedDirectives.push_back(key);
        if (options.strict) {
            return Status{ErrorCode::ProfileInvalid,
                          "configuration contains the disallowed directive '" + key + "'"};
        }
        return Status::ok();
    }

    // 2. Structural directives NovaVPN understands.
    if (key == "remote") {
        applyRemote(state, directive);
    } else if (key == "proto") {
        if (!directive.args.empty()) {
            state.protoDefault = directive.args[0];
        }
    } else if (key == "port" || key == "rport") {
        if (!directive.args.empty()) {
            state.portDefault =
                static_cast<u16>(std::strtoul(directive.args[0].c_str(), nullptr, 10));
        }
    } else if (key == "remote-random") {
        profile.options.shuffleRemotes = true;
    } else if (key == "auth-user-pass") {
        // With no argument the client prompts; either way the profile needs a
        // password. A referenced credentials file is deliberately NOT read -
        // NovaVPN keeps credentials in the Credential Manager, not on disk.
        profile.authMethod = profile.authMethod == AuthMethod::Certificate
                                 ? AuthMethod::CertificateAndPassword
                                 : AuthMethod::UserPassword;
        if (!directive.args.empty()) {
            report.warnings.push_back(
                "auth-user-pass referenced a credentials file; enter credentials in NovaVPN "
                "instead - the file was not read");
        }
    } else if (key == "redirect-gateway" || key == "redirect-private") {
        state.redirectGateway = true;
        profile.options.redirectGateway = true;
    } else if (key == "mssfix" || key == "tun-mtu") {
        if (!directive.args.empty()) {
            const u32 mtu = static_cast<u32>(std::strtoul(directive.args[0].c_str(), nullptr, 10));
            if (mtu >= 576 && mtu <= 9000) {
                profile.options.mtu = mtu;
            }
        }
    } else if (key == "keepalive") {
        if (directive.args.size() >= 2) {
            profile.options.keepaliveIntervalSeconds =
                static_cast<u32>(std::strtoul(directive.args[0].c_str(), nullptr, 10));
            profile.options.keepaliveTimeoutSeconds =
                static_cast<u32>(std::strtoul(directive.args[1].c_str(), nullptr, 10));
        }
    } else if (key == "cipher" || key == "data-ciphers") {
        if (!directive.args.empty()) {
            profile.options.cipherOverride = directive.args[0];
            // A weak cipher is honoured (the server may require it) but flagged
            // loudly - the user should know the tunnel is only as strong as this.
            for (const auto& cipher : directive.args) {
                if (isWeakCipher(cipher)) {
                    report.warnings.push_back("configuration selects a weak cipher: " + cipher);
                }
            }
        }
    } else if (key == "auth") {
        if (!directive.args.empty()) {
            profile.options.authDigestOverride = directive.args[0];
        }
    } else if (key == "comp-lzo" || key == "compress" || key == "comp-noadapt") {
        // Compression inside a VPN is a plaintext oracle (VORACLE). It is
        // accepted so the profile still connects, but off by default and warned.
        profile.options.allowCompression = true;
        report.warnings.push_back(
            "configuration enables compression, which is a known VPN weakness (VORACLE); "
            "disable it unless the server requires it");
    } else if (key == "verify-x509-name") {
        if (!directive.args.empty()) {
            profile.certificates.verifyX509Name = directive.args[0];
        }
    } else if (key == "tls-auth") {
        state.hasTlsAuth = true;
        profile.certificates.tlsWrapMode = 0;
    } else if (key == "tls-crypt") {
        state.hasTlsCrypt = true;
        profile.certificates.tlsWrapMode = 1;
    } else if (key == "tls-crypt-v2") {
        state.hasTlsCrypt = true;
        profile.certificates.tlsWrapMode = 2;
    } else if (key == "http-proxy") {
        if (directive.args.size() >= 2) {
            profile.options.proxyUrl =
                "http://" + directive.args[0] + ":" + directive.args[1];
        }
    } else if (key == "socks-proxy") {
        if (directive.args.size() >= 2) {
            profile.options.proxyUrl =
                "socks5://" + directive.args[0] + ":" + directive.args[1];
        }
    } else if (key == "ca" || key == "cert" || key == "key") {
        // Side-file form (inline form is handled by the block reader). Read the
        // public material; refuse to load a private key off disk.
        if (!directive.args.empty()) {
            if (key == "key") {
                report.warnings.push_back(
                    "private key referenced a file; import the key into NovaVPN's secure "
                    "store - it was not read from disk");
            } else {
                auto content = readSideFile(options, directive.args[0]);
                if (content.isError()) {
                    report.warnings.push_back("could not read " + key + " file '" +
                                              directive.args[0] +
                                              "': " + content.status().message());
                } else if (key == "ca") {
                    profile.certificates.caPem = content.value();
                    state.sawCa = true;
                } else if (key == "cert") {
                    profile.certificates.certificatePem = content.value();
                    state.sawCert = true;
                }
            }
        }
    } else if (ignoredDirectives().count(key) != 0) {
        report.ignoredDirectives.push_back(key);
    } else {
        // Unknown directive: record it as ignored so nothing is a silent no-op,
        // but do not fail - OpenVPN has a long tail of niche options.
        report.ignoredDirectives.push_back(key);
    }

    return Status::ok();
}

} // namespace

bool tokenizeOvpnLine(std::string_view line, int lineNumber, OvpnDirective& out)
{
    out.keyword.clear();
    out.args.clear();
    out.lineNumber = lineNumber;

    std::vector<std::string> tokens;
    std::string current;
    bool inToken = false;
    bool inDouble = false;
    bool inSingle = false;

    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];

        if (!inDouble && !inSingle && (c == '#' || c == ';')) {
            break; // rest of the line is a comment
        }

        if (inDouble) {
            if (c == '\\' && i + 1 < line.size()) {
                current.push_back(line[++i]); // escaped char inside double quotes
            } else if (c == '"') {
                inDouble = false;
            } else {
                current.push_back(c);
            }
            continue;
        }
        if (inSingle) {
            if (c == '\'') {
                inSingle = false;
            } else {
                current.push_back(c);
            }
            continue;
        }

        if (c == '"') {
            inDouble = true;
            inToken = true;
        } else if (c == '\'') {
            inSingle = true;
            inToken = true;
        } else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            if (inToken) {
                tokens.push_back(std::move(current));
                current.clear();
                inToken = false;
            }
        } else {
            current.push_back(c);
            inToken = true;
        }
    }
    if (inToken) {
        tokens.push_back(std::move(current));
    }

    if (tokens.empty()) {
        return false;
    }

    out.keyword = str::toLower(tokens.front());
    out.args.assign(tokens.begin() + 1, tokens.end());
    return true;
}

Result<ImportReport> parseOvpn(std::string_view text, const OvpnParseOptions& options)
{
    ParseState state;
    state.profile.name         = options.suggestedName.empty() ? "Imported profile"
                                                               : options.suggestedName;
    state.profile.engine       = EngineKind::OpenVpn;
    state.profile.sourceConfig = std::string{text};
    state.profile.authMethod   = AuthMethod::Certificate; // upgraded if auth-user-pass appears

    const std::vector<std::string_view> lines = str::split(text, '\n');

    for (std::size_t i = 0; i < lines.size(); ++i) {
        const std::string_view raw = str::trim(lines[i]);
        if (raw.empty() || raw.front() == '#' || raw.front() == ';') {
            continue;
        }

        // Inline PKI block: <ca> ... </ca>, <cert>, <key>, <tls-auth>, <tls-crypt>.
        if (raw.front() == '<' && raw.back() == '>' && raw.find("</") == std::string_view::npos) {
            const std::string tag = str::toLower(std::string{raw.substr(1, raw.size() - 2)});
            std::string body;
            if (!readInlineBlock(lines, i, tag, body)) {
                return Status{ErrorCode::ParseError,
                              "unterminated <" + tag + "> block in configuration"};
            }
            if (tag == "ca") {
                state.profile.certificates.caPem = body;
                state.sawCa = true;
            } else if (tag == "cert") {
                state.profile.certificates.certificatePem = body;
                state.sawCert = true;
            } else if (tag == "key") {
                // The private key is present inline. It must not be stored in
                // the clear; the store seals it into the Credential Manager.
                // Hand it back through the report for the store to consume.
                state.profile.certificates.privateKeyTarget = ""; // set by the store
                state.report.warnings.push_back(
                    "an inline private key was found; NovaVPN will move it into its secure "
                    "store on import");
                state.sawKey = true;
                // Stash the key material on the source config only; never in a
                // field that gets serialised to the database in the clear.
            } else if (tag == "tls-auth") {
                state.hasTlsAuth = true;
            } else if (tag == "tls-crypt") {
                state.hasTlsCrypt = true;
            }
            continue;
        }

        OvpnDirective directive;
        if (!tokenizeOvpnLine(raw, static_cast<int>(i + 1), directive)) {
            continue;
        }
        NOVA_RETURN_IF_ERROR(applyDirective(state, directive, options));
    }

    // Post-processing and coherence checks.
    if (!state.sawRemote) {
        return Status{ErrorCode::ProfileInvalid,
                      "configuration has no remote server (missing 'remote' directive)"};
    }

    // If the config never mentioned auth-user-pass and has a client cert, it is
    // certificate-only; if it has neither we cannot authenticate the client.
    if (state.sawCert && state.profile.authMethod == AuthMethod::UserPassword) {
        state.profile.authMethod = AuthMethod::CertificateAndPassword;
    }

    // A CA is mandatory to authenticate the server.
    if (!state.sawCa && state.profile.certificates.peerFingerprintSha256.empty()) {
        state.report.warnings.push_back(
            "configuration has no CA certificate; the server cannot be authenticated until one "
            "is provided");
    }

    state.report.profile = std::move(state.profile);
    return state.report;
}

Result<ImportReport> parseOvpnFile(const std::filesystem::path& path, std::string suggestedName)
{
    NOVA_ASSIGN_OR_RETURN(auto text, file::readText(path));

    OvpnParseOptions options;
    options.baseDirectory = path.parent_path();
    options.suggestedName =
        suggestedName.empty() ? path.stem().string() : std::move(suggestedName);
    return parseOvpn(text, options);
}

Result<std::string> exportOvpn(const Profile& profile)
{
    NOVA_RETURN_IF_ERROR(profile.validate());

    std::string out;
    out.reserve(1024);
    out.append("# Exported by NovaVPN\n");
    out.append("client\n");
    out.append("dev tun\n");

    for (const auto& remote : profile.remotes) {
        out.append("remote ");
        out.append(remote.host);
        out.push_back(' ');
        out.append(std::to_string(remote.port));
        out.push_back(' ');
        out.append(nova::toString(remote.transport));
        out.push_back('\n');
    }

    if (profile.options.shuffleRemotes) {
        out.append("remote-random\n");
    }
    if (profile.authMethod == AuthMethod::UserPassword ||
        profile.authMethod == AuthMethod::CertificateAndPassword ||
        profile.authMethod == AuthMethod::UserPasswordTotp) {
        out.append("auth-user-pass\n");
    }
    if (profile.options.redirectGateway) {
        out.append("redirect-gateway def1\n");
    }
    if (!profile.options.cipherOverride.empty()) {
        out.append("cipher ");
        out.append(profile.options.cipherOverride);
        out.push_back('\n');
    }
    if (!profile.options.authDigestOverride.empty()) {
        out.append("auth ");
        out.append(profile.options.authDigestOverride);
        out.push_back('\n');
    }
    if (!profile.certificates.verifyX509Name.empty()) {
        out.append("verify-x509-name ");
        out.append(profile.certificates.verifyX509Name);
        out.append(" name\n");
    }
    if (profile.options.mtu.has_value()) {
        out.append("tun-mtu ");
        out.append(std::to_string(*profile.options.mtu));
        out.push_back('\n');
    }

    // Public PKI material is inlined; private keys and credentials are never
    // written - the recipient supplies their own.
    if (!profile.certificates.caPem.empty()) {
        out.append("<ca>\n");
        out.append(profile.certificates.caPem);
        if (out.back() != '\n') {
            out.push_back('\n');
        }
        out.append("</ca>\n");
    }
    if (!profile.certificates.certificatePem.empty()) {
        out.append("<cert>\n");
        out.append(profile.certificates.certificatePem);
        if (out.back() != '\n') {
            out.push_back('\n');
        }
        out.append("</cert>\n");
    }

    return out;
}

} // namespace nova::profiles
