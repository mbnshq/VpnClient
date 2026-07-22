// NovaVPN - Profiles/OvpnParser.h
// Parser for OpenVPN configuration files (.ovpn).
//
// An .ovpn file is untrusted input - it arrives by email, download or MDM push
// and drives where the machine's traffic goes and which certificates it trusts.
// The parser therefore does three things beyond reading directives:
//
//   * it REJECTS directives that would weaken security (script execution,
//     insecure ciphers, verification removal) and reports them, rather than
//     silently honouring or silently dropping them;
//   * it IGNORES directives that are irrelevant on Windows/Wintun and reports
//     those too, so an import is never a black box;
//   * it extracts inline <ca>/<cert>/<key>/<tls-auth> blocks and referenced
//     side files, resolving the latter only within the config's own directory
//     (no traversal, no absolute escapes).
//
// The result is an ImportReport: a Profile plus the lists of what was ignored,
// rejected and warned about, which the import dialog shows verbatim.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Profiles/Profile.h>
#include <NovaVPN/Profiles/ProfileStore.h>

#include <filesystem>
#include <string>
#include <string_view>

namespace nova::profiles {

/// Options controlling how strict the parser is.
struct OvpnParseOptions {
    /// Directory used to resolve `ca ca.crt`-style side-file references. Empty
    /// disables side-file resolution (inline blocks still work). A reference
    /// that escapes this directory is rejected, never followed.
    std::filesystem::path baseDirectory;
    /// Name to give the resulting profile when the file has no clue to one.
    std::string           suggestedName;
    /// When true, a rejected security-relevant directive fails the whole parse
    /// instead of being recorded and skipped. The service uses true for
    /// automated MDM imports, the UI uses false so the user sees the report.
    bool                  strict = false;
};

/// Parses `text` (the verbatim contents of a .ovpn file).
[[nodiscard]] Result<ImportReport> parseOvpn(std::string_view text,
                                             const OvpnParseOptions& options);

/// Parses a .ovpn file from disk, using its directory as the side-file base.
[[nodiscard]] Result<ImportReport> parseOvpnFile(const std::filesystem::path& path,
                                                 std::string suggestedName = {});

/// Re-emits a profile as .ovpn text the stock OpenVPN client accepts. Inline
/// blocks are used for all PKI material that the profile holds in the clear
/// (the CA and client certificate); private keys and credentials are never
/// written, since they live in the Credential Manager.
[[nodiscard]] Result<std::string> exportOvpn(const Profile& profile);

// --- exposed for testing --------------------------------------------------

/// One tokenised directive line: the keyword plus its arguments, with quoting
/// and comments already handled.
struct OvpnDirective {
    std::string              keyword;
    std::vector<std::string> args;
    int                      lineNumber = 0;
};

/// Tokenises one line the way OpenVPN does: `#`/`;` start comments, double and
/// single quotes group arguments, backslash escapes within double quotes.
/// Returns false for a blank or comment-only line.
[[nodiscard]] bool tokenizeOvpnLine(std::string_view line, int lineNumber,
                                    OvpnDirective& out);

} // namespace nova::profiles
