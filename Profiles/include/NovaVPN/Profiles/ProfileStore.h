// NovaVPN - Profiles/ProfileStore.h
// Persistence and import/export contract for profiles.
//
// The store is owned by the service (machine scope). The UI never touches the
// profile files directly - it goes through IPC - so that a standard user cannot
// alter what an administrator provisioned.
//
// Implemented in Phase 3 alongside the OpenVPN engine (the .ovpn parser and the
// store land together, since the parser defines what a profile can hold).
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/SecureMemory.h>
#include <NovaVPN/Database/Database.h>
#include <NovaVPN/Profiles/Profile.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <vector>

namespace nova::profiles {

/// Sort orders offered by the profile list.
enum class SortOrder : u8 {
    NameAscending,
    RecentlyUsed,
    MostUsed,
    CountryThenName,
};

struct ProfileQuery {
    /// Case-insensitive substring match against name, country, city and tags.
    std::string              search;
    std::vector<std::string> tags;
    std::optional<bool>      favoritesOnly;
    SortOrder                sort = SortOrder::NameAscending;
    std::size_t              limit = 0; ///< 0 = unlimited
};

/// What an import produced. Reported to the user so a partially-usable bundle
/// is transparent rather than silently degraded.
struct ImportReport {
    Profile                  profile;
    /// Directives the parser understood but deliberately ignored (e.g. `nobind`
    /// on a platform where it is implicit).
    std::vector<std::string> ignoredDirectives;
    /// Directives that were rejected because they would weaken security
    /// (e.g. `verify-x509-name` removed, insecure ciphers, `script-security`).
    std::vector<std::string> rejectedDirectives;
    /// Human-readable warnings surfaced in the import dialog.
    std::vector<std::string> warnings;
};

class IProfileStore {
public:
    virtual ~IProfileStore() = default;

    // --- lifecycle --------------------------------------------------------

    /// Opens the store, applying any pending schema migrations.
    [[nodiscard]] virtual Status open() = 0;
    virtual void close() = 0;

    // --- queries ----------------------------------------------------------

    [[nodiscard]] virtual Result<std::vector<Profile>> list(const ProfileQuery& query) const = 0;
    [[nodiscard]] virtual Result<Profile> get(const Id& id) const = 0;
    [[nodiscard]] virtual Result<Profile> getByName(const std::string& name) const = 0;
    [[nodiscard]] virtual Result<std::size_t> count() const = 0;

    // --- mutation ---------------------------------------------------------

    /// Assigns an id when the profile has none. Fails with AlreadyExists when
    /// the name collides.
    [[nodiscard]] virtual Result<Id> add(Profile profile) = 0;
    [[nodiscard]] virtual Status update(const Profile& profile) = 0;
    /// Removes the profile, its stored blob and its Credential Manager entries.
    [[nodiscard]] virtual Status remove(const Id& id) = 0;

    /// Records a successful connection for the "recent" and "most used" sorts.
    [[nodiscard]] virtual Status recordConnection(const Id& id, ByteCount sent,
                                                  ByteCount received) = 0;

    // --- import / export --------------------------------------------------

    /// Parses an .ovpn file (including inline <ca>/<cert>/<key> blocks and
    /// referenced side files relative to the config's directory).
    [[nodiscard]] virtual Result<ImportReport> importOvpnFile(
        const std::filesystem::path& path) = 0;

    /// Parses .ovpn content already in memory (paste-from-clipboard, MDM push).
    [[nodiscard]] virtual Result<ImportReport> importOvpnText(std::string_view text,
                                                              std::string suggestedName) = 0;

    /// Writes a `.novaprofile` bundle. `includeSecrets` requires an explicit
    /// user confirmation at the UI layer and an export passphrase.
    [[nodiscard]] virtual Status exportProfile(const Id& id,
                                               const std::filesystem::path& destination,
                                               bool includeSecrets,
                                               const SecureString& passphrase) = 0;

    /// Re-emits the profile as an .ovpn file the stock OpenVPN client accepts.
    [[nodiscard]] virtual Result<std::string> exportAsOvpn(const Id& id) const = 0;
};

using ProfileStorePtr = std::shared_ptr<IProfileStore>;

/// Credential storage contract, backed by the Windows Credential Manager.
/// Split out from the store so that a future enterprise build can back it with
/// a TPM-sealed blob or a smart card without touching profile code.
class ICredentialStore {
public:
    virtual ~ICredentialStore() = default;

    /// Stores a secret under `target`, scoped to the local machine and
    /// readable only by the service account.
    [[nodiscard]] virtual Status store(const std::string& target, const std::string& userName,
                                       const SecureString& secret) = 0;

    [[nodiscard]] virtual Result<SecureString> retrieve(const std::string& target) = 0;
    [[nodiscard]] virtual Result<std::string> userNameFor(const std::string& target) = 0;
    [[nodiscard]] virtual Status erase(const std::string& target) = 0;
    [[nodiscard]] virtual bool contains(const std::string& target) const = 0;
};

using CredentialStorePtr = std::shared_ptr<ICredentialStore>;

/// SQLite-backed profile store. Shares an already-opened database with the rest
/// of the service; seals the verbatim .ovpn source with DPAPI machine scope in
/// profile_blobs, and delegates secret material to `credentials`. The database
/// is required; `credentials` may be null (credential erasure on delete is then
/// skipped), which keeps the store usable in tests that do not touch the vault.
[[nodiscard]] ProfileStorePtr makeProfileStore(db::DatabasePtr database,
                                               CredentialStorePtr credentials);

/// Windows Credential Manager implementation. Secrets are stored as
/// CRED_TYPE_GENERIC entries at CRED_PERSIST_LOCAL_MACHINE scope, so they are
/// readable by the SYSTEM service and survive a reboot but are not roamed.
/// Target names are automatically namespaced under "NovaVPN/" so the product's
/// credentials never collide with anything else in the vault.
[[nodiscard]] CredentialStorePtr makeCredentialStore();

/// Namespace prefix applied to every credential target. Exposed so a profile's
/// stored target reference and the vault entry agree.
[[nodiscard]] std::string credentialTargetPrefix();

} // namespace nova::profiles
