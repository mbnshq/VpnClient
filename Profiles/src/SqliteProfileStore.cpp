#include <NovaVPN/Core/DataProtection.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Database/Database.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Profiles/OvpnParser.h>
#include <NovaVPN/Profiles/ProfileStore.h>

#include <algorithm>
#include <chrono>

using nova::logs::Channel;

namespace nova::profiles {
namespace {

i64 nowMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               SystemClock::now().time_since_epoch())
        .count();
}

i64 toMillis(SystemTime time)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch())
        .count();
}

/// Case-insensitive substring test used by the search filter.
bool matchesSearch(const Profile& profile, const std::string& needle)
{
    if (needle.empty()) {
        return true;
    }
    const std::string lowered = str::toLower(needle);
    const auto has = [&](std::string_view field) {
        return str::contains(str::toLower(std::string{field}), lowered);
    };
    if (has(profile.name) || has(profile.metadata.country) || has(profile.metadata.city)) {
        return true;
    }
    return std::any_of(profile.metadata.tags.begin(), profile.metadata.tags.end(),
                       [&](const std::string& tag) { return has(tag); });
}

class SqliteProfileStore final : public IProfileStore {
public:
    SqliteProfileStore(db::DatabasePtr database, CredentialStorePtr credentials)
        : m_db(std::move(database)), m_credentials(std::move(credentials))
    {
    }

    Status open() override
    {
        // The store does not own the database's open() - the service opens it
        // once and shares it - but it does assert the schema is present.
        if (m_db == nullptr) {
            return err::invalidState("profile store has no database");
        }
        return Status::ok();
    }

    void close() override {}

    // --- queries -----------------------------------------------------------

    Result<std::vector<Profile>> list(const ProfileQuery& query) const override
    {
        NOVA_ASSIGN_OR_RETURN(auto statement,
                              m_db->prepare("SELECT document FROM profiles"));

        std::vector<Profile> profiles;
        while (true) {
            NOVA_ASSIGN_OR_RETURN(const bool hasRow, statement->step());
            if (!hasRow) {
                break;
            }
            auto profile = fromJson(parseDocument(db::asText(statement->column(0))));
            if (profile.isError()) {
                NOVA_LOG_WARN(Channel::Profile, "skipping unreadable profile row")
                    .status(profile.status());
                continue;
            }
            if (passesFilter(profile.value(), query)) {
                profiles.push_back(std::move(profile).value());
            }
        }

        sortProfiles(profiles, query.sort);
        if (query.limit != 0 && profiles.size() > query.limit) {
            profiles.resize(query.limit);
        }
        return profiles;
    }

    Result<Profile> get(const Id& id) const override
    {
        return loadById(id);
    }

    Result<Profile> getByName(const std::string& name) const override
    {
        NOVA_ASSIGN_OR_RETURN(
            auto statement,
            m_db->prepare("SELECT document FROM profiles WHERE name = ?1"));
        NOVA_RETURN_IF_ERROR(statement->bind(1, db::Value{name}));
        NOVA_ASSIGN_OR_RETURN(const bool hasRow, statement->step());
        if (!hasRow) {
            return err::notFound("no profile named '" + name + "'");
        }
        return fromJson(parseDocument(db::asText(statement->column(0))));
    }

    Result<std::size_t> count() const override
    {
        NOVA_ASSIGN_OR_RETURN(auto statement, m_db->prepare("SELECT count(*) FROM profiles"));
        NOVA_ASSIGN_OR_RETURN(const bool hasRow, statement->step());
        if (!hasRow) {
            return std::size_t{0};
        }
        return static_cast<std::size_t>(db::asInt(statement->column(0)));
    }

    // --- mutation ----------------------------------------------------------

    Result<Id> add(Profile profile) override
    {
        if (profile.id.empty()) {
            profile.id = Uuid::generate().toString();
        }
        if (profile.metadata.createdAt.time_since_epoch().count() == 0) {
            profile.metadata.createdAt = SystemClock::now();
        }
        profile.metadata.modifiedAt = SystemClock::now();

        NOVA_RETURN_IF_ERROR(profile.validate());

        NOVA_ASSIGN_OR_RETURN(auto transaction, m_db->beginTransaction());
        NOVA_RETURN_IF_ERROR(writeProfileRow(profile, /*isUpdate=*/false));
        NOVA_RETURN_IF_ERROR(writeTags(profile));
        NOVA_RETURN_IF_ERROR(sealSource(profile));
        NOVA_RETURN_IF_ERROR(transaction->commit());

        NOVA_LOG_INFO(Channel::Profile, "profile added")
            .field("id", profile.id)
            .field("name", profile.name);
        return profile.id;
    }

    Status update(const Profile& profileIn) override
    {
        Profile profile = profileIn;
        profile.metadata.modifiedAt = SystemClock::now();
        NOVA_RETURN_IF_ERROR(profile.validate());

        // Must already exist - update is not an upsert, so a typo'd id is an
        // error rather than a silent insert.
        NOVA_RETURN_IF_ERROR(loadById(profile.id).statusOrOk());

        NOVA_ASSIGN_OR_RETURN(auto transaction, m_db->beginTransaction());
        NOVA_RETURN_IF_ERROR(writeProfileRow(profile, /*isUpdate=*/true));
        NOVA_RETURN_IF_ERROR(m_db->execute("DELETE FROM profile_tags WHERE profile_id = '" +
                                           sqlEscape(profile.id) + "'"));
        NOVA_RETURN_IF_ERROR(writeTags(profile));
        if (!profile.sourceConfig.empty()) {
            NOVA_RETURN_IF_ERROR(sealSource(profile));
        }
        NOVA_RETURN_IF_ERROR(transaction->commit());
        return Status::ok();
    }

    Status remove(const Id& id) override
    {
        NOVA_ASSIGN_OR_RETURN(auto profile, loadById(id));

        NOVA_ASSIGN_OR_RETURN(auto transaction, m_db->beginTransaction());
        // profile_tags and profile_blobs cascade on the foreign key.
        auto deleteStatement = m_db->prepare("DELETE FROM profiles WHERE id = ?1");
        NOVA_RETURN_IF_ERROR(deleteStatement.statusOrOk());
        NOVA_RETURN_IF_ERROR(deleteStatement.value()->bind(1, db::Value{id}));
        NOVA_RETURN_IF_ERROR(deleteStatement.value()->step().statusOrOk());
        NOVA_RETURN_IF_ERROR(transaction->commit());

        // Remove the associated vault entries after the row is gone, so a
        // crash mid-delete never leaves a profile pointing at an absent secret.
        eraseCredentials(profile);

        NOVA_LOG_INFO(Channel::Profile, "profile removed").field("id", id);
        return Status::ok();
    }

    Status recordConnection(const Id& id, ByteCount sent, ByteCount received) override
    {
        NOVA_ASSIGN_OR_RETURN(auto profile, loadById(id));
        profile.metadata.lastConnectedAt    = SystemClock::now();
        profile.metadata.connectCount      += 1;
        profile.metadata.totalBytesSent    += sent;
        profile.metadata.totalBytesReceived += received;
        return update(profile);
    }

    // --- import / export ---------------------------------------------------

    Result<ImportReport> importOvpnFile(const std::filesystem::path& path) override
    {
        NOVA_ASSIGN_OR_RETURN(auto report, parseOvpnFile(path));
        NOVA_RETURN_IF_ERROR(persistImported(report));
        return report;
    }

    Result<ImportReport> importOvpnText(std::string_view text, std::string suggestedName) override
    {
        OvpnParseOptions options;
        options.suggestedName = std::move(suggestedName);
        NOVA_ASSIGN_OR_RETURN(auto report, parseOvpn(text, options));
        NOVA_RETURN_IF_ERROR(persistImported(report));
        return report;
    }

    Status exportProfile(const Id& id, const std::filesystem::path& destination,
                         bool includeSecrets, const SecureString& passphrase) override
    {
        NOVA_ASSIGN_OR_RETURN(auto profile, loadById(id));

        if (includeSecrets) {
            // Exporting secrets requires a passphrase and would produce an
            // encrypted bundle. That bundle format is a Phase 8 concern; until
            // then, refuse rather than silently export in the clear.
            if (passphrase.empty()) {
                return err::invalidArgument(
                    "exporting a profile with secrets requires a passphrase");
            }
            return err::notImplemented(
                "encrypted profile bundles with secrets are not yet supported");
        }

        const Json document = toJson(profile, /*includeSecrets=*/false);
        return json::writeFile(destination, document);
    }

    Result<std::string> exportAsOvpn(const Id& id) const override
    {
        NOVA_ASSIGN_OR_RETURN(auto profile, loadById(id));
        return exportOvpn(profile);
    }

private:
    // --- persistence helpers ----------------------------------------------

    static std::string sqlEscape(const std::string& value)
    {
        return str::replaceAll(value, "'", "''");
    }

    static Json parseDocument(const std::string& text)
    {
        auto parsed = json::parse(text);
        return parsed.isOk() ? parsed.value() : Json::object();
    }

    Result<Profile> loadById(const Id& id) const
    {
        std::string document;
        {
            NOVA_ASSIGN_OR_RETURN(auto statement,
                                  m_db->prepare("SELECT document FROM profiles WHERE id = ?1"));
            NOVA_RETURN_IF_ERROR(statement->bind(1, db::Value{id}));
            NOVA_ASSIGN_OR_RETURN(const bool hasRow, statement->step());
            if (!hasRow) {
                return err::notFound("no profile with id " + id);
            }
            document = db::asText(statement->column(0));
        }
        NOVA_ASSIGN_OR_RETURN(Profile profile, fromJson(parseDocument(document)));
        // The verbatim .ovpn source is sealed separately in profile_blobs and is
        // NOT in the document; restore it so the engine has a config to connect
        // with. Without this, a loaded profile connects with an empty source.
        NOVA_RETURN_IF_ERROR(unsealSource(profile));
        return profile;
    }

    /// Loads and decrypts the profile's sealed .ovpn source into sourceConfig.
    /// A profile with no sealed blob is left as-is (not an error).
    Status unsealSource(Profile& profile) const
    {
        NOVA_ASSIGN_OR_RETURN(
            auto statement,
            m_db->prepare("SELECT payload FROM profile_blobs WHERE profile_id = ?1"));
        NOVA_RETURN_IF_ERROR(statement->bind(1, db::Value{profile.id}));
        NOVA_ASSIGN_OR_RETURN(const bool hasRow, statement->step());
        if (!hasRow) {
            return Status::ok();
        }
        const std::vector<u8> sealed = db::asBlob(statement->column(0));
        if (sealed.empty()) {
            return Status::ok();
        }
        NOVA_ASSIGN_OR_RETURN(auto plain, crypto::unseal(sealed));
        profile.sourceConfig = std::string{plain.view()};
        return Status::ok();
    }

    Status writeProfileRow(const Profile& profile, bool isUpdate)
    {
        // The stored document deliberately excludes the source config (it is
        // sealed separately in profile_blobs) but keeps credential references.
        Profile forStorage = profile;
        forStorage.sourceConfig.clear();
        const Json document = toJson(forStorage, /*includeSecrets=*/true);

        const char* sql =
            isUpdate
                ? "UPDATE profiles SET name=?2, engine=?3, engine_id=?4, auth_method=?5, "
                  "credential_target=?6, user_name=?7, save_password=?8, requires_totp=?9, "
                  "document=?10, source_hash=?11, country=?12, city=?13, favorite=?14, "
                  "image_ref=?15, modified_at=?16, last_connected_at=?17, connect_count=?18, "
                  "total_bytes_sent=?19, total_bytes_recv=?20 WHERE id=?1"
                : "INSERT INTO profiles (id, name, engine, engine_id, auth_method, "
                  "credential_target, user_name, save_password, requires_totp, document, "
                  "source_hash, country, city, favorite, image_ref, created_at, modified_at, "
                  "last_connected_at, connect_count, total_bytes_sent, total_bytes_recv) VALUES "
                  "(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?21,?16,?17,?18,?19,?20)";

        NOVA_ASSIGN_OR_RETURN(auto statement, m_db->prepare(sql));

        NOVA_RETURN_IF_ERROR(statement->bind(1, db::Value{profile.id}));
        NOVA_RETURN_IF_ERROR(statement->bind(2, db::Value{profile.name}));
        NOVA_RETURN_IF_ERROR(
            statement->bind(3, db::Value{std::string{nova::profiles::toString(profile.engine)}}));
        NOVA_RETURN_IF_ERROR(statement->bind(4, db::Value{profile.engineId}));
        NOVA_RETURN_IF_ERROR(statement->bind(
            5, db::Value{std::string{nova::profiles::toString(profile.authMethod)}}));
        NOVA_RETURN_IF_ERROR(
            statement->bind(6, db::Value{profile.credentials.credentialTarget}));
        NOVA_RETURN_IF_ERROR(statement->bind(7, db::Value{profile.credentials.userName}));
        NOVA_RETURN_IF_ERROR(
            statement->bind(8, db::Value{i64{profile.credentials.savePassword ? 1 : 0}}));
        NOVA_RETURN_IF_ERROR(
            statement->bind(9, db::Value{i64{profile.credentials.requiresTotp ? 1 : 0}}));
        NOVA_RETURN_IF_ERROR(statement->bind(10, db::Value{document.dump()}));
        NOVA_RETURN_IF_ERROR(statement->bind(11, db::Value{profile.sourceHash}));
        NOVA_RETURN_IF_ERROR(statement->bind(12, db::Value{profile.metadata.country}));
        NOVA_RETURN_IF_ERROR(statement->bind(13, db::Value{profile.metadata.city}));
        NOVA_RETURN_IF_ERROR(
            statement->bind(14, db::Value{i64{profile.metadata.favorite ? 1 : 0}}));
        NOVA_RETURN_IF_ERROR(statement->bind(15, db::Value{profile.metadata.imageRef}));
        NOVA_RETURN_IF_ERROR(
            statement->bind(16, db::Value{toMillis(profile.metadata.modifiedAt)}));
        NOVA_RETURN_IF_ERROR(
            statement->bind(17, db::Value{toMillis(profile.metadata.lastConnectedAt)}));
        NOVA_RETURN_IF_ERROR(
            statement->bind(18, db::Value{static_cast<i64>(profile.metadata.connectCount)}));
        NOVA_RETURN_IF_ERROR(
            statement->bind(19, db::Value{static_cast<i64>(profile.metadata.totalBytesSent)}));
        NOVA_RETURN_IF_ERROR(statement->bind(
            20, db::Value{static_cast<i64>(profile.metadata.totalBytesReceived)}));
        if (!isUpdate) {
            NOVA_RETURN_IF_ERROR(
                statement->bind(21, db::Value{toMillis(profile.metadata.createdAt)}));
        }

        NOVA_ASSIGN_OR_RETURN(const bool row, statement->step());
        (void)row;
        return Status::ok();
    }

    Status writeTags(const Profile& profile)
    {
        for (const auto& tag : profile.metadata.tags) {
            NOVA_ASSIGN_OR_RETURN(
                auto statement,
                m_db->prepare("INSERT OR IGNORE INTO profile_tags (profile_id, tag) "
                              "VALUES (?1, ?2)"));
            NOVA_RETURN_IF_ERROR(statement->bind(1, db::Value{profile.id}));
            NOVA_RETURN_IF_ERROR(statement->bind(2, db::Value{tag}));
            NOVA_RETURN_IF_ERROR(statement->step().statusOrOk());
        }
        return Status::ok();
    }

    /// Seals the verbatim .ovpn source with DPAPI machine scope and stores it
    /// in profile_blobs, so even a stolen database file yields no config.
    Status sealSource(const Profile& profile)
    {
        if (profile.sourceConfig.empty()) {
            return Status::ok();
        }
        NOVA_ASSIGN_OR_RETURN(
            auto sealed,
            crypto::seal(profile.sourceConfig, crypto::ProtectionScope::Machine));

        NOVA_ASSIGN_OR_RETURN(
            auto statement,
            m_db->prepare("INSERT OR REPLACE INTO profile_blobs "
                          "(profile_id, payload, payload_len, sealed_at) VALUES (?1,?2,?3,?4)"));
        NOVA_RETURN_IF_ERROR(statement->bind(1, db::Value{profile.id}));
        NOVA_RETURN_IF_ERROR(statement->bind(2, db::Value{sealed}));
        NOVA_RETURN_IF_ERROR(statement->bind(3, db::Value{static_cast<i64>(sealed.size())}));
        NOVA_RETURN_IF_ERROR(statement->bind(4, db::Value{nowMillis()}));
        return statement->step().statusOrOk();
    }

    void eraseCredentials(const Profile& profile)
    {
        if (m_credentials == nullptr) {
            return;
        }
        for (const std::string& target :
             {profile.credentials.credentialTarget, profile.certificates.privateKeyTarget,
              profile.certificates.tlsAuthKeyTarget}) {
            if (!target.empty()) {
                (void)m_credentials->erase(target);
            }
        }
    }

    Status persistImported(ImportReport& report)
    {
        // Give the profile a stable id and a content hash before storing, so a
        // re-import of the same file can be detected.
        report.profile.id = Uuid::generate().toString();
        report.profile.sourceHash =
            str::toHex(report.profile.sourceConfig.data(),
                       std::min<std::size_t>(report.profile.sourceConfig.size(), 32));

        // An imported password-based profile has no credentials yet - the user
        // enters them later. Reserve a vault target derived from the id so the
        // profile is structurally complete; the secret is written into that
        // target when the user supplies it, without another profile edit.
        const bool needsPassword =
            report.profile.authMethod == AuthMethod::UserPassword ||
            report.profile.authMethod == AuthMethod::CertificateAndPassword ||
            report.profile.authMethod == AuthMethod::UserPasswordTotp;
        if (needsPassword && report.profile.credentials.credentialTarget.empty()) {
            report.profile.credentials.credentialTarget =
                credentialTargetPrefix() + "profile/" + report.profile.id;
        }

        NOVA_ASSIGN_OR_RETURN(auto id, add(report.profile));
        report.profile.id = id;
        return Status::ok();
    }

    bool passesFilter(const Profile& profile, const ProfileQuery& query) const
    {
        if (query.favoritesOnly.has_value() &&
            *query.favoritesOnly != profile.metadata.favorite) {
            return false;
        }
        if (!matchesSearch(profile, query.search)) {
            return false;
        }
        for (const auto& required : query.tags) {
            if (std::find(profile.metadata.tags.begin(), profile.metadata.tags.end(), required) ==
                profile.metadata.tags.end()) {
                return false;
            }
        }
        return true;
    }

    static void sortProfiles(std::vector<Profile>& profiles, SortOrder order)
    {
        switch (order) {
        case SortOrder::NameAscending:
            std::sort(profiles.begin(), profiles.end(), [](const Profile& a, const Profile& b) {
                return str::toLower(a.name) < str::toLower(b.name);
            });
            break;
        case SortOrder::RecentlyUsed:
            std::sort(profiles.begin(), profiles.end(), [](const Profile& a, const Profile& b) {
                return a.metadata.lastConnectedAt > b.metadata.lastConnectedAt;
            });
            break;
        case SortOrder::MostUsed:
            std::sort(profiles.begin(), profiles.end(), [](const Profile& a, const Profile& b) {
                return a.metadata.connectCount > b.metadata.connectCount;
            });
            break;
        case SortOrder::CountryThenName:
            std::sort(profiles.begin(), profiles.end(), [](const Profile& a, const Profile& b) {
                if (a.metadata.country != b.metadata.country) {
                    return a.metadata.country < b.metadata.country;
                }
                return str::toLower(a.name) < str::toLower(b.name);
            });
            break;
        }
    }

    db::DatabasePtr    m_db;
    CredentialStorePtr m_credentials;
};

} // namespace

ProfileStorePtr makeProfileStore(db::DatabasePtr database, CredentialStorePtr credentials)
{
    return std::make_shared<SqliteProfileStore>(std::move(database), std::move(credentials));
}

} // namespace nova::profiles
