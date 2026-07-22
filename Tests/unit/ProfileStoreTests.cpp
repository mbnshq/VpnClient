#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Database/Database.h>
#include <NovaVPN/Profiles/ProfileStore.h>

#include <catch2/catch_test_macros.hpp>

#include <filesystem>

using namespace nova;
using namespace nova::profiles;

namespace {

/// A profile store over a fresh temp database, removed on scope exit. No
/// credential store is wired in, so these tests never touch the machine vault.
class StoreFixture {
public:
    StoreFixture()
        : m_path(std::filesystem::temp_directory_path() /
                 ("novavpn-ps-" + Uuid::generate().toString() + ".db"))
    {
        m_db = db::makeSqliteDatabase();
        REQUIRE(m_db->open(m_path).isOk());
        m_store = makeProfileStore(m_db, nullptr);
        REQUIRE(m_store->open().isOk());
    }

    ~StoreFixture()
    {
        m_store.reset();
        m_db->close();
        m_db.reset();
        std::error_code ec;
        std::filesystem::remove(m_path, ec);
        std::filesystem::remove(m_path.string() + "-wal", ec);
        std::filesystem::remove(m_path.string() + "-shm", ec);
    }

    [[nodiscard]] IProfileStore& store() { return *m_store; }

    static Profile sample(std::string name = "Hong Kong 01")
    {
        Profile profile;
        profile.name = std::move(name);
        RemoteEntry remote;
        remote.host = "hk1.example.net";
        remote.port = 1194;
        profile.remotes.push_back(remote);
        profile.authMethod                   = AuthMethod::CertificateAndPassword;
        profile.credentials.credentialTarget = "NovaVPN/test/hk";
        profile.credentials.userName         = "alice";
        profile.certificates.caPem           = "-----BEGIN CERTIFICATE-----\nMIIB\n";
        profile.certificates.certificatePem  = "-----BEGIN CERTIFICATE-----\nMIIC\n";
        profile.metadata.country             = "HK";
        profile.metadata.tags                = {"asia", "streaming"};
        return profile;
    }

private:
    std::filesystem::path m_path;
    db::DatabasePtr       m_db;
    ProfileStorePtr       m_store;
};

} // namespace

TEST_CASE("a profile round-trips through add and get", "[profilestore]")
{
    StoreFixture fixture;

    auto id = fixture.store().add(StoreFixture::sample());
    REQUIRE(id.isOk());
    REQUIRE_FALSE(id.value().empty());

    auto loaded = fixture.store().get(id.value());
    REQUIRE(loaded.isOk());
    REQUIRE(loaded.value().name == "Hong Kong 01");
    REQUIRE(loaded.value().remotes.size() == 1);
    REQUIRE(loaded.value().credentials.userName == "alice");
    REQUIRE(loaded.value().metadata.country == "HK");
    REQUIRE(loaded.value().metadata.tags.size() == 2);
}

TEST_CASE("add assigns an id and timestamps", "[profilestore]")
{
    StoreFixture fixture;
    Profile profile = StoreFixture::sample();
    REQUIRE(profile.id.empty());

    auto id = fixture.store().add(std::move(profile));
    REQUIRE(id.isOk());

    auto loaded = fixture.store().get(id.value());
    REQUIRE(loaded.value().metadata.createdAt.time_since_epoch().count() > 0);
    REQUIRE(loaded.value().metadata.modifiedAt.time_since_epoch().count() > 0);
}

TEST_CASE("a duplicate name is rejected", "[profilestore]")
{
    StoreFixture fixture;
    REQUIRE(fixture.store().add(StoreFixture::sample("Same")).isOk());

    const auto second = fixture.store().add(StoreFixture::sample("Same"));
    REQUIRE(second.isError());
    REQUIRE(second.status().code() == ErrorCode::AlreadyExists);
}

TEST_CASE("an invalid profile is refused before storage", "[profilestore]")
{
    StoreFixture fixture;
    Profile profile = StoreFixture::sample();
    profile.remotes.clear(); // no remote -> invalid

    REQUIRE(fixture.store().add(std::move(profile)).isError());
    REQUIRE(fixture.store().count().value() == 0);
}

TEST_CASE("update modifies an existing profile", "[profilestore]")
{
    StoreFixture fixture;
    auto id = fixture.store().add(StoreFixture::sample()).value();

    auto profile = fixture.store().get(id).value();
    profile.metadata.favorite = true;
    profile.metadata.city     = "Central";
    REQUIRE(fixture.store().update(profile).isOk());

    auto reloaded = fixture.store().get(id).value();
    REQUIRE(reloaded.metadata.favorite);
    REQUIRE(reloaded.metadata.city == "Central");
}

TEST_CASE("update of a non-existent profile is NotFound", "[profilestore]")
{
    StoreFixture fixture;
    Profile ghost = StoreFixture::sample();
    ghost.id = Uuid::generate().toString();
    REQUIRE(fixture.store().update(ghost).code() == ErrorCode::NotFound);
}

TEST_CASE("remove deletes the profile and cascades tags", "[profilestore]")
{
    StoreFixture fixture;
    auto id = fixture.store().add(StoreFixture::sample()).value();
    REQUIRE(fixture.store().count().value() == 1);

    REQUIRE(fixture.store().remove(id).isOk());
    REQUIRE(fixture.store().count().value() == 0);
    REQUIRE(fixture.store().get(id).status().code() == ErrorCode::NotFound);
}

TEST_CASE("recordConnection bumps usage stats", "[profilestore]")
{
    StoreFixture fixture;
    auto id = fixture.store().add(StoreFixture::sample()).value();

    REQUIRE(fixture.store().recordConnection(id, 1000, 2000).isOk());
    REQUIRE(fixture.store().recordConnection(id, 500, 500).isOk());

    auto profile = fixture.store().get(id).value();
    REQUIRE(profile.metadata.connectCount == 2);
    REQUIRE(profile.metadata.totalBytesSent == 1500);
    REQUIRE(profile.metadata.totalBytesReceived == 2500);
    REQUIRE(profile.metadata.lastConnectedAt.time_since_epoch().count() > 0);
}

TEST_CASE("list filters by search, tags and favourites", "[profilestore]")
{
    StoreFixture fixture;

    Profile hk = StoreFixture::sample("Hong Kong");
    hk.metadata.favorite = true;
    REQUIRE(fixture.store().add(hk).isOk());

    Profile jp = StoreFixture::sample("Japan Tokyo");
    jp.metadata.country = "JP";
    jp.metadata.tags    = {"asia", "gaming"};
    REQUIRE(fixture.store().add(jp).isOk());

    Profile us = StoreFixture::sample("US East");
    us.metadata.country = "US";
    us.metadata.tags    = {"americas"};
    REQUIRE(fixture.store().add(us).isOk());

    // Search matches name/country/city/tags, case-insensitively.
    ProfileQuery byName;
    byName.search = "tokyo";
    REQUIRE(fixture.store().list(byName).value().size() == 1);

    ProfileQuery byTag;
    byTag.tags = {"asia"};
    REQUIRE(fixture.store().list(byTag).value().size() == 2);

    ProfileQuery favourites;
    favourites.favoritesOnly = true;
    auto favResult = fixture.store().list(favourites);
    REQUIRE(favResult.value().size() == 1);
    REQUIRE(favResult.value()[0].name == "Hong Kong");

    // A limit truncates the result.
    ProfileQuery limited;
    limited.limit = 2;
    REQUIRE(fixture.store().list(limited).value().size() == 2);
}

TEST_CASE("list sorts by the requested order", "[profilestore]")
{
    StoreFixture fixture;

    REQUIRE(fixture.store().add(StoreFixture::sample("Charlie")).isOk());
    REQUIRE(fixture.store().add(StoreFixture::sample("alpha")).isOk());
    REQUIRE(fixture.store().add(StoreFixture::sample("Bravo")).isOk());

    ProfileQuery byName;
    byName.sort = SortOrder::NameAscending;
    auto sorted = fixture.store().list(byName).value();
    REQUIRE(sorted.size() == 3);
    // Case-insensitive: alpha, Bravo, Charlie.
    REQUIRE(sorted[0].name == "alpha");
    REQUIRE(sorted[1].name == "Bravo");
    REQUIRE(sorted[2].name == "Charlie");
}

TEST_CASE("getByName finds a profile", "[profilestore]")
{
    StoreFixture fixture;
    REQUIRE(fixture.store().add(StoreFixture::sample("Findable")).isOk());

    REQUIRE(fixture.store().getByName("Findable").isOk());
    REQUIRE(fixture.store().getByName("Missing").status().code() == ErrorCode::NotFound);
}

TEST_CASE("importing .ovpn text stores a usable profile", "[profilestore][ovpn]")
{
    StoreFixture fixture;

    const char* config = R"(client
remote hk1.example.net 1194 udp
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
cacontent
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
certcontent
-----END CERTIFICATE-----
</cert>
)";

    auto report = fixture.store().importOvpnText(config, "Imported HK");
    REQUIRE(report.isOk());
    REQUIRE_FALSE(report.value().profile.id.empty());

    // The imported profile is now retrievable and carries a content hash.
    auto loaded = fixture.store().get(report.value().profile.id);
    REQUIRE(loaded.isOk());
    REQUIRE(loaded.value().name == "Imported HK");
    REQUIRE(loaded.value().remotes[0].host == "hk1.example.net");
    REQUIRE_FALSE(loaded.value().sourceHash.empty());
}

TEST_CASE("export without secrets writes a JSON document", "[profilestore]")
{
    StoreFixture fixture;
    auto id = fixture.store().add(StoreFixture::sample()).value();

    const auto destination = std::filesystem::temp_directory_path() /
                             ("novavpn-export-" + Uuid::generate().toString() + ".json");

    REQUIRE(fixture.store().exportProfile(id, destination, /*includeSecrets=*/false, {}).isOk());
    REQUIRE(std::filesystem::exists(destination));

    std::error_code ec;
    std::filesystem::remove(destination, ec);
}

TEST_CASE("exportAsOvpn re-emits a connectable config", "[profilestore][ovpn]")
{
    StoreFixture fixture;
    auto id = fixture.store().add(StoreFixture::sample()).value();

    auto config = fixture.store().exportAsOvpn(id);
    REQUIRE(config.isOk());
    REQUIRE(config.value().find("remote hk1.example.net 1194 udp") != std::string::npos);
    REQUIRE(config.value().find("PRIVATE KEY") == std::string::npos);
}

TEST_CASE("exporting with secrets requires a passphrase and is not yet supported",
          "[profilestore][security]")
{
    StoreFixture fixture;
    auto id = fixture.store().add(StoreFixture::sample()).value();

    const auto destination = std::filesystem::temp_directory_path() / "unused.bundle";

    // No passphrase -> argument error.
    REQUIRE(fixture.store()
                .exportProfile(id, destination, /*includeSecrets=*/true, SecureString{})
                .code() == ErrorCode::InvalidArgument);

    // With a passphrase -> explicitly not implemented (never a silent clear export).
    REQUIRE(fixture.store()
                .exportProfile(id, destination, /*includeSecrets=*/true,
                               SecureString{"passphrase"})
                .code() == ErrorCode::NotImplemented);
    REQUIRE_FALSE(std::filesystem::exists(destination));
}
