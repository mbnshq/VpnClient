#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Core/Version.h>
#include <NovaVPN/Database/Database.h>

#include <catch2/catch_test_macros.hpp>

#include <filesystem>

using namespace nova;
using namespace nova::db;

namespace {

class ScratchDb {
public:
    ScratchDb()
        : m_path(std::filesystem::temp_directory_path() /
                 ("novavpn-db-" + Uuid::generate().toString() + ".db"))
    {
    }
    ~ScratchDb()
    {
        std::error_code ec;
        std::filesystem::remove(m_path, ec);
        std::filesystem::remove(m_path.string() + "-wal", ec);
        std::filesystem::remove(m_path.string() + "-shm", ec);
    }
    [[nodiscard]] const std::filesystem::path& path() const { return m_path; }

private:
    std::filesystem::path m_path;
};

} // namespace

TEST_CASE("a fresh database opens and migrates to the current schema",
          "[db]")
{
    ScratchDb scratch;
    auto db = makeSqliteDatabase();

    REQUIRE(db->open(scratch.path()).isOk());
    REQUIRE(db->schemaVersion() == version::kDatabaseSchema);
    REQUIRE(db->verifyIntegrity().isOk());

    // Every table the schema declares must exist after migration.
    for (const char* table : {"profiles", "profile_tags", "profile_blobs", "routing_rules",
                              "split_tunnel_apps", "connection_log", "traffic_daily",
                              "settings", "owned_routes"}) {
        auto statement = db->prepare(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1");
        REQUIRE(statement.isOk());
        REQUIRE(statement.value()->bind(1, Value{std::string{table}}).isOk());
        REQUIRE(statement.value()->step().value());
        REQUIRE(asInt(statement.value()->column(0)) == 1);
    }
}

TEST_CASE("migrations are idempotent across reopen", "[db]")
{
    ScratchDb scratch;
    {
        auto db = makeSqliteDatabase();
        REQUIRE(db->open(scratch.path()).isOk());
    }
    // Reopening an already-migrated database must not re-run migrations or
    // change the version.
    auto db = makeSqliteDatabase();
    REQUIRE(db->open(scratch.path()).isOk());
    REQUIRE(db->schemaVersion() == version::kDatabaseSchema);
}

TEST_CASE("parameterised insert and read round-trip every value type", "[db]")
{
    ScratchDb scratch;
    auto db = makeSqliteDatabase();
    REQUIRE(db->open(scratch.path()).isOk());

    REQUIRE(db->execute("CREATE TABLE t (i INTEGER, d REAL, s TEXT, b BLOB, n TEXT)").isOk());

    auto insert = db->prepare("INSERT INTO t VALUES (?1, ?2, ?3, ?4, ?5)");
    REQUIRE(insert.isOk());
    REQUIRE(insert.value()->bind(1, Value{i64{42}}).isOk());
    REQUIRE(insert.value()->bind(2, Value{3.5}).isOk());
    REQUIRE(insert.value()->bind(3, Value{std::string{"hello"}}).isOk());
    REQUIRE(insert.value()->bind(4, Value{std::vector<u8>{0xDE, 0xAD, 0xBE, 0xEF}}).isOk());
    REQUIRE(insert.value()->bind(5, Value{std::monostate{}}).isOk());
    REQUIRE_FALSE(insert.value()->step().value()); // INSERT yields no row
    REQUIRE(db->lastInsertRowId() == 1);
    REQUIRE(db->changes() == 1);

    auto select = db->prepare("SELECT i, d, s, b, n FROM t");
    REQUIRE(select.isOk());
    REQUIRE(select.value()->step().value());
    REQUIRE(asInt(select.value()->column(0)) == 42);
    REQUIRE(asDouble(select.value()->column(1)) == 3.5);
    REQUIRE(asText(select.value()->column(2)) == "hello");
    REQUIRE(asBlob(select.value()->column(3)) == std::vector<u8>{0xDE, 0xAD, 0xBE, 0xEF});
    REQUIRE(isNull(select.value()->column(4)));
    REQUIRE_FALSE(select.value()->step().value()); // one row only
}

TEST_CASE("named parameters bind by name", "[db]")
{
    ScratchDb scratch;
    auto db = makeSqliteDatabase();
    REQUIRE(db->open(scratch.path()).isOk());
    REQUIRE(db->execute("CREATE TABLE t (name TEXT, value INTEGER)").isOk());

    auto insert = db->prepare("INSERT INTO t VALUES (:name, :value)");
    REQUIRE(insert.isOk());
    REQUIRE(insert.value()->bind(":name", Value{std::string{"mtu"}}).isOk());
    REQUIRE(insert.value()->bind(":value", Value{i64{1420}}).isOk());
    REQUIRE_FALSE(insert.value()->step().value());

    // A non-existent parameter name is an error, not a silent no-op.
    REQUIRE(insert.value()->bind(":nope", Value{i64{1}}).isError());

    auto select = db->prepare("SELECT value FROM t WHERE name=:name");
    REQUIRE(select.value()->bind(":name", Value{std::string{"mtu"}}).isOk());
    REQUIRE(select.value()->step().value());
    REQUIRE(asInt(select.value()->column(0)) == 1420);
}

TEST_CASE("a committed transaction persists", "[db]")
{
    ScratchDb scratch;
    auto db = makeSqliteDatabase();
    REQUIRE(db->open(scratch.path()).isOk());
    REQUIRE(db->execute("CREATE TABLE t (v INTEGER)").isOk());

    {
        auto transaction = db->beginTransaction();
        REQUIRE(transaction.isOk());
        REQUIRE(db->execute("INSERT INTO t VALUES (1)").isOk());
        REQUIRE(db->execute("INSERT INTO t VALUES (2)").isOk());
        REQUIRE(transaction.value()->commit().isOk());
    }

    auto count = db->prepare("SELECT count(*) FROM t");
    REQUIRE(count.value()->step().value());
    REQUIRE(asInt(count.value()->column(0)) == 2);
}

TEST_CASE("a transaction rolls back when not committed", "[db]")
{
    ScratchDb scratch;
    auto db = makeSqliteDatabase();
    REQUIRE(db->open(scratch.path()).isOk());
    REQUIRE(db->execute("CREATE TABLE t (v INTEGER)").isOk());

    {
        // Dropping the handle without commit() must undo the writes - this is
        // the guarantee every policy update relies on.
        auto transaction = db->beginTransaction();
        REQUIRE(transaction.isOk());
        REQUIRE(db->execute("INSERT INTO t VALUES (1)").isOk());
    }

    auto count = db->prepare("SELECT count(*) FROM t");
    REQUIRE(count.value()->step().value());
    REQUIRE(asInt(count.value()->column(0)) == 0);
}

TEST_CASE("a UNIQUE violation is reported as AlreadyExists", "[db]")
{
    ScratchDb scratch;
    auto db = makeSqliteDatabase();
    REQUIRE(db->open(scratch.path()).isOk());
    REQUIRE(db->execute("CREATE TABLE t (id TEXT PRIMARY KEY)").isOk());
    REQUIRE(db->execute("INSERT INTO t VALUES ('a')").isOk());

    const Status duplicate = db->execute("INSERT INTO t VALUES ('a')");
    REQUIRE(duplicate.isError());
    REQUIRE(duplicate.code() == ErrorCode::AlreadyExists);
}

TEST_CASE("foreign keys are enforced", "[db]")
{
    ScratchDb scratch;
    auto db = makeSqliteDatabase();
    REQUIRE(db->open(scratch.path()).isOk());

    // profile_blobs references profiles(id) ON DELETE CASCADE - inserting a
    // blob for a non-existent profile must fail.
    auto insert = db->prepare(
        "INSERT INTO profile_blobs (profile_id, payload, payload_len, sealed_at) "
        "VALUES (?1, ?2, ?3, ?4)");
    REQUIRE(insert.isOk());
    REQUIRE(insert.value()->bind(1, Value{std::string{"ghost"}}).isOk());
    REQUIRE(insert.value()->bind(2, Value{std::vector<u8>{1, 2, 3}}).isOk());
    REQUIRE(insert.value()->bind(3, Value{i64{3}}).isOk());
    REQUIRE(insert.value()->bind(4, Value{i64{0}}).isOk());
    REQUIRE(insert.value()->step().isError());
}

TEST_CASE("backup produces a readable copy", "[db]")
{
    ScratchDb scratch;
    ScratchDb backupTarget;

    auto db = makeSqliteDatabase();
    REQUIRE(db->open(scratch.path()).isOk());
    REQUIRE(db->execute("CREATE TABLE t (v INTEGER)").isOk());
    REQUIRE(db->execute("INSERT INTO t VALUES (7)").isOk());

    REQUIRE(db->backupTo(backupTarget.path()).isOk());

    auto copy = makeSqliteDatabase();
    REQUIRE(copy->open(backupTarget.path()).isOk());
    auto select = copy->prepare("SELECT v FROM t");
    REQUIRE(select.value()->step().value());
    REQUIRE(asInt(select.value()->column(0)) == 7);
}

TEST_CASE("statement reset allows rebinding", "[db]")
{
    ScratchDb scratch;
    auto db = makeSqliteDatabase();
    REQUIRE(db->open(scratch.path()).isOk());
    REQUIRE(db->execute("CREATE TABLE t (v INTEGER)").isOk());

    auto insert = db->prepare("INSERT INTO t VALUES (?1)");
    for (i64 i = 1; i <= 3; ++i) {
        REQUIRE(insert.value()->bind(1, Value{i}).isOk());
        REQUIRE_FALSE(insert.value()->step().value());
        REQUIRE(insert.value()->reset().isOk());
    }

    auto sum = db->prepare("SELECT sum(v) FROM t");
    REQUIRE(sum.value()->step().value());
    REQUIRE(asInt(sum.value()->column(0)) == 6);
}

TEST_CASE("double-quoted string literals are rejected", "[db][security]")
{
    // SQLITE_DQS=0: "x" is an identifier, never a string. This closes a whole
    // class of injection where a mistyped quote silently becomes a literal.
    ScratchDb scratch;
    auto db = makeSqliteDatabase();
    REQUIRE(db->open(scratch.path()).isOk());
    REQUIRE(db->execute("CREATE TABLE t (v TEXT)").isOk());

    // "hello" is parsed as a column reference, which does not exist -> error.
    REQUIRE(db->execute("INSERT INTO t VALUES (\"hello\")").isError());
    // Single-quoted string literals still work.
    REQUIRE(db->execute("INSERT INTO t VALUES ('hello')").isOk());
}
