#include <NovaVPN/Core/Version.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Database/Database.h>
#include <NovaVPN/Logs/Logger.h>

#include <sqlite3.h>

#include <mutex>
#include <utility>

using nova::logs::Channel;

namespace nova::db {
namespace {

/// Maps a SQLite result code to the NovaVPN taxonomy, preserving the raw code.
ErrorCode classifySqlite(int code) noexcept
{
    switch (code) {
    case SQLITE_OK:
    case SQLITE_ROW:
    case SQLITE_DONE:
        return ErrorCode::Ok;
    case SQLITE_PERM:
    case SQLITE_AUTH:
    case SQLITE_READONLY:
        return ErrorCode::PermissionDenied;
    case SQLITE_BUSY:
    case SQLITE_LOCKED:
        return ErrorCode::Unavailable;
    case SQLITE_NOTFOUND:
        return ErrorCode::NotFound;
    case SQLITE_CONSTRAINT:
        return ErrorCode::AlreadyExists;
    case SQLITE_CORRUPT:
    case SQLITE_NOTADB:
        return ErrorCode::ChecksumMismatch;
    case SQLITE_MISUSE:
    case SQLITE_RANGE:
        return ErrorCode::InvalidArgument;
    case SQLITE_NOMEM:
        return ErrorCode::OutOfMemory;
    case SQLITE_INTERRUPT:
        return ErrorCode::Cancelled;
    default:
        return ErrorCode::IoError;
    }
}

Status sqliteError(sqlite3* handle, int code, std::string_view context)
{
    std::string message{context};
    message.append(": ");
    message.append(sqlite3_errstr(code));
    if (handle != nullptr) {
        if (const char* detail = sqlite3_errmsg(handle);
            detail != nullptr && std::string_view{detail} != sqlite3_errstr(code)) {
            message.append(" (");
            message.append(detail);
            message.push_back(')');
        }
    }
    return Status{classifySqlite(code), std::move(message), static_cast<u32>(code)};
}

// -------------------------------------------------------------------------
// Statement
// -------------------------------------------------------------------------
class SqliteStatement final : public IStatement {
public:
    SqliteStatement(sqlite3* db, sqlite3_stmt* stmt) : m_db(db), m_stmt(stmt) {}

    ~SqliteStatement() override
    {
        if (m_stmt != nullptr) {
            sqlite3_finalize(m_stmt);
        }
    }

    Status bind(int index, const Value& value) override
    {
        int code = SQLITE_OK;
        std::visit(
            [&](const auto& held) {
                using T = std::decay_t<decltype(held)>;
                if constexpr (std::is_same_v<T, std::monostate>) {
                    code = sqlite3_bind_null(m_stmt, index);
                } else if constexpr (std::is_same_v<T, i64>) {
                    code = sqlite3_bind_int64(m_stmt, index, held);
                } else if constexpr (std::is_same_v<T, double>) {
                    code = sqlite3_bind_double(m_stmt, index, held);
                } else if constexpr (std::is_same_v<T, std::string>) {
                    // SQLITE_TRANSIENT: SQLite copies, so the Value may die
                    // before the statement steps.
                    code = sqlite3_bind_text(m_stmt, index, held.data(),
                                             static_cast<int>(held.size()), SQLITE_TRANSIENT);
                } else if constexpr (std::is_same_v<T, std::vector<u8>>) {
                    code = sqlite3_bind_blob(m_stmt, index, held.data(),
                                             static_cast<int>(held.size()), SQLITE_TRANSIENT);
                }
            },
            value);
        if (code != SQLITE_OK) {
            return sqliteError(m_db, code, "bind at index " + std::to_string(index));
        }
        return Status::ok();
    }

    Status bind(std::string_view name, const Value& value) override
    {
        const std::string parameter{name};
        const int index = sqlite3_bind_parameter_index(m_stmt, parameter.c_str());
        if (index == 0) {
            return err::invalidArgument("no such bind parameter: " + parameter);
        }
        return bind(index, value);
    }

    Result<bool> step() override
    {
        const int code = sqlite3_step(m_stmt);
        if (code == SQLITE_ROW) {
            return true;
        }
        if (code == SQLITE_DONE) {
            return false;
        }
        return sqliteError(m_db, code, "step");
    }

    Value column(int index) const override
    {
        switch (sqlite3_column_type(m_stmt, index)) {
        case SQLITE_INTEGER:
            return Value{static_cast<i64>(sqlite3_column_int64(m_stmt, index))};
        case SQLITE_FLOAT:
            return Value{sqlite3_column_double(m_stmt, index)};
        case SQLITE_TEXT: {
            const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(m_stmt, index));
            const int size   = sqlite3_column_bytes(m_stmt, index);
            return Value{std::string{text != nullptr ? text : "",
                                     static_cast<std::size_t>(size)}};
        }
        case SQLITE_BLOB: {
            const auto* data = static_cast<const u8*>(sqlite3_column_blob(m_stmt, index));
            const int size   = sqlite3_column_bytes(m_stmt, index);
            return Value{std::vector<u8>{data, data + size}};
        }
        default:
            return Value{std::monostate{}};
        }
    }

    int columnCount() const override { return sqlite3_column_count(m_stmt); }

    std::string columnName(int index) const override
    {
        const char* name = sqlite3_column_name(m_stmt, index);
        return name != nullptr ? std::string{name} : std::string{};
    }

    Status reset() override
    {
        sqlite3_clear_bindings(m_stmt);
        const int code = sqlite3_reset(m_stmt);
        if (code != SQLITE_OK) {
            return sqliteError(m_db, code, "reset");
        }
        return Status::ok();
    }

private:
    sqlite3*      m_db = nullptr;
    sqlite3_stmt* m_stmt = nullptr;
};

// -------------------------------------------------------------------------
// Transaction
// -------------------------------------------------------------------------
class SqliteTransaction final : public ITransaction {
public:
    explicit SqliteTransaction(sqlite3* db) : m_db(db) {}

    ~SqliteTransaction() override
    {
        // Roll back automatically unless commit() was called - so an early
        // return or a thrown allocation failure can never half-apply a change.
        rollback();
    }

    Status begin()
    {
        return exec("BEGIN IMMEDIATE");
    }

    Status commit() override
    {
        if (m_finished) {
            return err::invalidState("transaction already finished");
        }
        m_finished = true;
        return exec("COMMIT");
    }

    void rollback() noexcept override
    {
        if (m_finished) {
            return;
        }
        m_finished = true;
        char* error = nullptr;
        sqlite3_exec(m_db, "ROLLBACK", nullptr, nullptr, &error);
        if (error != nullptr) {
            sqlite3_free(error);
        }
    }

private:
    Status exec(const char* sql)
    {
        char* error = nullptr;
        const int code = sqlite3_exec(m_db, sql, nullptr, nullptr, &error);
        if (code != SQLITE_OK) {
            Status status = sqliteError(m_db, code, sql);
            if (error != nullptr) {
                sqlite3_free(error);
            }
            return status;
        }
        return Status::ok();
    }

    sqlite3* m_db = nullptr;
    bool     m_finished = false;
};

// -------------------------------------------------------------------------
// Database
// -------------------------------------------------------------------------
class SqliteDatabase final : public IDatabase {
public:
    ~SqliteDatabase() override { close(); }

    Status open(const std::filesystem::path& path) override
    {
        std::lock_guard lock{m_mutex};
        if (m_db != nullptr) {
            return err::invalidState("database already open");
        }

        // SQLite on Windows expects a UTF-8 filename and widens it internally,
        // so convert from the native wide path rather than the ANSI narrowing
        // that path.string() would produce.
        const std::string utf8Path = win::toUtf8(path.wstring());

        int code = sqlite3_open_v2(utf8Path.c_str(), &m_db,
                                   SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        if (code != SQLITE_OK) {
            Status status = sqliteError(m_db, code, "open " + path.string());
            sqlite3_close_v2(m_db);
            m_db = nullptr;
            return status;
        }

        // A concurrent reader (the UI history view) must never block the writer.
        // WAL + a generous busy timeout is what delivers that.
        sqlite3_busy_timeout(m_db, 5000);
        NOVA_RETURN_IF_ERROR(execUnlocked("PRAGMA journal_mode=WAL"));
        NOVA_RETURN_IF_ERROR(execUnlocked("PRAGMA synchronous=NORMAL"));
        NOVA_RETURN_IF_ERROR(execUnlocked("PRAGMA foreign_keys=ON"));

        Status integrity = verifyIntegrityUnlocked();
        if (integrity.isError()) {
            Status status = integrity;
            sqlite3_close_v2(m_db);
            m_db = nullptr;
            return status;
        }

        Status migration = migrateUnlocked();
        if (migration.isError()) {
            sqlite3_close_v2(m_db);
            m_db = nullptr;
            return migration;
        }

        NOVA_LOG_INFO(Channel::Database, "database open")
            .field("path", path.string())
            .field("schema", m_schemaVersion);
        return Status::ok();
    }

    void close() override
    {
        std::lock_guard lock{m_mutex};
        if (m_db != nullptr) {
            // Checkpoint so the WAL does not linger next to the database file.
            sqlite3_wal_checkpoint_v2(m_db, nullptr, SQLITE_CHECKPOINT_TRUNCATE, nullptr,
                                      nullptr);
            sqlite3_close_v2(m_db);
            m_db = nullptr;
        }
    }

    Result<StatementPtr> prepare(std::string_view sql) override
    {
        std::lock_guard lock{m_mutex};
        return prepareUnlocked(sql);
    }

    Status execute(std::string_view sql) override
    {
        std::lock_guard lock{m_mutex};
        return execUnlocked(sql);
    }

    Result<TransactionPtr> beginTransaction() override
    {
        std::lock_guard lock{m_mutex};
        if (m_db == nullptr) {
            return err::invalidState("database not open");
        }
        auto transaction = std::make_unique<SqliteTransaction>(m_db);
        NOVA_RETURN_IF_ERROR(transaction->begin());
        return TransactionPtr{std::move(transaction)};
    }

    i64 lastInsertRowId() const override
    {
        std::lock_guard lock{m_mutex};
        return m_db != nullptr ? sqlite3_last_insert_rowid(m_db) : 0;
    }

    int changes() const override
    {
        std::lock_guard lock{m_mutex};
        return m_db != nullptr ? sqlite3_changes(m_db) : 0;
    }

    int schemaVersion() const override
    {
        std::lock_guard lock{m_mutex};
        return m_schemaVersion;
    }

    Status backupTo(const std::filesystem::path& destination) override
    {
        std::lock_guard lock{m_mutex};
        if (m_db == nullptr) {
            return err::invalidState("database not open");
        }

        sqlite3* target = nullptr;
        int code = sqlite3_open_v2(destination.string().c_str(), &target,
                                   SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        if (code != SQLITE_OK) {
            Status status = sqliteError(target, code, "open backup target");
            sqlite3_close_v2(target);
            return status;
        }

        sqlite3_backup* backup = sqlite3_backup_init(target, "main", m_db, "main");
        if (backup == nullptr) {
            Status status = sqliteError(target, sqlite3_errcode(target), "backup_init");
            sqlite3_close_v2(target);
            return status;
        }

        code = sqlite3_backup_step(backup, -1); // -1 = copy the whole database
        sqlite3_backup_finish(backup);

        Status status = Status::ok();
        if (code != SQLITE_DONE) {
            status = sqliteError(target, code, "backup_step");
        }
        sqlite3_close_v2(target);
        return status;
    }

    Status verifyIntegrity() override
    {
        std::lock_guard lock{m_mutex};
        return verifyIntegrityUnlocked();
    }

private:
    Result<StatementPtr> prepareUnlocked(std::string_view sql)
    {
        if (m_db == nullptr) {
            return err::invalidState("database not open");
        }
        sqlite3_stmt* stmt = nullptr;
        const int code = sqlite3_prepare_v2(m_db, sql.data(), static_cast<int>(sql.size()),
                                            &stmt, nullptr);
        if (code != SQLITE_OK) {
            return sqliteError(m_db, code, "prepare");
        }
        return StatementPtr{std::make_unique<SqliteStatement>(m_db, stmt)};
    }

    Status execUnlocked(std::string_view sql)
    {
        if (m_db == nullptr) {
            return err::invalidState("database not open");
        }
        const std::string statement{sql};
        char* error = nullptr;
        const int code = sqlite3_exec(m_db, statement.c_str(), nullptr, nullptr, &error);
        if (code != SQLITE_OK) {
            Status status = sqliteError(m_db, code, statement);
            if (error != nullptr) {
                sqlite3_free(error);
            }
            return status;
        }
        return Status::ok();
    }

    Status verifyIntegrityUnlocked()
    {
        NOVA_ASSIGN_OR_RETURN(auto statement, prepareUnlocked("PRAGMA integrity_check"));
        NOVA_ASSIGN_OR_RETURN(const bool hasRow, statement->step());
        if (!hasRow) {
            return Status{ErrorCode::IoError, "integrity_check returned no rows"};
        }
        const std::string result = asText(statement->column(0));
        if (result != "ok") {
            return Status{ErrorCode::ChecksumMismatch,
                          "database integrity check failed: " + result};
        }
        return Status::ok();
    }

    int userVersionUnlocked()
    {
        auto statement = prepareUnlocked("PRAGMA user_version");
        if (statement.isError()) {
            return 0;
        }
        auto row = statement.value()->step();
        if (row.isError() || !row.value()) {
            return 0;
        }
        return static_cast<int>(asInt(statement.value()->column(0)));
    }

    Status migrateUnlocked()
    {
        int current = userVersionUnlocked();
        const auto pending = migrations();

        for (const auto& migration : pending) {
            if (migration.version <= current) {
                continue;
            }

            // Each migration is one transaction: a failed upgrade leaves the
            // database at the previous version, never half-migrated.
            auto transaction = std::make_unique<SqliteTransaction>(m_db);
            NOVA_RETURN_IF_ERROR(transaction->begin());
            NOVA_RETURN_IF_ERROR(execUnlocked(migration.sql)
                                     .withContext("migration to v" +
                                                  std::to_string(migration.version)));
            NOVA_RETURN_IF_ERROR(
                execUnlocked("PRAGMA user_version=" + std::to_string(migration.version)));
            NOVA_RETURN_IF_ERROR(transaction->commit());

            NOVA_LOG_INFO(Channel::Database, "applied migration")
                .field("version", migration.version)
                .field("description", std::string{migration.description});
            current = migration.version;
        }

        m_schemaVersion = current;
        if (m_schemaVersion > version::kDatabaseSchema) {
            // The file was written by a newer build. Refusing is safer than
            // silently operating against a schema this binary does not know.
            return Status{ErrorCode::ServiceVersion,
                          "database schema v" + std::to_string(m_schemaVersion) +
                              " is newer than this build supports (v" +
                              std::to_string(version::kDatabaseSchema) + ")"};
        }
        return Status::ok();
    }

    mutable std::mutex m_mutex;
    sqlite3*           m_db = nullptr;
    int                m_schemaVersion = 0;
};

} // namespace

DatabasePtr makeSqliteDatabase()
{
    return std::make_shared<SqliteDatabase>();
}

// --- Value helpers --------------------------------------------------------

i64 asInt(const Value& value, i64 fallback) noexcept
{
    if (const auto* held = std::get_if<i64>(&value)) {
        return *held;
    }
    if (const auto* held = std::get_if<double>(&value)) {
        return static_cast<i64>(*held);
    }
    return fallback;
}

double asDouble(const Value& value, double fallback) noexcept
{
    if (const auto* held = std::get_if<double>(&value)) {
        return *held;
    }
    if (const auto* held = std::get_if<i64>(&value)) {
        return static_cast<double>(*held);
    }
    return fallback;
}

std::string asText(const Value& value, std::string_view fallback)
{
    if (const auto* held = std::get_if<std::string>(&value)) {
        return *held;
    }
    return std::string{fallback};
}

std::vector<u8> asBlob(const Value& value)
{
    if (const auto* held = std::get_if<std::vector<u8>>(&value)) {
        return *held;
    }
    return {};
}

bool isNull(const Value& value) noexcept
{
    return std::holds_alternative<std::monostate>(value);
}

} // namespace nova::db
