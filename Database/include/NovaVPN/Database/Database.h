// NovaVPN - Database/Database.h
// SQLite catalogue contract.
//
// What lives in the database:
//   profiles          - the profile model, minus secrets
//   profile_blobs     - the encrypted .ovpn source, DPAPI-machine sealed
//   routing_rules     - IP, domain, application and country rules
//   split_tunnel_apps - the app checkbox list plus cached icons
//   connection_log    - one row per connection attempt, for the history view
//   traffic_daily     - per-profile daily rollups for the statistics page
//   settings          - service-scope key/value overrides
//   schema_version    - migration bookkeeping
//
// What deliberately does not: passwords, private keys, TLS wrap keys. Those are
// Credential Manager entries referenced by target name (docs/SECURITY.md).
//
// Implemented in Phase 3.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/Types.h>

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace nova::db {

/// A value bound into a statement or read out of a row.
using Value = std::variant<std::monostate, i64, double, std::string, std::vector<u8>>;

class IStatement {
public:
    virtual ~IStatement() = default;

    [[nodiscard]] virtual Status bind(int index, const Value& value) = 0;
    [[nodiscard]] virtual Status bind(std::string_view name, const Value& value) = 0;

    /// Advances to the next row. Returns true while a row is available.
    [[nodiscard]] virtual Result<bool> step() = 0;

    [[nodiscard]] virtual Value column(int index) const = 0;
    [[nodiscard]] virtual int columnCount() const = 0;
    [[nodiscard]] virtual std::string columnName(int index) const = 0;

    [[nodiscard]] virtual Status reset() = 0;
};

using StatementPtr = std::unique_ptr<IStatement>;

/// RAII transaction. Rolls back on destruction unless commit() was called, so
/// an early return or a thrown allocation failure can never half-apply a
/// policy change.
class ITransaction {
public:
    virtual ~ITransaction() = default;
    [[nodiscard]] virtual Status commit() = 0;
    virtual void rollback() noexcept = 0;
};

using TransactionPtr = std::unique_ptr<ITransaction>;

class IDatabase {
public:
    virtual ~IDatabase() = default;

    /// Opens (creating if needed) and runs migrations up to the compiled schema
    /// version. WAL journalling and a busy timeout are configured here so a
    /// concurrent reader (the UI's history view) never blocks the service.
    [[nodiscard]] virtual Status open(const std::filesystem::path& path) = 0;
    virtual void close() = 0;

    [[nodiscard]] virtual Result<StatementPtr> prepare(std::string_view sql) = 0;
    [[nodiscard]] virtual Status execute(std::string_view sql) = 0;
    [[nodiscard]] virtual Result<TransactionPtr> beginTransaction() = 0;

    [[nodiscard]] virtual i64 lastInsertRowId() const = 0;
    [[nodiscard]] virtual int changes() const = 0;

    [[nodiscard]] virtual int schemaVersion() const = 0;

    /// Online backup to `destination`, used by the support-bundle exporter and
    /// before every schema migration.
    [[nodiscard]] virtual Status backupTo(const std::filesystem::path& destination) = 0;

    /// PRAGMA integrity_check. Run at start; a corrupt database is quarantined
    /// and recreated rather than crashing the service.
    [[nodiscard]] virtual Status verifyIntegrity() = 0;
};

using DatabasePtr = std::shared_ptr<IDatabase>;

/// One schema migration. Migrations are append-only and never edited once
/// shipped; the pair (version, sql) is what makes an upgrade reproducible.
struct Migration {
    int              version = 0;
    std::string_view description;
    std::string_view sql;
};

/// The full migration list, ordered by version.
[[nodiscard]] std::span<const Migration> migrations() noexcept;

} // namespace nova::db
