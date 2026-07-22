#include <NovaVPN/Database/Database.h>

#include <array>

namespace nova::db {
namespace {

/// v1 - initial schema.
///
/// Notes on the shape:
///   * `profiles.id` is a UUID text primary key, not a rowid alias, because a
///     profile id travels over IPC and into exported bundles; a rowid would be
///     ambiguous across installs.
///   * secrets are absent by construction - `credential_target` is a Credential
///     Manager target name, never a blob.
///   * `profile_blobs.payload` holds the DPAPI-machine-sealed .ovpn source, so
///     even a stolen database file yields nothing without the machine key.
///   * every rule table carries `priority` and `created_at` so the evaluation
///     order documented in ARCHITECTURE.md is reproducible.
constexpr std::string_view kV1 = R"SQL(
CREATE TABLE profiles (
    id                  TEXT PRIMARY KEY NOT NULL,
    name                TEXT NOT NULL UNIQUE,
    engine              TEXT NOT NULL DEFAULT 'openvpn',
    engine_id           TEXT NOT NULL DEFAULT '',
    auth_method         TEXT NOT NULL,
    credential_target   TEXT NOT NULL DEFAULT '',
    user_name           TEXT NOT NULL DEFAULT '',
    save_password       INTEGER NOT NULL DEFAULT 0,
    requires_totp       INTEGER NOT NULL DEFAULT 0,
    document            TEXT NOT NULL,          -- profile JSON without secrets
    source_hash         TEXT NOT NULL DEFAULT '',
    country             TEXT NOT NULL DEFAULT '',
    city                TEXT NOT NULL DEFAULT '',
    favorite            INTEGER NOT NULL DEFAULT 0,
    image_ref           TEXT NOT NULL DEFAULT '',
    created_at          INTEGER NOT NULL,
    modified_at         INTEGER NOT NULL,
    last_connected_at   INTEGER NOT NULL DEFAULT 0,
    connect_count       INTEGER NOT NULL DEFAULT 0,
    total_bytes_sent    INTEGER NOT NULL DEFAULT 0,
    total_bytes_recv    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_profiles_favorite  ON profiles(favorite, name);
CREATE INDEX idx_profiles_recent    ON profiles(last_connected_at DESC);
CREATE INDEX idx_profiles_country   ON profiles(country, name);

CREATE TABLE profile_tags (
    profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    tag         TEXT NOT NULL,
    PRIMARY KEY (profile_id, tag)
);
CREATE INDEX idx_profile_tags_tag ON profile_tags(tag);

CREATE TABLE profile_blobs (
    profile_id  TEXT PRIMARY KEY NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    payload     BLOB NOT NULL,      -- DPAPI(machine)-sealed .ovpn source
    payload_len INTEGER NOT NULL,
    sealed_at   INTEGER NOT NULL
);

CREATE TABLE routing_rules (
    id              TEXT PRIMARY KEY NOT NULL,
    kind            TEXT NOT NULL,          -- ip | domain | application | country
    name            TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    priority        INTEGER NOT NULL DEFAULT 0,
    disposition     TEXT NOT NULL,          -- tunnel | direct | block
    tunnel_id       TEXT NOT NULL DEFAULT '',
    match_value     TEXT NOT NULL,          -- CIDR, pattern, path or country code
    match_port      INTEGER,
    match_transport TEXT,
    notes           TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL
);
CREATE INDEX idx_routing_rules_kind ON routing_rules(kind, enabled, priority DESC);

CREATE TABLE split_tunnel_apps (
    image_path       TEXT PRIMARY KEY NOT NULL COLLATE NOCASE,
    display_name     TEXT NOT NULL DEFAULT '',
    publisher        TEXT NOT NULL DEFAULT '',
    enabled          INTEGER NOT NULL DEFAULT 1,
    tunnel_id        TEXT NOT NULL DEFAULT '',
    include_children INTEGER NOT NULL DEFAULT 1,
    is_packaged      INTEGER NOT NULL DEFAULT 0,
    package_family   TEXT NOT NULL DEFAULT '',
    icon_png         BLOB,
    added_at         INTEGER NOT NULL
);

CREATE TABLE connection_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      TEXT NOT NULL,
    tunnel_id       TEXT NOT NULL DEFAULT '',
    session_id      TEXT NOT NULL DEFAULT '',
    started_at      INTEGER NOT NULL,
    connected_at    INTEGER,
    ended_at        INTEGER,
    end_reason      TEXT NOT NULL DEFAULT '',
    error_code      INTEGER NOT NULL DEFAULT 0,
    remote_endpoint TEXT NOT NULL DEFAULT '',
    local_address   TEXT NOT NULL DEFAULT '',
    cipher          TEXT NOT NULL DEFAULT '',
    bytes_sent      INTEGER NOT NULL DEFAULT 0,
    bytes_recv      INTEGER NOT NULL DEFAULT 0,
    attempts        INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_connection_log_profile ON connection_log(profile_id, started_at DESC);
CREATE INDEX idx_connection_log_time    ON connection_log(started_at DESC);

CREATE TABLE traffic_daily (
    profile_id  TEXT NOT NULL,
    day         INTEGER NOT NULL,       -- days since the Unix epoch, UTC
    bytes_sent  INTEGER NOT NULL DEFAULT 0,
    bytes_recv  INTEGER NOT NULL DEFAULT 0,
    seconds     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (profile_id, day)
);

CREATE TABLE settings (
    key         TEXT PRIMARY KEY NOT NULL,
    value       TEXT NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE owned_routes (
    destination      TEXT NOT NULL,
    interface_index  INTEGER NOT NULL,
    next_hop         TEXT NOT NULL DEFAULT '',
    metric           INTEGER NOT NULL DEFAULT 0,
    tunnel_id        TEXT NOT NULL DEFAULT '',
    created_at       INTEGER NOT NULL,
    PRIMARY KEY (destination, interface_index)
);
)SQL";

constexpr std::array<Migration, 1> kMigrations{
    Migration{1, "initial schema", kV1},
};

} // namespace

std::span<const Migration> migrations() noexcept
{
    return std::span<const Migration>{kMigrations};
}

} // namespace nova::db
