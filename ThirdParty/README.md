# ThirdParty

## Policy

Dependencies are acquired in one of two ways, and the choice is deliberate:

**Fetched at configure time** (`cmake/Dependencies.cmake`) — pinned to a release
URL with a SHA-256 hash. Reproducible, auditable, and nothing binary is
committed. This is the default.

| Dependency | Version | Used for | Licence |
| --- | --- | --- | --- |
| nlohmann/json | 3.11.3 | config, profiles, IPC wire format, update manifest | MIT |
| Catch2 | 3.5.2 | tests only | BSL-1.0 |

**Vendored here** — only when upstream ships no usable release archive, or when
the artifact must be signed and shipped inside the installer.

| Dependency | Phase | Notes |
| --- | --- | --- |
| Wintun | 3 | `wintun.dll` + header. Redistributable; loaded dynamically and Authenticode-verified before first use. Not committed — the packaging step fetches and verifies it. |
| OpenSSL | 3 | Static libraries for the OpenVPN engine. Built from source by the packaging pipeline so the exact configuration is known. |
| OpenVPN | 3 | Protocol engine. Used as the upstream open-source implementation; no proprietary client code is included. |
| SQLite | 3 | Amalgamation (`sqlite3.c` / `sqlite3.h`), vendored because upstream ships an amalgamation rather than a package. |

`NOVAVPN_OFFLINE=ON` turns every fetch into a hard error, which is how the
release pipeline proves it consumed only the pre-populated cache.

## Licence obligations

Every third-party licence is reproduced verbatim in the installed
`licenses/` directory and surfaced in the UI's About page. Attribution is a
shipping requirement, not an afterthought.
