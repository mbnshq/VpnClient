# The OpenVPN Engine

NovaVPN's OpenVPN support is an adapter over **OpenVPN3 Core**
(`openvpn::ClientAPI::OpenVPNClient`), the same open-source protocol engine that
underpins OpenVPN Connect. NovaVPN contains no proprietary OpenVPN client code —
the engine is the upstream library, wrapped behind NovaVPN's `IVpnEngine` ABI.

The engine is **opt-in** because it compiles OpenVPN3 Core and pulls in a native
dependency set (OpenSSL, asio, lz4, fmt). The rest of the product builds, links
and tests without it; when it is absent, `makeOpenVpnEngine()` returns
`NotImplemented` and the service simply reports no OpenVPN engine.

---

## Building with the engine

Dependencies come from **vcpkg**; OpenVPN3 Core itself is fetched at configure
time, pinned by commit.

### 1. Bootstrap vcpkg (once)

```powershell
git clone https://github.com/microsoft/vcpkg.git
.\vcpkg\bootstrap-vcpkg.bat -disableMetrics
```

No administrator rights are required. vcpkg acquires its own NASM and Perl to
build OpenSSL, so those tools do not need to be installed on the machine.

### 2. Install the dependencies (static, to match NovaVPN's `/MT` CRT)

```powershell
.\vcpkg\vcpkg.exe install openssl asio lz4 xxhash fmt jsoncpp tap-windows6 --triplet x64-windows-static
```

### 3. Configure NovaVPN with the engine enabled

```powershell
cmake --preset ninja-release `
  -DNOVAVPN_BUILD_OPENVPN_ENGINE=ON `
  -DCMAKE_TOOLCHAIN_FILE=<path>\vcpkg\scripts\buildsystems\vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build --preset ninja-release
```

The build fetches OpenVPN3 Core at the pinned commit (see
`cmake/Dependencies.cmake`) and compiles its ClientAPI into a dedicated
`novavpn_openvpn_engine` target.

---

## How it is wired

OpenVPN3 Core is not a standalone library — its own build documents that too
much depends on per-target compile flags and `#define`s, so consumers compile
the ClientAPI sources (`client/ovpncli.cpp`, `openvpn/crypto/data_epoch.cpp`)
into their own target. NovaVPN does exactly that in `Tunnel/CMakeLists.txt`,
with OpenVPN3's build recipe:

* defines `ASIO_STANDALONE USE_ASIO HAVE_LZ4 USE_OPENSSL`, Windows
  `_WIN32_WINNT=0x0600`, `TAP_WIN_COMPONENT_ID=tap0901`,
  `ASIO_DISABLE_LOCAL_SOCKETS`;
* MSVC `/bigobj` and relaxed warnings (`/W3 /wd4200 /wd4146`) — the OpenVPN3
  headers do not build under NovaVPN's `/W4 /WX`.

Two boundaries are deliberate:

* **The strict warning flags stop at this target.** `novavpn_openvpn_engine`
  does not use `nova::warnings`, and it pulls the NovaVPN headers it needs as
  *include directories only* rather than by linking `nova::core` — linking it
  would drag in `nova::hardening`'s `_WIN32_WINNT=0x0A00`, which conflicts with
  the `0x0600` baseline OpenVPN3's Windows tun code requires. As a static
  library the target needs no nova symbols at build time; they resolve when the
  final executable links `nova::core` through `novavpn_tunnel`.
* **No OpenVPN3 type crosses `IVpnEngine`.** `OpenVpnEngine.cpp` is the only
  translation unit that includes `ovpncli.hpp`; everything above it sees only
  NovaVPN types.

The engine registers itself as the built-in `openvpn` engine via
`registerOpenVpnEngine()`, which the service calls at startup. In a build
without the engine, the stub's `registerOpenVpnEngine()` is a successful no-op,
so the startup path is identical either way.

---

## What the adapter maps

| NovaVPN `IVpnEngine` | OpenVPN3 `OpenVPNClient` |
| --- | --- |
| `validate(profile)` | `OpenVPNClientHelper::eval_config` on the profile's `.ovpn` source |
| `start(config, host, token)` | `eval_config` + `provide_creds` + `connect()` on a worker thread |
| `stop()` | `stop()`, then join the worker |
| event callbacks | `event()` → `ConnectionState` + session facts via `connection_info()` |
| `renegotiate()` | `reconnect(0)` |
| cancellation token | `stop()` on cancel, unblocking `connect()` |

`connect()` blocks until the session ends, so it runs on a dedicated
`NovaVPN.OpenVPN` thread; OpenVPN3's event callbacks are marshalled onto the
NovaVPN `EngineHost` without blocking.

---

## Verification status

* **Build**: OpenVPN3 Core compiles and links cleanly into NovaVPN on
  MSVC 19.44 / Windows SDK 10.0.22621 with the vcpkg static triplet.
* **Validation**: verified against OpenVPN3's own `eval_config` — a well-formed
  profile validates, an empty or malformed one is rejected. No server needed.
* **Live tunnel**: establishing a real session requires an OpenVPN server and an
  elevated service host. The connect/event/teardown path is implemented against
  the ClientAPI but is exercised end-to-end only in that environment.
