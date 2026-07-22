# NovaVPN Architecture

NovaVPN is a Windows 10/11 VPN client built around the OpenVPN protocol, with
per-application split tunnelling, multiple simultaneous tunnels, a
firewall-backed kill switch and a Fluent UI.

This document describes the shape of the system and the rules that keep it
correct. It is the reference every phase is measured against.

---

## 1. Process model

NovaVPN runs as two processes with a hard privilege boundary between them.

```
┌──────────────────────────────┐        ┌──────────────────────────────────┐
│  NovaVPN.exe  (user)         │        │  NovaVPNService.exe  (SYSTEM)    │
│                              │        │                                  │
│  • Fluent UI                 │  named │  • tunnel manager + engines      │
│  • dashboard, profiles       │◄──────►│  • Wintun adapters               │
│  • settings, split-tunnel UI │  pipe  │  • route table ownership         │
│  • notifications, tray       │        │  • WFP filters / kill switch     │
│                              │        │  • split-tunnel callout control  │
│  no privileged capability    │        │  • profile + credential store    │
│                              │        │  • updater                       │
└──────────────────────────────┘        └──────────────────────────────────┘
```

**Why two processes.** Creating a virtual adapter, editing the routing table and
programming WFP all require SYSTEM. Doing that work in the UI would mean either
an elevation prompt for every action or a permanently elevated GUI — a large
attack surface for something that renders untrusted profile names and server
banners. Instead every privileged operation lives in the service, and the UI is
an ordinary user process that asks for things over a named pipe.

**The UI never mutates state directly.** It has no file access to the profile
store, no route API calls, no WFP handle. Every change is a request the service
validates, authorises and applies. This is what makes a standard user unable to
alter what an administrator provisioned.

---

## 2. Module layering

Dependencies point strictly downward. A module may use anything below it and
nothing above it; `nova_add_module()` in `cmake/NovaVpnModule.cmake` encodes
this and the build fails if it is violated.

```
                        ┌──────────────┐
                        │      UI      │   Phase 5
                        └──────┬───────┘
                               │ IPC
                    ┌──────────▼───────────┐
                    │       Services       │   service host + IPC contract
                    └──────────┬───────────┘
        ┌──────────┬───────────┼───────────┬──────────┐
        │          │           │           │          │
   ┌────▼────┐ ┌───▼────┐ ┌────▼─────┐ ┌───▼────┐ ┌───▼─────┐
   │ Tunnel  │ │Firewall│ │SplitTunnel│ │Routing │ │ Updater │
   └────┬────┘ └───┬────┘ └────┬─────┘ └───┬────┘ └───┬─────┘
        │          │           │           │          │
   ┌────▼────┐     │      ┌────▼─────┐     │          │
   │ Driver  │     │      │ Process  │     │          │
   │(Wintun) │     │      │ Registry │     │          │
   └────┬────┘     │      └────┬─────┘     │          │
        └──────────┴───────────┴───────────┴──────────┘
                               │
              ┌────────────────┼────────────────┐
         ┌────▼─────┐    ┌─────▼──────┐   ┌─────▼────┐
         │ Profiles │    │ Networking │   │ Database │
         └────┬─────┘    └─────┬──────┘   └─────┬────┘
              └────────────────┼────────────────┘
                          ┌────▼────┐
                          │  Logs   │
                          └────┬────┘
                          ┌────▼────┐
                          │  Core   │
                          └─────────┘
```

| Module | Responsibility |
| --- | --- |
| `Core` | `Status`/`Result`, secure memory, Win32 error bridging, paths, atomic file I/O, JSON, config, cancellation, event bus |
| `Logs` | structured asynchronous logging, rotating file/event-log/ring sinks |
| `Networking` | IP/CIDR/endpoint value types, resolver and network-monitor contracts, statistics |
| `Database` | SQLite catalogue contract and the migration set |
| `Profiles` | profile model, validation, serialisation, `.ovpn` import/export, credential store |
| `Driver` | Wintun adapter ownership; split-tunnel callout control surface |
| `Tunnel` | tunnel lifecycle, engine plugin ABI, OpenVPN engine |
| `Routing` | routing policy vocabulary + evaluation, Windows route table ownership |
| `Firewall` | WFP policy: kill switch, DNS/IPv6/WebRTC leak protection |
| `SplitTunnel` | per-application routing, process identity, DNS interception |
| `Updater` | signed automatic updates with delta packages |
| `Services` | Windows service host, IPC transport and dispatch |
| `UI` | Fluent dashboard, profile manager, settings |

---

## 3. Error handling

NovaVPN does not throw across module boundaries. Every fallible operation
returns `Status` (no value) or `Result<T>` (value or error).

```cpp
NOVA_ASSIGN_OR_RETURN(auto adapter, driver->createAdapter("NovaVPN", "NovaVPN"));
NOVA_RETURN_IF_ERROR(adapter->setMtu(1420));
```

`ErrorCode` is a stable, append-only taxonomy shared by logs, the IPC contract
and the UI's error surface. Windows failures are translated at the API boundary
by `nova::win::lastError()` / `fromHresult()`, which classify the code and keep
the raw value in `Status::platformCode()` so support can correlate.

Exceptions are reserved for genuinely unrecoverable conditions
(`std::bad_alloc`) and are caught at thread roots.

---

## 4. Routing decision order

Rules are evaluated in a fixed order. The first match decides.

1. **IP rules** — longest matching prefix wins; equal prefixes fall back to
   `priority`.
2. **Domain rules** — longest matching suffix wins; `*.example.com` matches
   sub-domains but *not* the apex, so `*.corp.com` can never capture
   `evilcorp.com`.
3. **Application rules** — an exact image path beats a glob; longer globs beat
   shorter ones.
4. **Default disposition** — the profile's `redirect-gateway` behaviour.

Every decision reports which rule produced it (`RouteDecision::matchedRuleId`),
which is what makes the "why did this app go direct?" diagnostic possible.

Addresses are normalised before matching: `::ffff:10.0.0.1` is folded to
`10.0.0.1`, so an IPv4-mapped address cannot slip past an IPv4 rule.

`PolicyEvaluator` is pure — no OS state — so routing behaviour is fully
unit-testable and reproducible from a log.

---

## 5. Split tunnelling

Three mechanisms cooperate; each covers what the others cannot.

1. **WFP bind/connect redirection.** At `ALE_BIND_REDIRECT` /
   `ALE_CONNECT_REDIRECT`, the callout rewrites the local bind address to the
   tunnel adapter (for tunnelled apps) or the physical adapter (for direct
   apps). Because this happens at socket-creation time, the first packet already
   goes the right way — there is no leak window and nothing has to be re-routed
   after the fact.
2. **Coexisting routing tables.** Binding alone is not enough when the default
   route points into the tunnel. The physical default route is kept alive at a
   higher metric and direct traffic is pinned to it by source address.
3. **DNS interception.** Domain rules are decided on the *name*. Resolver
   answers are captured and converted into short-lived IP rules carrying the
   record's TTL — without this, a CDN-hosted domain rule is unenforceable.

Process identity is the **image path**, not the process name, because names are
trivially spoofed. `includeChildren` walks the parent chain so an app cannot
escape its rule by launching a helper. The PID→path map is maintained from the
ETW process feed rather than by polling, so short-lived processes classify
correctly.

Multi-VPN falls out of this: each `AppBinding` names a `tunnelId`, so
TikTok → Hong Kong, Steam → Japan and Discord → Singapore are simply three
bindings pointing at three live tunnels.

---

## 6. Ordering rules (the leak-free invariants)

These orderings are not stylistic. Each one closes a window through which
traffic could escape.

**Connect**

1. Firewall filters are programmed **before** the tunnel starts.
2. A host route to the VPN gateway is pinned to the underlay adapter **before**
   the default route is captured — otherwise redirecting the default route tears
   down the connection carrying the tunnel.
3. The default route is captured with `0.0.0.0/1` + `128.0.0.0/1` rather than by
   deleting the system default, so a crashed process cannot leave the machine
   offline.
4. DNS is applied to the tunnel interface, and plaintext DNS to anything else is
   blocked.

**Disconnect**

1. IPC stops accepting new work.
2. Tunnels disconnect.
3. Routes are removed.
4. Firewall filters are released **last** — and not at all when the kill switch
   is `hard`.

**Recovery.** Every route and filter NovaVPN creates is recorded. On service
start, `reconcile()` compares the record against live state and removes
leftovers from a crashed run. Hard kill-switch filters are *persistent* WFP
filters, so they survive a reboot and continue to hold.

---

## 7. IPC contract

Transport is a named pipe, `\\.\pipe\NovaVPN.Service`, created by the service
with a DACL granting Users connect access and nothing more.

* **Framing** — 4-byte little-endian length prefix, then UTF-8 JSON. A frame
  larger than 8 MiB is refused on the prefix alone, before any allocation.
* **Handshake** — `Hello` must be first. Major protocol mismatch is refused with
  `ServiceVersion`, which the UI surfaces as "restart to finish updating".
* **Authorisation** — `ipc::requiresAdministrator()` enumerates the methods that
  change machine-wide policy. The service checks the caller's token; the UI's
  opinion is never trusted.
* **Peer verification** — the client verifies the pipe's owner is SYSTEM before
  sending anything, so a squatting process cannot impersonate the service and
  harvest credentials.
* **Events** — the service pushes state changes, statistics ticks and challenges.
  The UI never polls.

---

## 8. Threading

| Thread | Owner | Rule |
| --- | --- | --- |
| Service main | `ServiceHost` | SCM control handling only; never blocks |
| Logger drain | `Logs` | single consumer; sinks are only touched here |
| Tunnel reader | per tunnel | adapter → engine; must never block on I/O |
| Tunnel writer | per tunnel | engine → adapter |
| Engine | per tunnel | protocol state machine; owns its sockets |
| IPC accept | `Services` | one connection thread per client |
| Network monitor | `Networking` | OS change callbacks, marshalled to a queue |

Cancellation is cooperative everywhere: `CancellationToken` is threaded through
every long-running operation, so a disconnect or service stop never has to kill
a thread. Logging is asynchronous and *drops* under pressure rather than
blocking a producer — a dropped-record count is emitted so a gap is always
visible.

---

## 9. Configuration and storage

| Path | Owner | Contents |
| --- | --- | --- |
| `%ProgramData%\NovaVPN\` | service (ACL'd) | config, profiles, database, logs, staged updates |
| `%LocalAppData%\NovaVPN\` | UI | theme, language, window state, UI logs |

The split is a security boundary: anything influencing tunnel behaviour lives
under the machine root, ACL'd so a standard user cannot rewrite it behind the
service's back.

Configuration is layered — compiled defaults ← file ← runtime overrides — and
only the *delta* against the defaults is persisted. A hand-edited or truncated
config degrades to defaults instead of failing the service start, and new
default values reach existing installs on upgrade instead of being frozen by a
stale file.

---

## 10. Plugin ABI

Protocol engines live behind `IVpnEngine`. The tunnel above it deals only in
"packets in, packets out, session facts, state changes", so adding WireGuard,
Shadowsocks, V2Ray or Hysteria2 requires no change above the interface.

Plugins are separate DLLs, so the boundary is C-compatible:

```cpp
extern "C" __declspec(dllexport) nova::u32 NovaVpnEngineAbiVersion();
extern "C" __declspec(dllexport)
    nova::tunnel::IVpnEngine* NovaVpnCreateEngine(const char* engineId);
```

Plugins are Authenticode-verified against the product certificate before
loading. An ABI major-version mismatch is refused.

---

## 11. Phase map

| Phase | Scope | State |
| --- | --- | --- |
| 1 | Architecture, Core, Logs, contracts, service host, tests | **complete** |
| 2 | Resolver, network monitor, route manager | **complete** |
| 3 | Wintun, OpenVPN engine, profile store, SQLite, `.ovpn` parser | pending |
| 4 | WFP callout, process registry, split-tunnel engine | pending |
| 5 | WinUI 3 shell, dashboard, profile manager, settings | pending |
| 6 | Kill switch, DNS/IPv6/WebRTC leak protection, leak tester | pending |
| 7 | Updater | pending |
| 8 | Installer (service, driver, firewall rules, shortcuts) | pending |
| 9 | Integration, stress, leak tests, benchmarks | pending |
| 10 | Optimisation | pending |
