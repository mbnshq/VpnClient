# NovaVPN

A commercial-grade Windows VPN client for Windows 10 and 11 — OpenVPN protocol
support with per-application split tunnelling, multiple simultaneous tunnels, a
firewall-backed kill switch and a modern Fluent interface.

NovaVPN is an original implementation. It uses the open-source OpenVPN protocol
engine and Wintun, and contains no proprietary third-party client code.

---

## What it does

**Connection**
Connect / disconnect, `.ovpn` import and profile export, certificate and
username/password authentication, TOTP, auto-connect, auto-reconnect with
back-off, connection timer, live upload/download rates, VPN and ISP addresses,
ping, packet loss and a latency graph.

**Split tunnelling** — per-application routing built into the product. No
Proxifier, no third-party routing shim.

```
☑ TikTok LIVE Studio   → Hong Kong
☑ WhatsApp             → Hong Kong
☐ Chrome               → direct (ISP)
☐ Steam                → Japan
☑ Discord              → Singapore
```

Rules can also be written against domains (`*.tiktok.com → VPN`,
`*.youtube.com → Direct`), IP ranges (individual addresses, CIDR, country
blocks), or any combination. Multiple tunnels run at once and each application
can use a different one.

**Protection** — soft / hard / firewall-backed kill switch surviving reboot, DNS
leak protection, DoH and DoT, custom DNS, IPv6 leak protection, WebRTC leak
protection, and an active leak tester.

**Management** — unlimited profiles with country, tags, notes, favourites,
images and usage history; a process manager showing per-application traffic and
the tunnel each one uses; detailed searchable logs; signed automatic updates.

---

## Status

Development is phased. **Phase 1 (architecture) is complete**: the module
layout, the foundation layer, the logging pipeline, every subsystem contract,
the Windows service host, the IPC protocol and a 127-case unit test suite all
build and pass.

| Phase | Scope | State |
| --- | --- | --- |
| 1 | Architecture, `Core`, `Logs`, contracts, service host, tests | ✅ complete |
| 2 | Core networking: resolver, network monitor, route manager | ✅ complete |
| 3 | VPN engine: Wintun, OpenVPN, profile store, SQLite, `.ovpn` parser | pending |
| 4 | Split tunnel engine: WFP callout, process registry, DNS interception | pending |
| 5 | UI: WinUI 3 shell, dashboard, profile manager, settings | pending |
| 6 | Firewall: kill switch, leak protection, leak tester | pending |
| 7 | Updater | pending |
| 8 | Installer | pending |
| 9 | Integration, stress, leak tests, benchmarks | pending |
| 10 | Optimisation | pending |

What builds today:

```
novavpn_core        Status/Result, secure memory, paths, atomic I/O, JSON, config,
                    cancellation, event bus, Win32 error bridging
novavpn_logs        asynchronous structured logging; file/event-log/console/ring sinks
novavpn_networking  IP/CIDR/endpoint types, network monitor (adapters, default
                    routes, change notification), scope-pinned DNS resolver
novavpn_routing     policy vocabulary + evaluation; route-table manager with a
                    crash-recovery ledger, gateway pinning and default capture
novavpn_profiles    profile model, validation and serialisation
novavpn_services    IPC protocol, Windows service host
NovaVPNService.exe  the service - runs live: monitors the network, reconciles
                    routes on start, unwinds them on stop
novavpn_unit_tests  152 test cases, 3866 assertions
```

---

## Build

```powershell
.\scripts\build.ps1 -Preset ninja-debug -Test
```

Full instructions, presets and options: [docs/BUILD.md](docs/BUILD.md).

## Documentation

| Document | Contents |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | process model, module layering, ordering invariants, IPC, threading |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, secret handling, privilege boundary, leak protection |
| [docs/BUILD.md](docs/BUILD.md) | prerequisites, presets, options, troubleshooting |

## Requirements

* Windows 10 21H2 (build 19044) or later, x64
* Visual Studio 2022 (or Build Tools) with the C++ workload
* Windows SDK 10.0.22621.0 or later
* CMake 3.24+

## Licence

MIT — see [LICENSE](LICENSE). Third-party components keep their own licences;
the OpenVPN engine is GPLv2 and is kept separable through the plugin ABI so each
licence can be honoured independently. Attribution is listed in
[ThirdParty/README.md](ThirdParty/README.md).

## Repository layout

```
Core/          foundation: errors, secure memory, config, paths, JSON
Logs/          structured asynchronous logging
Networking/    address types, resolver and monitor contracts, statistics
Database/      SQLite catalogue contract and migrations
Profiles/      profile model, store and credential contracts
Driver/        Wintun adapter ownership
Tunnel/        tunnel lifecycle and the engine plugin ABI
Routing/       routing policy and Windows route ownership
Firewall/      WFP policy: kill switch and leak protection
SplitTunnel/   per-application routing and process identity
Updater/       signed updates with delta packages
Services/      Windows service host and the UI↔service IPC contract
Tests/         unit tests
cmake/         build helpers
docs/          architecture, security, build
scripts/       developer tooling
```
