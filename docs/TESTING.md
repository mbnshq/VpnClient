# NovaVPN Testing

The suite is one binary, `novavpn_unit_tests`, split by Catch2 tags into five
dimensions. A normal run executes everything except the hidden benchmark and
elevation-gated cases.

```powershell
.\scripts\build.ps1 -Preset ninja-debug -Test      # build + run via CTest
.\build\ninja-debug\bin\novavpn_unit_tests.exe      # run directly
.\build\ninja-debug\bin\novavpn_unit_tests.exe "[routing]"   # one area
```

## Dimensions

| Dimension | Tag(s) | What it covers |
| --- | --- | --- |
| Unit | (default) | every module's logic in isolation — errors, types, secure memory, config, IP/CIDR, routing, profiles, `.ovpn` parser, DB, credentials, DPAPI, IPC protocol, engine registry, tunnel manager, updater crypto, firewall/leak modes, split-tunnel classifier |
| Concurrency stress | `[stress]` | the real primitives under many threads, with deterministic count/final-state assertions — EventBus publish/subscribe churn, logger flood accounting, ConfigStore readers/writers, cancellation contention, IPC with 24 concurrent clients |
| Integration | `[integration]` | cross-subsystem paths — import → store → connect through the tunnel manager; split-tunnel and routing agreeing on the same rules; database round-trip across reopen |
| Robustness / fuzz | `[robustness]` | ~200k adversarial and random inputs to every untrusted-input surface (`.ovpn`, IP/CIDR/endpoint, JSON, IPC frames, UUID) — must never crash, hang or read out of bounds, always a definite verdict |
| Benchmarks | `[!benchmark]` (hidden) | micro-benchmarks for the hot paths (IP parse, routing eval, IPC framing, JSON) |

## Elevation-gated tests

Tests that touch real privileged kernel state are tagged `[.integration]`
(hidden by default) and skip themselves when not elevated. Run them from an
elevated shell:

```powershell
novavpn_unit_tests.exe "[.integration]" --success
```

They create a **real Wintun adapter** (assigning an address, starting a
session, tearing it down) and apply and clear **real WFP firewall filters** —
so the driver and kill-switch paths are verified against the actual OS, not a
mock.

## Running the benchmarks

```powershell
novavpn_unit_tests.exe "[!benchmark]" --benchmark-samples 50
```

Representative results (Release, MSVC 19.44): IPv4 parse ~43 ns, IPv6 parse
~71 ns, routing decision against 64 rules ~87 ns.

## Sanitizers

The `ninja-asan` preset builds with AddressSanitizer, under which the
concurrency-stress tests double as a race / use-after-free detector. It requires
the x64 ASan runtime component of the MSVC toolchain to be installed.

## Coverage snapshot

298 test cases, ~85,500 assertions, green in Debug and Release (the latter with
`/W4 /WX` and LTO), plus the elevation-gated real-adapter and real-WFP tests.
