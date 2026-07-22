# NovaVPN Security Model

A VPN client is a privileged network product. It installs a driver, runs as
SYSTEM, edits the routing table, holds credentials and private keys, and ships
signed updates. This document states what NovaVPN defends against, what it
does not, and the rules the code follows.

---

## 1. Threat model

**In scope**

| Adversary | Concern |
| --- | --- |
| Local unprivileged user | escalating to SYSTEM via the service, the pipe, the installer or an unquoted path |
| Malicious application | escaping split-tunnel confinement; reading credentials out of NovaVPN's memory or files |
| Network attacker on the underlay | MITM of the tunnel handshake; MITM of the update channel |
| Hostile or compromised VPN server | pushing routes/DNS that redirect traffic; exploiting the config parser |
| Someone with the machine's disk | reading stored profiles, keys and passwords offline |
| Observer on the local network | learning that a VPN is in use, or seeing DNS/IPv6/WebRTC leaks |

**Out of scope**

* An attacker who is already SYSTEM or has kernel code execution.
* A compromised OS, hypervisor or firmware.
* Traffic analysis against a correctly functioning tunnel (obfuscation is a
  plugin concern, not a client guarantee).
* Physical attacks against a running machine (cold boot, DMA).

---

## 2. Secrets

**Rule: a secret exists in exactly one place, for the shortest possible time.**

| Secret | Where it lives | Lifetime in memory |
| --- | --- | --- |
| Account password | Windows Credential Manager, machine scope | handshake only |
| Private key | Credential Manager, or the Windows cert store / smart card | handshake only |
| TLS wrap key (`tls-auth`/`tls-crypt`) | Credential Manager | session |
| TOTP code | never stored | seconds |
| Session keys | engine memory | session, renegotiated periodically |

The database and profile documents hold **credential target names**, never
credential material. `toJson(profile, includeSecrets=false)` — the export path —
strips even those, so a shared profile cannot carry another user's key
references.

`SecureBuffer` / `SecureString` back every secret:

* `VirtualAlloc` + `VirtualLock` — keeps pages out of the pagefile.
* `RtlSecureZeroMemory` before release — the compiler may not elide it.
* Move-only — a secret has exactly one owner; copying requires an explicit
  `clone()`.
* `constantTimeEquals` for every comparison, so a token check cannot leak its
  contents through timing.

Logging can never print a secret: `RecordBuilder::secret()` emits a redacted
fingerprint (`ab****yz`) regardless of the redaction setting.

---

## 3. Privilege boundary

The service runs as SYSTEM; the UI does not. The boundary is the named pipe.

* The pipe DACL grants **Users** connect access only. No other rights, no
  `WRITE_DAC`, no `WRITE_OWNER`.
* The service impersonates the caller to read its token and checks group
  membership. `ipc::requiresAdministrator()` enumerates the privileged methods:
  every policy mutation (firewall, routing, split tunnel, settings) and every
  profile mutation, because a profile determines where traffic goes and which
  certificates are trusted.
* The client verifies the pipe's **owner is SYSTEM** before transmitting. Without
  this, a process that squats the pipe name at boot could impersonate the
  service and harvest credentials.
* Frames are length-prefixed and capped at 8 MiB; an oversized announcement is
  rejected on the prefix, before allocation.
* Unknown method and event values are rejected rather than cast into the enum —
  casting an out-of-range integer into an enum is undefined behaviour and could
  land on a privileged handler.

**Installation hardening**

* The service binary path is registered **quoted** (unquoted service paths with
  spaces are a classic escalation).
* `%ProgramData%\NovaVPN` is created with a protected DACL: SYSTEM and
  Administrators full, Users read/execute. A standard user cannot swap a profile
  or a staged update out from under the service.
* `wintun.dll` is loaded with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` and its
  Authenticode signature is verified before first use, so a planted DLL beside
  the working directory cannot run as SYSTEM.

---

## 4. Process hardening

`hardenProcessAgainstDumps()` runs at startup in both processes:

* `ProcessDynamicCodePolicy` — prohibit dynamic code generation where the host
  allows it.
* `ProcessExtensionPointDisablePolicy` — block legacy injection vectors
  (AppInit DLLs, hooks, IMEs).
* `ProcessImageLoadPolicy` — no remote images, no low-IL images.
* Error-mode changes that keep locked secret pages out of automatic crash dumps.

Compiler and linker mitigations are applied to every first-party target through
`nova::hardening`: `/GS`, `/guard:cf`, `/Qspectre`, `/DYNAMICBASE`, `/NXCOMPAT`,
`/HIGHENTROPYVA`, `/GUARD:CF`.

---

## 5. Network protection

**Kill switch**

| Mode | Behaviour |
| --- | --- |
| `Off` | no filters; traffic falls back to the ISP if the tunnel drops |
| `Soft` | non-tunnel traffic blocked while a tunnel is up or reconnecting; released on user disconnect |
| `Hard` | blocked from client start until explicitly disabled, **including across reboots and crashes** (persistent WFP filters) |

Filters live under one NovaVPN provider and sublayer with fixed GUIDs, so every
filter is attributable and removable in one sweep, and a crashed service leaves
a state the next start can reconcile.

Policy is applied in a single WFP transaction: either every filter lands or none
do. A half-applied policy is a leak.

**Leak protection**

* **DNS** — plaintext DNS to anything but the tunnel's resolvers is blocked.
  DoH/DoT are supported per profile.
* **IPv6** — blocked by default. A v6 leak around a v4-only tunnel is the single
  most common VPN leak.
* **WebRTC** — STUN/TURN discovery outside the tunnel is blocked. Deliberately
  narrow: it targets the candidate-discovery ports, not all UDP.
* **Route protection** — every owned route is recorded and reconciled on start.

Each exception (`allowLan`, `allowLocalDiscovery`, `bypassApplications`, …) is a
deliberate hole, surfaced in the UI with its consequence spelled out and logged
when in force.

---

## 6. Server trust

A profile that can authenticate no server is rejected by `Profile::validate()`:
without a CA chain **or** a pinned SHA-256 peer fingerprint, the tunnel would
accept any peer — an unauthenticated pipe wearing a VPN costume.

* `verify-x509-name` is preserved from the imported config; an import that would
  *remove* a verification directive is reported as a rejected directive, not
  silently accepted.
* Compression is **off** unless a profile explicitly opts in: LZO/LZ4 inside a
  VPN is a known plaintext oracle (VORACLE).
* Pushed routes and DNS are validated against the policy before being applied; a
  hostile server cannot push a route that captures traffic the policy says is
  direct.

---

## 7. Update channel

The updater runs as SYSTEM and installs code, so it is the highest-value target
in the product.

1. Manifest fetched over TLS with certificate pinning.
2. Manifest signature verified against a public key **compiled into the binary**,
   before a single field is interpreted.
3. Package hash taken from the verified manifest — never from a response header.
4. Package Authenticode-verified against the product certificate.
5. Deltas applied to a *copy*; the result is hash-checked against the manifest's
   full-image hash before anything is replaced.
6. Downgrades refused unless policy explicitly allows them.

---

## 8. Input validation

Everything crossing a trust boundary is parsed defensively.

* **`.ovpn` files** — untrusted. Directives that would weaken security
  (`script-security`, external command execution, insecure ciphers) are rejected
  and reported in the import summary rather than silently dropped.
* **IPv4 literals** — leading zeros are rejected. `010.0.0.1` is octal to some
  resolvers and decimal to others; that ambiguity has produced real SSRF and
  ACL-bypass bugs.
* **IPv4-mapped IPv6** — normalised before rule matching, so `::ffff:10.0.0.1`
  cannot bypass a rule for `10.0.0.0/8`.
* **Domain wildcards** — `*.corp.com` matches sub-domains only, never the apex
  and never `evilcorp.com`.
* **File names** — `paths::sanitizeFileName()` strips reserved characters, DOS
  device names and trailing dots; `paths::isContainedIn()` blocks traversal in
  imported profiles and update payloads.
* **Glob matching** — iterative with backtracking, never recursive, so a hostile
  pattern in a routing rule cannot blow the stack.

---

## 9. Reporting a vulnerability

Report security issues privately to the maintainers rather than through a public
issue. Include a description, affected version, and reproduction steps. Please
allow reasonable time for a fix before disclosure.
