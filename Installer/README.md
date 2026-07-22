# Installer — Phase 8

Produces a signed MSI (WiX) plus a small bootstrapper for the update path.

## What it installs

| Component | Destination | Notes |
| --- | --- | --- |
| `NovaVPNService.exe` | `%ProgramFiles%\NovaVPN\` | registered as an auto-start service with a **quoted** binary path |
| `NovaVPN.exe` | `%ProgramFiles%\NovaVPN\` | the UI |
| `wintun.dll` | `%ProgramFiles%\NovaVPN\` | loaded dynamically, signature-verified at runtime |
| Split-tunnel callout driver | driver store | WHQL-signed; installed via the driver package |
| Machine data root | `%ProgramData%\NovaVPN\` | created with the protected DACL (SYSTEM + Administrators full, Users read/execute) |
| Firewall rules | Windows Firewall | inbound rules for the service, so a default-deny profile does not silently break reconnection |
| Shortcuts | Start menu, optional desktop | |
| Licences | `%ProgramFiles%\NovaVPN\licenses\` | third-party attribution |

## Requirements

* Per-machine install only. A per-user install cannot register a service or
  install a driver, and a mixed model would leave the kill switch unowned.
* Every shipped binary is Authenticode-signed with the product certificate; the
  driver additionally carries a WHQL attestation signature.
* Uninstall must unwind network state before removing files: stop the service,
  clear WFP filters (including persistent ones), remove owned routes, delete
  adapters. An uninstall that leaves a hard kill switch in place would take the
  machine offline permanently.
* Upgrade preserves `%ProgramData%\NovaVPN\`; uninstall offers to remove it,
  defaulting to keeping profiles.
