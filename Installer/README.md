# Installer — Phase 8

Produces an MSI (WiX v5) that installs the service, the client and the driver.
The authoring is [`NovaVPN.wxs`](NovaVPN.wxs); build it with
[`build-installer.ps1`](build-installer.ps1).

## Build

WiX v5 installs as a user-local .NET tool — no admin, and free (WiX v7 requires
a paid OSMF licence, so this project pins v5):

```powershell
dotnet tool install --global wix --version 5.0.2
wix extension add -g WixToolset.Firewall.wixext/5.0.2
wix extension add -g WixToolset.Util.wixext/5.0.2
```

Then, after building the service in Release and publishing the self-contained
client:

```powershell
.\Installer\build-installer.ps1
```

This stages `NovaVPNService.exe`, the self-contained `NovaVPN.exe` and
`wintun.dll`, and produces `build\NovaVPN.msi` (~55 MB — the client bundles the
.NET runtime, so no framework install is required on the target).

The produced MSI is validated to carry the correct product metadata and the
`NovaVPNService` service-install entry. For release it must additionally be
Authenticode-signed; a signed build is the CI pipeline's job.

## Original design notes

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
