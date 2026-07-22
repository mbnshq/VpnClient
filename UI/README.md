# UI — Phase 5

The NovaVPN desktop client: `NovaVPN.exe`, an ordinary user-privilege process
that talks to the service over the named pipe described in
[../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md).

The implementation lives in [NovaVpn.App/](NovaVpn.App/) — see its
[README](NovaVpn.App/README.md) for build and structure.

## Framework decision

**WPF on .NET 9** (implemented). WinUI 3 was the original target, but its build
requires Visual Studio's UWP/MSIX workload (the PRI/Appx MSBuild tasks), which is
not part of a Build Tools installation and cannot be driven from the command
line — so per the brief's own fallback clause, the client is WPF. It is still a
native Windows app and uses .NET 9's built-in Windows 11 Fluent theme; the
choice costs nothing architecturally because the UI performs no networking of
its own — it drives the SYSTEM service over the named-pipe IPC, so the framework
never touches a socket.

Networking integration is not a constraint on this choice: the UI performs no
networking. It sends IPC requests and renders the events the service pushes, so
the framework never touches a socket, an adapter or a WFP handle.

The fallback recorded in the brief — WPF on .NET 8 with a native C++ backend —
remains viable and would reuse the same IPC contract unchanged, since the
contract is JSON over a pipe rather than a C++ ABI. It is held in reserve for
the case where the Windows App SDK's deployment model proves unworkable for
per-machine installation alongside a service.

## Planned surface

| Screen | Contents |
| --- | --- |
| Dashboard | connection state, duration, current profile and tunnel, public IP and country, upload/download graphs, packets, latency, server load |
| Profiles | list with search, favourites, tags, country and image; import `.ovpn`; export; per-profile settings |
| Split tunnel | application picker with icons and checkboxes, per-app tunnel assignment, domain and IP rule editors |
| Processes | live process list with icon, name, PID, upload, download, current IP and tunnel |
| Protection | kill switch mode, DNS settings, leak-protection toggles, leak test |
| Logs | filtering by level and channel, search, export |
| Settings | auto launch, auto connect, start minimised, notifications, theme, language, updates |

All state comes from the service. The UI holds no authoritative copy and
performs no privileged operation.
