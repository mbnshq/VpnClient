# UI — Phase 5

The NovaVPN desktop client: `NovaVPN.exe`, an ordinary user-privilege process
that talks to the service over the named pipe described in
[../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md).

## Framework decision

**WinUI 3 (Windows App SDK) with C++/WinRT** is the target. It gives native
Windows 11 Fluent design — Mica backdrop, rounded corners, the system motion
system, automatic light/dark and accent-colour following — without a managed
runtime in the process that renders untrusted profile names and server banners.

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
