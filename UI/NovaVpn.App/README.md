# NovaVPN Desktop Client

`NovaVPN.exe` — the user-facing client. An ordinary user-privilege process that
drives the SYSTEM service over the named-pipe IPC channel; it performs no
networking of its own.

## Framework

**WPF on .NET 9.** WinUI 3 was the original target, but its build requires
Visual Studio's UWP/MSIX workload (the PRI/Appx MSBuild tasks), which is not
part of a Build Tools installation and cannot be driven from the command line.
The brief sanctions WPF (.NET) as the fallback, and the choice costs nothing
architecturally: the UI talks JSON over a pipe, so the framework never touches a
socket. .NET 9's WPF ships the built-in Windows 11 **Fluent theme**
(`PresentationFramework.Fluent`), which gives the modern look without a
third-party control library.

## Structure

```
Ipc/IpcClient.cs      named-pipe transport: length-prefixed JSON frames, the
                      SYSTEM-owner verification, the Hello handshake
Ipc/Protocol.cs       method/event enums and frame types (mirror IpcProtocol.h)
Services/             NovaVpnService — a task-based facade over the IPC client
Models/               ProfileSummary, TunnelInfo
ViewModels/           ObservableObject/RelayCommand + MainViewModel (MVVM)
App.xaml              Fluent theme + shared styles
MainWindow.xaml       the dashboard: profile list, state badge, live traffic
                      tiles, connect/disconnect
```

The IPC wire contract is re-implemented in C# rather than P/Invoking the native
client, because the protocol is language-agnostic JSON over a pipe and the UI is
a separate process anyway. The enums in `Protocol.cs` are kept in lockstep with
`Services/IpcProtocol.h`.

## Build & run

Requires the .NET 9 SDK.

```powershell
dotnet build UI/NovaVpn.App -c Release
```

The client connects to the service on `\\.\pipe\NovaVPN.Service`. With no
service running it shows "Cannot reach the NovaVPN service" and stays usable;
once the service is up it lists profiles and drives connect/disconnect, and
renders tunnel state and live traffic pushed from the service as events.

## Status

Built and verified to launch and render on .NET 9 / Windows 11. The dashboard,
profile list and connect/disconnect flow are implemented against the live IPC
API. The split-tunnel app picker, settings and logs screens are the next UI
increment.
