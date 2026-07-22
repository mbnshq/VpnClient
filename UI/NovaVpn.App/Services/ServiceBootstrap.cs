using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace NovaVpn.App.Services;

/// <summary>
/// Brings the SYSTEM background service up on demand, the way OpenVPN Connect
/// and WireGuard do: the unprivileged UI cannot itself create or start a SYSTEM
/// service, so it launches the service executable with <c>--ensure</c> through
/// the shell "runas" verb. That is a single UAC prompt the first time; the
/// helper registers the service as auto-start and starts it, and every boot
/// after that Windows starts it automatically with no prompt.
/// </summary>
public static class ServiceBootstrap
{
    public readonly record struct Result(bool Ok, string Message);

    /// <summary>
    /// Locates NovaVPNService.exe. In a normal install it sits next to the UI;
    /// a development layout keeps it one level up under <c>bin</c>. No absolute
    /// or user-specific path is ever hard-coded.
    /// </summary>
    public static string? FindServiceExecutable()
    {
        var baseDir = AppContext.BaseDirectory;
        string[] candidates =
        {
            Path.Combine(baseDir, "NovaVPNService.exe"),
            Path.Combine(baseDir, "..", "bin", "NovaVPNService.exe"),
            Path.Combine(baseDir, "..", "NovaVPNService.exe"),
        };
        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return Path.GetFullPath(candidate);
            }
        }
        return null;
    }

    /// <summary>
    /// Ensures the service is installed and running, elevating once if needed.
    /// Returns whether the elevated helper reported success and a message fit to
    /// show the user. Safe to call when the service is already running (the
    /// helper is idempotent).
    /// </summary>
    public static Result TryEnsureService()
    {
        var exe = FindServiceExecutable();
        if (exe is null)
        {
            return new Result(false,
                "NovaVPNService.exe was not found next to the app. Reinstall NovaVPN.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = "--ensure",
            UseShellExecute = true, // required for the runas verb
            Verb = "runas",         // triggers the Windows elevation prompt
            WindowStyle = ProcessWindowStyle.Hidden,
            CreateNoWindow = true,
        };

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return new Result(false, "Could not launch the NovaVPN service helper.");
            }

            // --ensure installs (if needed) and asks the SCM to start the
            // service, then exits; it does not block on the service reaching
            // "running". A generous wait covers a cold first-time install.
            if (!process.WaitForExit(30_000))
            {
                return new Result(false, "The NovaVPN service helper timed out.");
            }

            return process.ExitCode == 0
                ? new Result(true, "NovaVPN background service is running.")
                : new Result(false,
                    "The NovaVPN service helper could not start the service " +
                    $"(exit code {process.ExitCode}).");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED
        {
            return new Result(false,
                "NovaVPN needs permission to start its background service. " +
                "Click \"Start service\" and choose Yes on the Windows prompt.");
        }
        catch (Exception ex)
        {
            return new Result(false, $"Could not start the NovaVPN service: {ex.Message}");
        }
    }
}
