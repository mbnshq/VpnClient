using System.Windows;
using System.Windows.Threading;

namespace NovaVpn.App;

public partial class App : Application
{
    public App()
    {
        // A background IPC failure must never crash the UI; surface it and
        // keep running.
        DispatcherUnhandledException += OnUnhandledException;

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            try
            {
                var path = System.IO.Path.Combine(
                    Environment.GetEnvironmentVariable("TEMP") ?? ".", "novavpn_ui_crash.log");
                System.IO.File.WriteAllText(path, (e.ExceptionObject as Exception)?.ToString() ?? "unknown");
            }
            catch { /* ignore */ }
        };
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(
            $"An unexpected error occurred:\n\n{e.Exception.Message}",
            "NovaVPN", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}
