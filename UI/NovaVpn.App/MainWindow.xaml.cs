using System.Windows;
using NovaVpn.App.Services;
using NovaVpn.App.ViewModels;

namespace NovaVpn.App;

public partial class MainWindow : Window
{
    private readonly NovaVpnService _service = new();
    private readonly ShellViewModel _shell;

    public MainWindow()
    {
        InitializeComponent();
        _shell = new ShellViewModel(_service);
        DataContext = _shell;

        Loaded += async (_, _) => await _shell.InitializeAsync();
        Closed += (_, _) => _service.Dispose();
    }
}
