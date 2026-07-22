using System.Windows;
using NovaVpn.App.Services;
using NovaVpn.App.ViewModels;

namespace NovaVpn.App;

public partial class MainWindow : Window
{
    private readonly NovaVpnService _service = new();
    private readonly MainViewModel _viewModel;

    public MainWindow()
    {
        InitializeComponent();
        _viewModel = new MainViewModel(_service);
        DataContext = _viewModel;

        Loaded += async (_, _) => await _viewModel.InitializeAsync();
        Closed += (_, _) => _service.Dispose();
    }
}
