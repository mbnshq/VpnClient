using System.Collections.ObjectModel;
using NovaVpn.App.Ipc;
using NovaVpn.App.Services;

namespace NovaVpn.App.ViewModels;

/// <summary>The split-tunnel app picker: the installed-app catalogue with a
/// tunnel/direct checkbox per app.</summary>
public sealed class SplitTunnelViewModel : PageViewModelBase
{
    private readonly NovaVpnService _service;
    private bool _enabled;
    private bool _includeMode = true;
    private string _status = "";
    private bool _loaded;

    public SplitTunnelViewModel(NovaVpnService service)
    {
        _service = service;
        RefreshCommand = new RelayCommand(_ => LoadAsync());
    }

    public ObservableCollection<AppEntry> Apps { get; } = new();
    public RelayCommand RefreshCommand { get; }

    public bool Enabled { get => _enabled; set => Set(ref _enabled, value); }
    public bool IncludeMode { get => _includeMode; set => Set(ref _includeMode, value); }
    public string Status { get => _status; set => Set(ref _status, value); }

    public override async Task OnNavigatedToAsync()
    {
        if (!_loaded)
        {
            await LoadAsync().ConfigureAwait(true);
        }
    }

    private async Task LoadAsync()
    {
        try
        {
            Status = "Loading installed applications…";
            var apps = await _service.ListInstalledAppsAsync().ConfigureAwait(true);
            Apps.Clear();
            foreach (var app in apps)
            {
                Apps.Add(new AppEntry(app.DisplayName, app.ImagePath, app.Publisher));
            }
            _loaded = true;
            Status = $"{Apps.Count} applications. Checked apps use the VPN; everything else uses your ISP.";
        }
        catch (IpcException ex)
        {
            Status = $"Could not load applications: {ex.Message}";
        }
    }
}

/// <summary>One selectable application row.</summary>
public sealed class AppEntry : ObservableObject
{
    private bool _tunnel;

    public AppEntry(string name, string path, string publisher)
    {
        Name = name;
        Path = path;
        Publisher = publisher;
    }

    public string Name { get; }
    public string Path { get; }
    public string Publisher { get; }

    /// <summary>When checked, this app's traffic goes through the VPN.</summary>
    public bool Tunnel { get => _tunnel; set => Set(ref _tunnel, value); }
}
