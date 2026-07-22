using System.Text.Json.Nodes;
using NovaVpn.App.Ipc;
using NovaVpn.App.Services;

namespace NovaVpn.App.ViewModels;

/// <summary>The settings page: reads the service settings document and writes
/// back changes as an overlay.</summary>
public sealed class SettingsViewModel : PageViewModelBase
{
    private readonly NovaVpnService _service;
    private bool _loading;
    private string _status = "";

    private bool _autoConnect;
    private bool _startMinimized;
    private bool _notificationsEnabled;
    private string _theme = "system";

    public SettingsViewModel(NovaVpnService service)
    {
        _service = service;
        SaveCommand = new RelayCommand(_ => SaveAsync());
    }

    public RelayCommand SaveCommand { get; }

    public string[] Themes { get; } = { "system", "light", "dark" };

    public bool AutoConnect { get => _autoConnect; set => Set(ref _autoConnect, value); }
    public bool StartMinimized { get => _startMinimized; set => Set(ref _startMinimized, value); }
    public bool NotificationsEnabled { get => _notificationsEnabled; set => Set(ref _notificationsEnabled, value); }
    public string Theme { get => _theme; set => Set(ref _theme, value); }
    public string Status { get => _status; set => Set(ref _status, value); }

    public override async Task OnNavigatedToAsync() => await LoadAsync().ConfigureAwait(true);

    private async Task LoadAsync()
    {
        _loading = true;
        try
        {
            var settings = await _service.GetSettingsAsync().ConfigureAwait(true);
            AutoConnect = settings["startup"]?["autoConnectProfileId"] is JsonValue v &&
                          !string.IsNullOrEmpty(v.GetValue<string>());
            StartMinimized = settings["startup"]?["startMinimized"]?.GetValue<bool>() ?? false;
            NotificationsEnabled = settings["notifications"]?["enabled"]?.GetValue<bool>() ?? true;
            Theme = settings["appearance"]?["theme"]?.GetValue<string>() ?? "system";
            Status = "";
        }
        catch (IpcException ex)
        {
            Status = $"Could not load settings: {ex.Message}";
        }
        finally
        {
            _loading = false;
        }
    }

    private async Task SaveAsync()
    {
        if (_loading)
        {
            return;
        }
        try
        {
            var overlay = new JsonObject
            {
                ["appearance"] = new JsonObject { ["theme"] = Theme },
                ["startup"] = new JsonObject { ["startMinimized"] = StartMinimized },
                ["notifications"] = new JsonObject { ["enabled"] = NotificationsEnabled },
            };
            await _service.SetSettingsAsync(overlay).ConfigureAwait(true);
            Status = "Settings saved.";
        }
        catch (IpcException ex)
        {
            Status = $"Could not save settings: {ex.Message}";
        }
    }
}
