using System.Collections.ObjectModel;
using System.Windows;
using NovaVpn.App.Ipc;
using NovaVpn.App.Models;
using NovaVpn.App.Services;

namespace NovaVpn.App.ViewModels;

/// <summary>
/// The dashboard view model: connection state, the profile list, live traffic,
/// and the connect/disconnect commands. All service calls are async and route
/// through the IPC client; events from the service marshal back onto the UI
/// thread via the dispatcher.
/// </summary>
public sealed class MainViewModel : ObservableObject
{
    private readonly NovaVpnService _service;

    private string _statusText = "Disconnected";
    private string _connectionState = "Disconnected";
    private string _serviceStatus = "Not connected to the NovaVPN service";
    private string _upRate = "0 bps";
    private string _downRate = "0 bps";
    private string _sent = "0 B";
    private string _received = "0 B";
    private string _activeTunnelId = "";
    private ProfileSummary? _selectedProfile;
    private bool _busy;

    public MainViewModel(NovaVpnService service)
    {
        _service = service;
        _service.TunnelStateChanged += s => OnUi(() => ApplyTunnelState(s));
        _service.StatisticsReceived += s => OnUi(() => ApplyStatistics(s));
        _service.Disconnected += () => OnUi(() =>
        {
            ServiceStatus = "Lost connection to the NovaVPN service";
            ConnectionState = "Disconnected";
        });

        ConnectCommand = new RelayCommand(_ => ConnectAsync(), _ => CanConnect);
        DisconnectCommand = new RelayCommand(_ => DisconnectAsync(), _ => IsConnected);
        RefreshCommand = new RelayCommand(_ => RefreshAsync());
    }

    public ObservableCollection<ProfileSummary> Profiles { get; } = new();

    public RelayCommand ConnectCommand { get; }
    public RelayCommand DisconnectCommand { get; }
    public RelayCommand RefreshCommand { get; }

    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }
    public string ConnectionState
    {
        get => _connectionState;
        set { if (Set(ref _connectionState, value)) { Raise(nameof(IsConnected)); Refresh(); } }
    }
    public string ServiceStatus { get => _serviceStatus; set => Set(ref _serviceStatus, value); }
    public string UpRate { get => _upRate; set => Set(ref _upRate, value); }
    public string DownRate { get => _downRate; set => Set(ref _downRate, value); }
    public string Sent { get => _sent; set => Set(ref _sent, value); }
    public string Received { get => _received; set => Set(ref _received, value); }

    public ProfileSummary? SelectedProfile
    {
        get => _selectedProfile;
        set { if (Set(ref _selectedProfile, value)) { Refresh(); } }
    }

    public bool Busy { get => _busy; set { if (Set(ref _busy, value)) { Refresh(); } } }

    public bool IsConnected =>
        ConnectionState is "Connected" or "Reconnecting";

    public bool CanConnect => !IsConnected && !Busy && SelectedProfile is not null;

    /// <summary>Connects to the service and loads the profile list on startup.</summary>
    public async Task InitializeAsync()
    {
        try
        {
            await _service.ConnectAsync().ConfigureAwait(true);
            ServiceStatus = $"Connected to NovaVPN service {_service.ServiceVersion}";
            await LoadProfilesAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            ServiceStatus = $"Cannot reach the NovaVPN service: {ex.Message}";
        }
    }

    private async Task LoadProfilesAsync()
    {
        var profiles = await _service.ListProfilesAsync().ConfigureAwait(true);
        Profiles.Clear();
        foreach (var profile in profiles)
        {
            Profiles.Add(profile);
        }
        SelectedProfile ??= Profiles.FirstOrDefault();
    }

    private async Task ConnectAsync()
    {
        if (SelectedProfile is null)
        {
            return;
        }
        Busy = true;
        StatusText = "Connecting…";
        try
        {
            _activeTunnelId = await _service
                .ConnectTunnelAsync(SelectedProfile.Id, null, null)
                .ConfigureAwait(true);
        }
        catch (IpcException ex)
        {
            StatusText = $"Connect failed: {ex.Message}";
            ConnectionState = "Faulted";
        }
        finally
        {
            Busy = false;
        }
    }

    private async Task DisconnectAsync()
    {
        Busy = true;
        try
        {
            if (!string.IsNullOrEmpty(_activeTunnelId))
            {
                await _service.DisconnectAsync(_activeTunnelId).ConfigureAwait(true);
            }
            else
            {
                await _service.DisconnectAllAsync().ConfigureAwait(true);
            }
        }
        catch (IpcException ex)
        {
            StatusText = $"Disconnect failed: {ex.Message}";
        }
        finally
        {
            Busy = false;
        }
    }

    private async Task RefreshAsync()
    {
        try
        {
            await LoadProfilesAsync().ConfigureAwait(true);
        }
        catch (IpcException ex)
        {
            ServiceStatus = ex.Message;
        }
    }

    private void ApplyTunnelState(TunnelState state)
    {
        if (!string.IsNullOrEmpty(_activeTunnelId) && state.TunnelId != _activeTunnelId)
        {
            return;
        }
        ConnectionState = state.State;
        StatusText = state.Error is { Length: > 0 } ? $"{state.State}: {state.Error}" : state.State;
    }

    private void ApplyStatistics(StatisticsSample sample)
    {
        if (!string.IsNullOrEmpty(_activeTunnelId) && sample.TunnelId != _activeTunnelId)
        {
            return;
        }
        UpRate = Format.Bitrate(sample.UpBps);
        DownRate = Format.Bitrate(sample.DownBps);
        Sent = Format.Bytes(sample.BytesSent);
        Received = Format.Bytes(sample.BytesReceived);
    }

    private void Refresh()
    {
        ConnectCommand.RaiseCanExecuteChanged();
        DisconnectCommand.RaiseCanExecuteChanged();
    }

    private static void OnUi(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
        {
            action();
        }
        else
        {
            dispatcher.Invoke(action);
        }
    }
}
