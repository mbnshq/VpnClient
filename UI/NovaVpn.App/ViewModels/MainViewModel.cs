using System.Collections.ObjectModel;
using System.IO;
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
public sealed class MainViewModel : PageViewModelBase
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
            IsServiceConnected = false;
            ServiceStatus = "Lost connection to the NovaVPN service";
            ConnectionState = "Disconnected";
        });

        ConnectCommand = new RelayCommand(_ => ConnectAsync(), _ => CanConnect);
        DisconnectCommand = new RelayCommand(_ => DisconnectAsync(), _ => IsConnected);
        RefreshCommand = new RelayCommand(_ => RefreshAsync());
        ImportCommand = new RelayCommand(_ => ImportAsync());
        StartServiceCommand = new RelayCommand(_ => StartServiceAsync(), _ => !IsServiceConnected);
        EditCredentialsCommand = new RelayCommand(_ => EditCredentialsAsync(),
            _ => SelectedProfile is { NeedsPassword: true });
        EditProfileCommand = new RelayCommand(
            p => EditProfileAsync(p as ProfileSummary ?? SelectedProfile),
            p => (p as ProfileSummary ?? SelectedProfile) is not null);
    }

    public ObservableCollection<ProfileSummary> Profiles { get; } = new();

    public RelayCommand ConnectCommand { get; }
    public RelayCommand DisconnectCommand { get; }
    public RelayCommand RefreshCommand { get; }
    public RelayCommand ImportCommand { get; }
    public RelayCommand StartServiceCommand { get; }
    public RelayCommand EditCredentialsCommand { get; }
    public RelayCommand EditProfileCommand { get; }

    private bool _isServiceConnected;
    public bool IsServiceConnected
    {
        get => _isServiceConnected;
        set
        {
            if (Set(ref _isServiceConnected, value))
            {
                Raise(nameof(IsServiceDisconnected));
                StartServiceCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool IsServiceDisconnected => !IsServiceConnected;

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
        set
        {
            if (Set(ref _selectedProfile, value))
            {
                Refresh();
                Raise(nameof(SelectedNeedsCredentials));
                EditCredentialsCommand.RaiseCanExecuteChanged();
                EditProfileCommand.RaiseCanExecuteChanged();
            }
        }
    }

    /// <summary>True when the selected profile authenticates by username/password.</summary>
    public bool SelectedNeedsCredentials => SelectedProfile is { NeedsPassword: true };

    public bool Busy { get => _busy; set { if (Set(ref _busy, value)) { Refresh(); } } }

    public bool HasNoProfiles => Profiles.Count == 0;

    public bool IsConnected =>
        ConnectionState is "Connected" or "Reconnecting";

    public bool CanConnect => !IsConnected && !Busy && SelectedProfile is not null;

    /// <summary>
    /// Connects to the service and loads the profile list on startup. If the
    /// service is not yet running, it is started automatically (one elevation
    /// prompt the first time), then the connection is retried - so the user
    /// never has to install or manage a service by hand.
    /// </summary>
    public async Task InitializeAsync()
    {
        if (await TryConnectAsync().ConfigureAwait(true))
        {
            return;
        }

        // Not reachable: bring the background service up, then retry once.
        ServiceStatus = "Starting the NovaVPN background service…";
        var result = await Task.Run(ServiceBootstrap.TryEnsureService).ConfigureAwait(true);
        if (!result.Ok)
        {
            ServiceStatus = result.Message;
            return;
        }

        if (!await TryConnectAsync().ConfigureAwait(true))
        {
            ServiceStatus =
                "The NovaVPN background service was started but is not answering yet. " +
                "Click Refresh in a moment.";
        }
    }

    /// <summary>Starts the background service on demand (the "Start service" button).</summary>
    private async Task StartServiceAsync()
    {
        ServiceStatus = "Starting the NovaVPN background service…";
        var result = await Task.Run(ServiceBootstrap.TryEnsureService).ConfigureAwait(true);
        if (result.Ok)
        {
            await TryConnectAsync().ConfigureAwait(true);
        }
        else
        {
            ServiceStatus = result.Message;
        }
    }

    /// <summary>Attempts a single connect + profile load; true on success.</summary>
    private async Task<bool> TryConnectAsync()
    {
        try
        {
            await _service.ConnectAsync().ConfigureAwait(true);
            IsServiceConnected = true;
            ServiceStatus = $"Connected to NovaVPN service {_service.ServiceVersion}";
            await LoadProfilesAsync().ConfigureAwait(true);
            return true;
        }
        catch (Exception)
        {
            IsServiceConnected = false;
            return false;
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
        Raise(nameof(HasNoProfiles));
    }

    private async Task ConnectAsync()
    {
        if (SelectedProfile is null)
        {
            return;
        }

        // A username/password profile with nothing saved needs credentials
        // before the handshake. Prompt once (offering to save), like OpenVPN
        // Connect, then pass them straight into this connection.
        string? username = null;
        string? password = null;
        if (SelectedProfile.NeedsPassword && !SelectedProfile.HasSavedPassword)
        {
            var entered = PromptForCredentials(SelectedProfile);
            if (entered is null)
            {
                StatusText = "Connect cancelled: credentials are required.";
                return;
            }
            username = entered.Value.Username;
            password = entered.Value.Password;
            if (entered.Value.Save)
            {
                try
                {
                    await _service.SetProfileCredentialsAsync(
                        SelectedProfile.Id, username, password, savePassword: true)
                        .ConfigureAwait(true);
                    await LoadProfilesAsync().ConfigureAwait(true);
                }
                catch (IpcException) { /* fall through; connect still uses them live */ }
            }
        }

        Busy = true;
        StatusText = "Connecting…";
        try
        {
            _activeTunnelId = await _service
                .ConnectTunnelAsync(SelectedProfile.Id, username, password)
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

    /// <summary>Edits the saved username/password for the selected profile.</summary>
    private async Task EditCredentialsAsync()
    {
        if (SelectedProfile is null)
        {
            return;
        }
        var entered = PromptForCredentials(SelectedProfile);
        if (entered is null)
        {
            return;
        }
        try
        {
            await _service.SetProfileCredentialsAsync(
                SelectedProfile.Id, entered.Value.Username, entered.Value.Password,
                entered.Value.Save).ConfigureAwait(true);
            StatusText = "Credentials saved.";
            await LoadProfilesAsync().ConfigureAwait(true);
        }
        catch (IpcException ex)
        {
            StatusText = $"Could not save credentials: {ex.Message}";
        }
    }

    /// <summary>Opens the profile detail screen: rename, credentials, or delete.</summary>
    private async Task EditProfileAsync(ProfileSummary? target)
    {
        var profile = target ?? SelectedProfile;
        if (profile is null)
        {
            return;
        }
        SelectedProfile = profile;
        var dialog = new Views.ProfileDetailDialog(profile)
        {
            Owner = Application.Current?.MainWindow,
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            if (dialog.Outcome == Views.ProfileDetailDialog.Result.Delete)
            {
                await _service.DeleteProfileAsync(profile.Id).ConfigureAwait(true);
                StatusText = $"Deleted {profile.Name}.";
                SelectedProfile = null;
                await LoadProfilesAsync().ConfigureAwait(true);
                return;
            }

            // Save: rename if changed, and update credentials when a password was
            // entered or the username changed.
            if (!string.Equals(dialog.ProfileName, profile.Name, StringComparison.Ordinal))
            {
                await _service.RenameProfileAsync(profile.Id, dialog.ProfileName).ConfigureAwait(true);
            }
            if (profile.NeedsPassword &&
                (dialog.PasswordEntered ||
                 !string.Equals(dialog.Username, profile.UserName, StringComparison.Ordinal)))
            {
                await _service.SetProfileCredentialsAsync(
                    profile.Id, dialog.Username, dialog.Password, dialog.SavePassword)
                    .ConfigureAwait(true);
            }
            StatusText = "Profile saved.";
            await LoadProfilesAsync().ConfigureAwait(true);
        }
        catch (IpcException ex)
        {
            StatusText = $"Could not save the profile: {ex.Message}";
        }
    }

    /// <summary>Shows the modal credential prompt; null when the user cancels.</summary>
    private static (string Username, string Password, bool Save)? PromptForCredentials(
        ProfileSummary profile)
    {
        var dialog = new Views.CredentialDialog(profile.Name, profile.UserName)
        {
            Owner = Application.Current?.MainWindow,
        };
        return dialog.ShowDialog() == true
            ? (dialog.Username, dialog.Password, dialog.SavePassword)
            : null;
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
        if (!_service.IsConnected)
        {
            // Refresh doubles as "try again" when the service is not connected.
            await InitializeAsync().ConfigureAwait(true);
            return;
        }
        try
        {
            await LoadProfilesAsync().ConfigureAwait(true);
        }
        catch (IpcException ex)
        {
            ServiceStatus = ex.Message;
        }
    }

    /// <summary>Imports one or more .ovpn files chosen by the user.</summary>
    private async Task ImportAsync()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Import an OpenVPN profile",
            Filter = "OpenVPN profiles (*.ovpn;*.conf)|*.ovpn;*.conf|All files (*.*)|*.*",
            Multiselect = true,
            CheckFileExists = true,
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        int imported = 0;
        var importedIds = new List<string>();
        foreach (var path in dialog.FileNames)
        {
            try
            {
                var config = await File.ReadAllTextAsync(path).ConfigureAwait(true);
                var name = Path.GetFileNameWithoutExtension(path);
                var id = await _service.ImportProfileAsync(config, name).ConfigureAwait(true);
                if (!string.IsNullOrEmpty(id)) { importedIds.Add(id); }
                imported++;
            }
            catch (IpcException ex)
            {
                StatusText = $"Import failed for {Path.GetFileName(path)}: {ex.Message}";
            }
            catch (IOException ex)
            {
                StatusText = $"Could not read {Path.GetFileName(path)}: {ex.Message}";
            }
        }

        if (imported > 0)
        {
            StatusText = $"Imported {imported} profile{(imported == 1 ? "" : "s")}.";
            await LoadProfilesAsync().ConfigureAwait(true);

            // Offer to set credentials for each imported username/password
            // profile, so it is ready to connect - the way OpenVPN Connect asks
            // right after import.
            foreach (var id in importedIds)
            {
                var profile = Profiles.FirstOrDefault(p => p.Id == id);
                if (profile is { NeedsPassword: true, HasSavedPassword: false })
                {
                    SelectedProfile = profile;
                    var entered = PromptForCredentials(profile);
                    if (entered is not null)
                    {
                        try
                        {
                            await _service.SetProfileCredentialsAsync(
                                id, entered.Value.Username, entered.Value.Password,
                                entered.Value.Save).ConfigureAwait(true);
                        }
                        catch (IpcException) { /* user can set them later */ }
                    }
                }
            }
            await LoadProfilesAsync().ConfigureAwait(true);
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
