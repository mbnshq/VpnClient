using System.Collections.ObjectModel;
using NovaVpn.App.Ipc;
using NovaVpn.App.Services;

namespace NovaVpn.App.ViewModels;

/// <summary>The logs page: reads the service's in-memory log ring, with a text
/// filter.</summary>
public sealed class LogsViewModel : PageViewModelBase
{
    private readonly NovaVpnService _service;
    private string _filter = "";
    private string _status = "";
    private IReadOnlyList<string> _all = Array.Empty<string>();

    public LogsViewModel(NovaVpnService service)
    {
        _service = service;
        RefreshCommand = new RelayCommand(_ => LoadAsync());
    }

    public ObservableCollection<string> Lines { get; } = new();
    public RelayCommand RefreshCommand { get; }

    public string Filter
    {
        get => _filter;
        set { if (Set(ref _filter, value)) { ApplyFilter(); } }
    }

    public string Status { get => _status; set => Set(ref _status, value); }

    public override async Task OnNavigatedToAsync() => await LoadAsync().ConfigureAwait(true);

    private async Task LoadAsync()
    {
        try
        {
            _all = await _service.GetLogsAsync().ConfigureAwait(true);
            ApplyFilter();
            Status = $"{_all.Count} log lines.";
        }
        catch (IpcException ex)
        {
            Status = $"Could not load logs: {ex.Message}";
        }
    }

    private void ApplyFilter()
    {
        Lines.Clear();
        foreach (var line in _all)
        {
            if (string.IsNullOrEmpty(_filter) ||
                line.Contains(_filter, StringComparison.OrdinalIgnoreCase))
            {
                Lines.Add(line);
            }
        }
    }
}
