using System.Windows;
using NovaVpn.App.Services;

namespace NovaVpn.App.ViewModels;

/// <summary>Live connection statistics - the detailed counterpart to the
/// dashboard's summary tiles.</summary>
public sealed class StatisticsViewModel : PageViewModelBase
{
    private readonly NovaVpnService _service;
    private string _state = "Disconnected";
    private string _downRate = "0 bps";
    private string _upRate = "0 bps";
    private string _received = "0 B";
    private string _sent = "0 B";
    private double _peakDown;
    private string _peakDownText = "0 bps";

    public StatisticsViewModel(NovaVpnService service)
    {
        _service = service;
        _service.StatisticsReceived += s => OnUi(() => Apply(s));
        _service.TunnelStateChanged += s => OnUi(() => State = s.State);
    }

    public string State { get => _state; set => Set(ref _state, value); }
    public string DownRate { get => _downRate; set => Set(ref _downRate, value); }
    public string UpRate { get => _upRate; set => Set(ref _upRate, value); }
    public string Received { get => _received; set => Set(ref _received, value); }
    public string Sent { get => _sent; set => Set(ref _sent, value); }
    public string PeakDownText { get => _peakDownText; set => Set(ref _peakDownText, value); }

    private void Apply(StatisticsSample sample)
    {
        DownRate = Format.Bitrate(sample.DownBps);
        UpRate = Format.Bitrate(sample.UpBps);
        Received = Format.Bytes(sample.BytesReceived);
        Sent = Format.Bytes(sample.BytesSent);
        if (sample.DownBps > _peakDown)
        {
            _peakDown = sample.DownBps;
            PeakDownText = Format.Bitrate(_peakDown);
        }
    }

    private static void OnUi(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess()) { action(); }
        else { dispatcher.Invoke(action); }
    }
}
