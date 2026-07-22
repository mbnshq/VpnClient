using System.Reflection;
using NovaVpn.App.Services;

namespace NovaVpn.App.ViewModels;

/// <summary>The About / Help page: version, the connected service, and pointers.</summary>
public sealed class AboutViewModel : PageViewModelBase
{
    private readonly NovaVpnService _service;
    private string _serviceInfo = "Not connected to the service";

    public AboutViewModel(NovaVpnService service)
    {
        _service = service;
    }

    public string Version =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";

    public string ServiceInfo { get => _serviceInfo; set => Set(ref _serviceInfo, value); }

    public string ProjectUrl => "https://github.com/mbnshq/VpnClient";

    public override Task OnNavigatedToAsync()
    {
        ServiceInfo = _service.IsConnected
            ? $"Connected to NovaVPN service {_service.ServiceVersion}"
            : "Not connected to the NovaVPN service";
        return Task.CompletedTask;
    }
}
