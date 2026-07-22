using System.Text.Json.Nodes;
using NovaVpn.App.Ipc;
using NovaVpn.App.Models;

namespace NovaVpn.App.Services;

/// <summary>
/// A task-based facade over the raw IPC client: the operations the view models
/// call, expressed in domain terms rather than JSON frames.
/// </summary>
public sealed class NovaVpnService : IDisposable
{
    private const string PipeName = "NovaVPN.Service";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    private readonly IpcClient _client = new("NovaVPN.App");

    public event Action<TunnelState>? TunnelStateChanged;
    public event Action<StatisticsSample>? StatisticsReceived;
    public event Action? Disconnected;

    public bool IsConnected => _client.IsConnected;
    public string ServiceVersion => _client.ServiceInfo?.ServiceVersion ?? "";

    public NovaVpnService()
    {
        _client.EventReceived += OnEvent;
        _client.Disconnected += () => Disconnected?.Invoke();
    }

    public Task ConnectAsync(CancellationToken ct = default) =>
        _client.ConnectAsync(PipeName, Timeout, ct);

    public async Task<IReadOnlyList<ProfileSummary>> ListProfilesAsync(
        string search = "", CancellationToken ct = default)
    {
        var response = await Call(Method.ListProfiles,
            new JsonObject { ["search"] = search }, ct).ConfigureAwait(false);

        var list = new List<ProfileSummary>();
        if (response.Result["profiles"] is JsonArray rows)
        {
            foreach (var row in rows)
            {
                if (row is JsonObject o)
                {
                    list.Add(ProfileSummary.From(o));
                }
            }
        }
        return list;
    }

    public async Task<string> ConnectTunnelAsync(
        string profileId, string? username, string? password, CancellationToken ct = default)
    {
        var parameters = new JsonObject { ["profileId"] = profileId };
        if (!string.IsNullOrEmpty(username)) parameters["username"] = username;
        if (!string.IsNullOrEmpty(password)) parameters["password"] = password;

        var response = await Call(Method.Connect, parameters, ct).ConfigureAwait(false);
        return response.Result["tunnelId"]?.GetValue<string>() ?? "";
    }

    public Task DisconnectAsync(string tunnelId, CancellationToken ct = default) =>
        Call(Method.Disconnect, new JsonObject { ["tunnelId"] = tunnelId }, ct);

    public Task DisconnectAllAsync(CancellationToken ct = default) =>
        Call(Method.DisconnectAll, null, ct);

    public async Task<IReadOnlyList<TunnelInfo>> GetTunnelsAsync(CancellationToken ct = default)
    {
        var response = await Call(Method.GetTunnels, null, ct).ConfigureAwait(false);
        var list = new List<TunnelInfo>();
        if (response.Result["tunnels"] is JsonArray rows)
        {
            foreach (var row in rows)
            {
                if (row is JsonObject o)
                {
                    list.Add(TunnelInfo.From(o));
                }
            }
        }
        return list;
    }

    public Task ImportProfileAsync(string config, string name, CancellationToken ct = default) =>
        Call(Method.ImportOvpn, new JsonObject { ["config"] = config, ["name"] = name }, ct);

    private async Task<IpcResponse> Call(Method method, JsonObject? parameters, CancellationToken ct)
    {
        var response = await _client.CallAsync(method, parameters, Timeout, ct).ConfigureAwait(false);
        if (!response.Success)
        {
            throw new IpcException(response.ErrorCode, response.ErrorMessage);
        }
        return response;
    }

    private void OnEvent(JsonObject frame)
    {
        int kind = frame["event"]?.GetValue<int>() ?? 0;
        var payload = frame["payload"] as JsonObject ?? new JsonObject();

        switch ((EventKind)kind)
        {
            case EventKind.TunnelStateChanged:
                TunnelStateChanged?.Invoke(new TunnelState(
                    payload["tunnelId"]?.GetValue<string>() ?? "",
                    payload["state"]?.GetValue<string>() ?? "Unknown",
                    payload["error"]?.GetValue<string>()));
                break;

            case EventKind.StatisticsTick:
                StatisticsReceived?.Invoke(new StatisticsSample(
                    payload["tunnelId"]?.GetValue<string>() ?? "",
                    payload["bytesSent"]?.GetValue<ulong>() ?? 0,
                    payload["bytesReceived"]?.GetValue<ulong>() ?? 0,
                    payload["upBps"]?.GetValue<double>() ?? 0,
                    payload["downBps"]?.GetValue<double>() ?? 0));
                break;
        }
    }

    public void Dispose() => _client.Dispose();
}

public readonly record struct TunnelState(string TunnelId, string State, string? Error);

public readonly record struct StatisticsSample(
    string TunnelId, ulong BytesSent, ulong BytesReceived, double UpBps, double DownBps);
