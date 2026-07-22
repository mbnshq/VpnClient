using System.Text.Json.Nodes;

namespace NovaVpn.App.Ipc;

/// <summary>IPC method verbs. Values mirror Services/IpcProtocol.h exactly.</summary>
public enum Method
{
    Hello = 1,
    ListProfiles = 100,
    GetProfile = 101,
    ImportOvpn = 105,
    DeleteProfile = 104,
    SetProfileFavorite = 107,
    SetProfileCredentials = 108,
    Connect = 200,
    Disconnect = 201,
    DisconnectAll = 202,
    Reconnect = 203,
    GetTunnels = 205,
    GetStatistics = 206,
    ListProcesses = 304,
    ListInstalledApps = 305,
    RunLeakTest = 402,
    GetSettings = 500,
    SetSettings = 501,
    GetLogs = 502,
    GetServiceInfo = 504,
}

/// <summary>Event kinds pushed by the service. Mirror IpcProtocol.h.</summary>
public enum EventKind
{
    TunnelStateChanged = 1000,
    StatisticsTick = 1001,
    AuthChallenge = 1002,
    NetworkChanged = 1003,
    LeakDetected = 1004,
    ProfileListChanged = 1005,
    LogRecord = 1007,
    ServiceShuttingDown = 1008,
}

/// <summary>A decoded response frame.</summary>
public sealed class IpcResponse
{
    public ulong Id { get; init; }
    public bool Success { get; init; }
    public JsonObject Result { get; init; } = new();
    public string ErrorCode { get; init; } = "";
    public string ErrorMessage { get; init; } = "";

    public static IpcResponse From(JsonObject frame)
    {
        bool success = frame["success"]?.GetValue<bool>() ?? false;
        return new IpcResponse
        {
            Id = frame["id"]?.GetValue<ulong>() ?? 0,
            Success = success,
            Result = success ? frame["result"] as JsonObject ?? new JsonObject() : new JsonObject(),
            ErrorCode = frame["error"]?["name"]?.GetValue<string>() ?? "",
            ErrorMessage = frame["error"]?["message"]?.GetValue<string>() ?? "",
        };
    }
}

/// <summary>Result of the Hello handshake.</summary>
public sealed class HelloResult
{
    public int ProtocolVersion { get; init; }
    public string ServiceVersion { get; init; } = "";
    public bool CallerIsAdministrator { get; init; }

    public static HelloResult From(JsonObject result) => new()
    {
        ProtocolVersion = result["protocolVersion"]?.GetValue<int>() ?? 0,
        ServiceVersion = result["serviceVersion"]?.GetValue<string>() ?? "",
        CallerIsAdministrator = result["callerIsAdministrator"]?.GetValue<bool>() ?? false,
    };
}

/// <summary>An IPC error surfaced as an exception, carrying the taxonomy code.</summary>
public sealed class IpcException : Exception
{
    public string Code { get; }
    public IpcException(string code, string message) : base(message) => Code = code;
}
