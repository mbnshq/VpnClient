using System.Text.Json.Nodes;

namespace NovaVpn.App.Models;

/// <summary>One row in the profile list, as the service reports it.</summary>
public sealed class ProfileSummary
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Country { get; init; } = "";
    public string City { get; init; } = "";
    public bool Favorite { get; init; }
    public ulong ConnectCount { get; init; }
    public string Engine { get; init; } = "";

    /// <summary>True when the profile authenticates with a username/password.</summary>
    public bool NeedsPassword { get; init; }
    /// <summary>True when a password is already saved in the vault.</summary>
    public bool HasSavedPassword { get; init; }
    /// <summary>The saved username, for pre-fill (never the password).</summary>
    public string UserName { get; init; } = "";

    public string Location =>
        string.IsNullOrEmpty(City) ? Country : $"{City}, {Country}";

    public static ProfileSummary From(JsonObject o) => new()
    {
        Id = o["id"]?.GetValue<string>() ?? "",
        Name = o["name"]?.GetValue<string>() ?? "",
        Country = o["country"]?.GetValue<string>() ?? "",
        City = o["city"]?.GetValue<string>() ?? "",
        Favorite = o["favorite"]?.GetValue<bool>() ?? false,
        ConnectCount = o["connectCount"]?.GetValue<ulong>() ?? 0,
        Engine = o["engine"]?.GetValue<string>() ?? "",
        NeedsPassword = o["needsPassword"]?.GetValue<bool>() ?? false,
        HasSavedPassword = o["hasSavedPassword"]?.GetValue<bool>() ?? false,
        UserName = o["userName"]?.GetValue<string>() ?? "",
    };
}

/// <summary>A live tunnel, as the service reports it.</summary>
public sealed class TunnelInfo
{
    public string Id { get; init; } = "";
    public string ProfileId { get; init; } = "";
    public string State { get; init; } = "";
    public long UptimeSeconds { get; init; }
    public ulong BytesSent { get; init; }
    public ulong BytesReceived { get; init; }

    public static TunnelInfo From(JsonObject o) => new()
    {
        Id = o["id"]?.GetValue<string>() ?? "",
        ProfileId = o["profileId"]?.GetValue<string>() ?? "",
        State = o["state"]?.GetValue<string>() ?? "",
        UptimeSeconds = o["uptimeSeconds"]?.GetValue<long>() ?? 0,
        BytesSent = o["bytesSent"]?.GetValue<ulong>() ?? 0,
        BytesReceived = o["bytesReceived"]?.GetValue<ulong>() ?? 0,
    };
}
