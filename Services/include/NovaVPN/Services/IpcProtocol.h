// NovaVPN - Services/IpcProtocol.h
// The UI <-> service wire contract.
//
// Transport: a named pipe, \\.\pipe\NovaVPN.Service, created by the service
// with a DACL granting the Users group connect access and nothing else. The
// service verifies the peer's token on every connection; the client verifies
// that the pipe's owner is SYSTEM before sending anything, which is what stops
// a squatting process from impersonating the service and harvesting
// credentials.
//
// Framing: 4-byte little-endian length prefix, then a UTF-8 JSON object. A
// frame larger than kMaxFrameBytes is refused without being read, so a hostile
// client cannot make the service allocate unbounded memory.
//
// Compatibility: every message carries `protocol`. The service rejects a client
// whose major protocol version differs, with ServiceVersion, and the UI turns
// that into "please restart to finish updating" rather than a silent hang.
#pragma once

#include <NovaVPN/Core/Json.h>
#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/Types.h>

#include <optional>
#include <string>
#include <vector>

namespace nova::ipc {

/// Maximum frame size. Generous enough for a profile with inline certificates,
/// small enough that a flood cannot exhaust the service.
inline constexpr u32 kMaxFrameBytes = 8u * 1024 * 1024;

/// Default pipe name; overridable through service.ipcPipeName for side-by-side
/// test instances.
inline constexpr std::string_view kDefaultPipeName = "NovaVPN.Service";

/// Request verbs. Append only - the numbering is part of the contract.
enum class Method : u16 {
    // --- handshake --------------------------------------------------------
    Hello                = 1,   ///< Version negotiation; must be the first call.

    // --- profiles ---------------------------------------------------------
    ListProfiles         = 100,
    GetProfile           = 101,
    AddProfile           = 102,
    UpdateProfile        = 103,
    DeleteProfile        = 104,
    ImportOvpn           = 105,
    ExportProfile        = 106,
    SetProfileFavorite   = 107,
    SetProfileCredentials = 108, ///< Save/replace a profile's username+password.
    RenameProfile        = 109, ///< Change a profile's display name.

    // --- connection -------------------------------------------------------
    Connect              = 200,
    Disconnect           = 201,
    DisconnectAll        = 202,
    Reconnect            = 203,
    AnswerChallenge      = 204,
    GetTunnels           = 205,
    GetStatistics        = 206,
    SetPrimaryTunnel     = 207,

    // --- routing / split tunnel ------------------------------------------
    GetRoutingPolicy     = 300,
    SetRoutingPolicy     = 301,
    GetSplitTunnelConfig = 302,
    SetSplitTunnelConfig = 303,
    ListProcesses        = 304,
    ListInstalledApps    = 305,
    GetApplicationIcon   = 306,

    // --- protection -------------------------------------------------------
    GetFirewallPolicy    = 400,
    SetFirewallPolicy    = 401,
    RunLeakTest          = 402,
    GetNetworkState      = 403,

    // --- settings / diagnostics ------------------------------------------
    GetSettings          = 500,
    SetSettings          = 501,
    GetLogs              = 502,
    ExportSupportBundle  = 503,
    GetServiceInfo       = 504,

    // --- updates ----------------------------------------------------------
    CheckForUpdate       = 600,
    DownloadUpdate       = 601,
    InstallUpdate        = 602,
};

/// Unsolicited messages pushed from the service to every connected client.
enum class EventKind : u16 {
    TunnelStateChanged   = 1000,
    StatisticsTick       = 1001,
    AuthChallenge        = 1002,
    NetworkChanged       = 1003,
    LeakDetected         = 1004,
    ProfileListChanged   = 1005,
    UpdateProgress       = 1006,
    LogRecord            = 1007,
    ServiceShuttingDown  = 1008,
};

[[nodiscard]] std::string_view toString(Method method) noexcept;
[[nodiscard]] std::string_view toString(EventKind kind) noexcept;

/// A request frame.
struct Request {
    /// Client-chosen, echoed in the response. Monotonic per connection.
    u64    id = 0;
    Method method = Method::Hello;
    /// Method-specific payload.
    Json   params = Json::object();
};

/// A response frame. Exactly one of `result` / `error` is meaningful.
struct Response {
    u64    id = 0;
    bool   success = true;
    Json   result = Json::object();
    /// Present when success == false.
    ErrorCode   errorCode = ErrorCode::Ok;
    std::string errorMessage;
    u32         platformCode = 0;
};

/// An event frame. `id` is always 0 so a client can distinguish it from a
/// response without inspecting the type field.
struct Event {
    EventKind kind = EventKind::TunnelStateChanged;
    Json      payload = Json::object();
};

/// Serialisation. These are total functions: any Request/Response/Event can be
/// encoded, and decoding reports a precise ErrorCode rather than throwing.
[[nodiscard]] Json encode(const Request& request);
[[nodiscard]] Json encode(const Response& response);
[[nodiscard]] Json encode(const Event& event);

[[nodiscard]] Result<Request> decodeRequest(const Json& value);
[[nodiscard]] Result<Response> decodeResponse(const Json& value);
[[nodiscard]] Result<Event> decodeEvent(const Json& value);

/// Convenience constructors.
[[nodiscard]] Response makeSuccess(u64 requestId, Json result);
[[nodiscard]] Response makeError(u64 requestId, const Status& status);

/// Frames a JSON document for the wire: 4-byte little-endian length + UTF-8.
[[nodiscard]] Result<std::vector<u8>> frame(const Json& value);

/// Reads the length prefix. Returns InvalidArgument when the frame exceeds
/// kMaxFrameBytes, so the caller can drop the connection without reading it.
[[nodiscard]] Result<u32> readFrameLength(std::span<const u8> prefix);

/// Parses a frame body.
[[nodiscard]] Result<Json> parseFrame(std::span<const u8> body);

/// Payload of Method::Hello, exchanged before anything else.
struct HelloParams {
    int         protocolVersion = 0;
    std::string clientVersion;
    std::string clientName;
};

struct HelloResult {
    int         protocolVersion = 0;
    std::string serviceVersion;
    /// True when the caller's token is a member of the Administrators group;
    /// policy-changing methods require it.
    bool        callerIsAdministrator = false;
    /// Service uptime, for the diagnostics panel.
    Seconds     uptime{0};
};

[[nodiscard]] Json encode(const HelloParams& params);
[[nodiscard]] Result<HelloParams> decodeHelloParams(const Json& value);
[[nodiscard]] Json encode(const HelloResult& result);
[[nodiscard]] Result<HelloResult> decodeHelloResult(const Json& value);

/// Methods that mutate machine-wide policy and therefore require an elevated
/// caller. Enforced by the service, never by the UI.
[[nodiscard]] bool requiresAdministrator(Method method) noexcept;

} // namespace nova::ipc
