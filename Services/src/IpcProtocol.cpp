#include <NovaVPN/Core/Version.h>
#include <NovaVPN/Services/IpcProtocol.h>

#include <array>
#include <cstring>

namespace nova::ipc {
namespace {

struct NamedMethod {
    Method           method;
    std::string_view name;
};

constexpr std::array<NamedMethod, 33> kMethods{{
    {Method::Hello, "Hello"},
    {Method::ListProfiles, "ListProfiles"},
    {Method::GetProfile, "GetProfile"},
    {Method::AddProfile, "AddProfile"},
    {Method::UpdateProfile, "UpdateProfile"},
    {Method::DeleteProfile, "DeleteProfile"},
    {Method::ImportOvpn, "ImportOvpn"},
    {Method::ExportProfile, "ExportProfile"},
    {Method::SetProfileFavorite, "SetProfileFavorite"},
    {Method::SetProfileCredentials, "SetProfileCredentials"},
    {Method::Connect, "Connect"},
    {Method::Disconnect, "Disconnect"},
    {Method::DisconnectAll, "DisconnectAll"},
    {Method::Reconnect, "Reconnect"},
    {Method::AnswerChallenge, "AnswerChallenge"},
    {Method::GetTunnels, "GetTunnels"},
    {Method::GetStatistics, "GetStatistics"},
    {Method::SetPrimaryTunnel, "SetPrimaryTunnel"},
    {Method::GetRoutingPolicy, "GetRoutingPolicy"},
    {Method::SetRoutingPolicy, "SetRoutingPolicy"},
    {Method::GetSplitTunnelConfig, "GetSplitTunnelConfig"},
    {Method::SetSplitTunnelConfig, "SetSplitTunnelConfig"},
    {Method::ListProcesses, "ListProcesses"},
    {Method::ListInstalledApps, "ListInstalledApps"},
    {Method::GetApplicationIcon, "GetApplicationIcon"},
    {Method::GetFirewallPolicy, "GetFirewallPolicy"},
    {Method::SetFirewallPolicy, "SetFirewallPolicy"},
    {Method::RunLeakTest, "RunLeakTest"},
    {Method::GetNetworkState, "GetNetworkState"},
    {Method::GetSettings, "GetSettings"},
    {Method::SetSettings, "SetSettings"},
    {Method::GetLogs, "GetLogs"},
    {Method::GetServiceInfo, "GetServiceInfo"},
}};

struct NamedEvent {
    EventKind        kind;
    std::string_view name;
};

constexpr std::array<NamedEvent, 9> kEvents{{
    {EventKind::TunnelStateChanged, "TunnelStateChanged"},
    {EventKind::StatisticsTick, "StatisticsTick"},
    {EventKind::AuthChallenge, "AuthChallenge"},
    {EventKind::NetworkChanged, "NetworkChanged"},
    {EventKind::LeakDetected, "LeakDetected"},
    {EventKind::ProfileListChanged, "ProfileListChanged"},
    {EventKind::UpdateProgress, "UpdateProgress"},
    {EventKind::LogRecord, "LogRecord"},
    {EventKind::ServiceShuttingDown, "ServiceShuttingDown"},
}};

/// Every enumerator that may legally appear on the wire. Decoding checks
/// against this rather than casting an arbitrary integer into the enum, which
/// would be undefined behaviour for an out-of-range value.
bool isKnownMethod(u16 raw, Method& out) noexcept
{
    for (const auto& entry : kMethods) {
        if (static_cast<u16>(entry.method) == raw) {
            out = entry.method;
            return true;
        }
    }
    // Methods without a display name are still valid wire values.
    switch (raw) {
    case static_cast<u16>(Method::ExportSupportBundle):
        out = Method::ExportSupportBundle;
        return true;
    case static_cast<u16>(Method::CheckForUpdate):
        out = Method::CheckForUpdate;
        return true;
    case static_cast<u16>(Method::DownloadUpdate):
        out = Method::DownloadUpdate;
        return true;
    case static_cast<u16>(Method::InstallUpdate):
        out = Method::InstallUpdate;
        return true;
    default:
        return false;
    }
}

bool isKnownEvent(u16 raw, EventKind& out) noexcept
{
    for (const auto& entry : kEvents) {
        if (static_cast<u16>(entry.kind) == raw) {
            out = entry.kind;
            return true;
        }
    }
    return false;
}

} // namespace

std::string_view toString(Method method) noexcept
{
    for (const auto& entry : kMethods) {
        if (entry.method == method) {
            return entry.name;
        }
    }
    switch (method) {
    case Method::ExportSupportBundle: return "ExportSupportBundle";
    case Method::CheckForUpdate:      return "CheckForUpdate";
    case Method::DownloadUpdate:      return "DownloadUpdate";
    case Method::InstallUpdate:       return "InstallUpdate";
    default:                          return "Unknown";
    }
}

std::string_view toString(EventKind kind) noexcept
{
    for (const auto& entry : kEvents) {
        if (entry.kind == kind) {
            return entry.name;
        }
    }
    return "Unknown";
}

// --- encoding -------------------------------------------------------------

Json encode(const Request& request)
{
    return Json{{"type", "request"},
                {"protocol", version::kIpcProtocol},
                {"id", request.id},
                {"method", static_cast<u16>(request.method)},
                {"methodName", toString(request.method)},
                {"params", request.params}};
}

Json encode(const Response& response)
{
    Json value{{"type", "response"},
               {"protocol", version::kIpcProtocol},
               {"id", response.id},
               {"success", response.success}};

    if (response.success) {
        value["result"] = response.result;
    } else {
        value["error"] = Json{{"code", static_cast<u16>(response.errorCode)},
                              {"name", nova::toString(response.errorCode)},
                              {"message", response.errorMessage},
                              {"platform", response.platformCode}};
    }
    return value;
}

Json encode(const Event& event)
{
    return Json{{"type", "event"},
                {"protocol", version::kIpcProtocol},
                {"id", 0},
                {"event", static_cast<u16>(event.kind)},
                {"eventName", toString(event.kind)},
                {"payload", event.payload}};
}

// --- decoding -------------------------------------------------------------

Result<Request> decodeRequest(const Json& value)
{
    if (!value.is_object()) {
        return Status{ErrorCode::IpcProtocol, "frame is not a JSON object"};
    }
    if (json::get<std::string>(value, "/type", "") != "request") {
        return Status{ErrorCode::IpcProtocol, "frame is not a request"};
    }

    const int protocol = json::get<int>(value, "/protocol", 0);
    if (protocol != version::kIpcProtocol) {
        return Status{ErrorCode::ServiceVersion,
                      "client speaks protocol " + std::to_string(protocol) + ", service speaks " +
                          std::to_string(version::kIpcProtocol)};
    }

    const int rawMethod = json::get<int>(value, "/method", -1);
    if (rawMethod < 0 || rawMethod > 0xFFFF) {
        return Status{ErrorCode::IpcProtocol, "request has no method"};
    }

    Request request;
    if (!isKnownMethod(static_cast<u16>(rawMethod), request.method)) {
        return Status{ErrorCode::IpcProtocol,
                      "unknown method " + std::to_string(rawMethod)};
    }

    request.id = json::get<u64>(value, "/id", 0);
    if (request.id == 0) {
        return Status{ErrorCode::IpcProtocol, "request id must be non-zero"};
    }

    if (value.contains("params")) {
        if (!value["params"].is_object()) {
            return Status{ErrorCode::IpcProtocol, "params must be an object"};
        }
        request.params = value["params"];
    }
    return request;
}

Result<Response> decodeResponse(const Json& value)
{
    if (!value.is_object()) {
        return Status{ErrorCode::IpcProtocol, "frame is not a JSON object"};
    }
    if (json::get<std::string>(value, "/type", "") != "response") {
        return Status{ErrorCode::IpcProtocol, "frame is not a response"};
    }

    Response response;
    response.id      = json::get<u64>(value, "/id", 0);
    response.success = json::get<bool>(value, "/success", false);

    if (response.success) {
        if (value.contains("result")) {
            response.result = value["result"];
        }
        return response;
    }

    const int code = json::get<int>(value, "/error/code", static_cast<int>(ErrorCode::Unknown));
    response.errorCode    = static_cast<ErrorCode>(static_cast<u16>(code));
    response.errorMessage = json::get<std::string>(value, "/error/message", "");
    response.platformCode = json::get<u32>(value, "/error/platform", 0);
    return response;
}

Result<Event> decodeEvent(const Json& value)
{
    if (!value.is_object()) {
        return Status{ErrorCode::IpcProtocol, "frame is not a JSON object"};
    }
    if (json::get<std::string>(value, "/type", "") != "event") {
        return Status{ErrorCode::IpcProtocol, "frame is not an event"};
    }

    const int raw = json::get<int>(value, "/event", -1);
    if (raw < 0 || raw > 0xFFFF) {
        return Status{ErrorCode::IpcProtocol, "event has no kind"};
    }

    Event event;
    if (!isKnownEvent(static_cast<u16>(raw), event.kind)) {
        // Forward compatibility: an unknown event from a newer service is
        // ignorable, but the caller decides, so it is reported rather than
        // silently dropped here.
        return Status{ErrorCode::IpcProtocol, "unknown event " + std::to_string(raw)};
    }
    if (value.contains("payload")) {
        event.payload = value["payload"];
    }
    return event;
}

Response makeSuccess(u64 requestId, Json result)
{
    Response response;
    response.id      = requestId;
    response.success = true;
    response.result  = std::move(result);
    return response;
}

Response makeError(u64 requestId, const Status& status)
{
    Response response;
    response.id           = requestId;
    response.success      = false;
    response.errorCode    = status.isOk() ? ErrorCode::Unknown : status.code();
    response.errorMessage = status.message();
    response.platformCode = status.platformCode();
    return response;
}

// --- framing --------------------------------------------------------------

Result<std::vector<u8>> frame(const Json& value)
{
    std::string text;
    try {
        text = value.dump();
    } catch (const Json::exception& ex) {
        return Status{ErrorCode::SerializationError,
                      std::string{"cannot serialise frame: "} + ex.what()};
    }

    if (text.size() > kMaxFrameBytes) {
        return Status{ErrorCode::IpcProtocol,
                      "frame of " + std::to_string(text.size()) + " bytes exceeds the limit"};
    }

    std::vector<u8> out;
    out.resize(4 + text.size());

    const u32 length = static_cast<u32>(text.size());
    out[0] = static_cast<u8>(length & 0xFF);
    out[1] = static_cast<u8>((length >> 8) & 0xFF);
    out[2] = static_cast<u8>((length >> 16) & 0xFF);
    out[3] = static_cast<u8>((length >> 24) & 0xFF);

    std::memcpy(out.data() + 4, text.data(), text.size());
    return out;
}

Result<u32> readFrameLength(std::span<const u8> prefix)
{
    if (prefix.size() < 4) {
        return Status{ErrorCode::IpcProtocol, "short frame prefix"};
    }

    const u32 length = static_cast<u32>(prefix[0]) | (static_cast<u32>(prefix[1]) << 8) |
                       (static_cast<u32>(prefix[2]) << 16) | (static_cast<u32>(prefix[3]) << 24);

    if (length == 0) {
        return Status{ErrorCode::IpcProtocol, "empty frame"};
    }
    if (length > kMaxFrameBytes) {
        return Status{ErrorCode::IpcProtocol,
                      "frame of " + std::to_string(length) + " bytes exceeds the limit"};
    }
    return length;
}

Result<Json> parseFrame(std::span<const u8> body)
{
    return json::parse(
        std::string_view{reinterpret_cast<const char*>(body.data()), body.size()});
}

// --- hello ----------------------------------------------------------------

Json encode(const HelloParams& params)
{
    return Json{{"protocolVersion", params.protocolVersion},
                {"clientVersion", params.clientVersion},
                {"clientName", params.clientName}};
}

Result<HelloParams> decodeHelloParams(const Json& value)
{
    HelloParams params;
    params.protocolVersion = json::get<int>(value, "/protocolVersion", 0);
    params.clientVersion   = json::get<std::string>(value, "/clientVersion", "");
    params.clientName      = json::get<std::string>(value, "/clientName", "");
    if (params.protocolVersion == 0) {
        return Status{ErrorCode::IpcProtocol, "hello is missing protocolVersion"};
    }
    return params;
}

Json encode(const HelloResult& result)
{
    return Json{{"protocolVersion", result.protocolVersion},
                {"serviceVersion", result.serviceVersion},
                {"callerIsAdministrator", result.callerIsAdministrator},
                {"uptimeSeconds", static_cast<i64>(result.uptime.count())}};
}

Result<HelloResult> decodeHelloResult(const Json& value)
{
    HelloResult result;
    result.protocolVersion       = json::get<int>(value, "/protocolVersion", 0);
    result.serviceVersion        = json::get<std::string>(value, "/serviceVersion", "");
    result.callerIsAdministrator = json::get<bool>(value, "/callerIsAdministrator", false);
    result.uptime = Seconds{json::get<i64>(value, "/uptimeSeconds", 0)};
    if (result.protocolVersion == 0) {
        return Status{ErrorCode::IpcProtocol, "hello result is missing protocolVersion"};
    }
    return result;
}

bool requiresAdministrator(Method method) noexcept
{
    switch (method) {
    // Machine-wide policy: a standard user may observe it but not change it.
    // These alter how the whole machine's traffic is treated (kill switch,
    // routing, split-tunnel enforcement, service settings) or install code.
    case Method::SetRoutingPolicy:
    case Method::SetSplitTunnelConfig:
    case Method::SetFirewallPolicy:
    case Method::SetSettings:
    case Method::InstallUpdate:
        return true;
    // Profile management (add/import/update/delete) is a normal user operation:
    // a profile only affects connections the user chooses to start, it does not
    // change machine-wide policy on its own. Requiring elevation to add your own
    // .ovpn would make the product unusable for a standard user, so it is not
    // gated here (the service still validates every profile before storing it).
    default:
        return false;
    }
}

} // namespace nova::ipc
