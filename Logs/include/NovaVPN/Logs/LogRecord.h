// NovaVPN - Logs/LogRecord.h
// The unit of logging. Records carry structured fields rather than a
// pre-formatted string so that sinks can render text for humans and JSON for
// the diagnostics bundle from the same data.
#pragma once

#include <NovaVPN/Core/Types.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace nova::logs {

enum class Level : u8 {
    Trace = 0, ///< Packet-level detail. Debug builds / debug mode only.
    Debug = 1, ///< Protocol steps, state machine transitions.
    Info  = 2, ///< Lifecycle events a support engineer wants to see.
    Warn  = 3, ///< Recovered problems (reconnect, route retry).
    Error = 4, ///< Operation failed; feature degraded.
    Fatal = 5, ///< Process cannot continue.
    Off   = 6, ///< Never emitted; used as a threshold only.
};

[[nodiscard]] std::string_view toString(Level level) noexcept;
[[nodiscard]] bool parseLevel(std::string_view text, Level& out) noexcept;

/// Subsystem tag. Keeps the log filterable ("show me only firewall").
enum class Channel : u8 {
    Core,
    Service,
    Ipc,
    Tunnel,
    Engine,
    Network,
    Dns,
    Routing,
    Firewall,
    SplitTunnel,
    Driver,
    Database,
    Profile,
    Updater,
    Ui,
    Plugin,
    Security,
};

[[nodiscard]] std::string_view toString(Channel channel) noexcept;
[[nodiscard]] bool parseChannel(std::string_view text, Channel& out) noexcept;

/// A structured key/value pair attached to a record.
struct Field {
    std::string key;
    std::string value;
};

struct SourceLocation {
    const char* file = nullptr;
    int         line = 0;
    const char* function = nullptr;
};

struct LogRecord {
    SystemTime         timestamp{};
    Level              level = Level::Info;
    Channel            channel = Channel::Core;
    std::string        message;
    std::vector<Field> fields;
    SourceLocation     location{};
    u32                threadId = 0;
    /// Correlates every record produced by one connection attempt.
    std::string        sessionId;
};

/// "2026-07-22T09:31:44.812Z"
[[nodiscard]] std::string formatTimestamp(SystemTime timestamp);

/// Human-readable single line:
/// "2026-07-22T09:31:44.812Z INFO  [tunnel] connected {profile=HK-01 mtu=1420}"
[[nodiscard]] std::string formatText(const LogRecord& record);

/// One JSON object per line, for machine ingestion and the support bundle.
[[nodiscard]] std::string formatJsonLine(const LogRecord& record);

} // namespace nova::logs
