#include <NovaVPN/Core/Json.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Logs/LogRecord.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <ctime>

namespace nova::logs {
namespace {

struct NamedLevel {
    Level            level;
    std::string_view name;
};

constexpr std::array<NamedLevel, 7> kLevels{{{Level::Trace, "trace"},
                                             {Level::Debug, "debug"},
                                             {Level::Info, "info"},
                                             {Level::Warn, "warn"},
                                             {Level::Error, "error"},
                                             {Level::Fatal, "fatal"},
                                             {Level::Off, "off"}}};

struct NamedChannel {
    Channel          channel;
    std::string_view name;
};

constexpr std::array<NamedChannel, 17> kChannels{{{Channel::Core, "core"},
                                                  {Channel::Service, "service"},
                                                  {Channel::Ipc, "ipc"},
                                                  {Channel::Tunnel, "tunnel"},
                                                  {Channel::Engine, "engine"},
                                                  {Channel::Network, "network"},
                                                  {Channel::Dns, "dns"},
                                                  {Channel::Routing, "routing"},
                                                  {Channel::Firewall, "firewall"},
                                                  {Channel::SplitTunnel, "splittunnel"},
                                                  {Channel::Driver, "driver"},
                                                  {Channel::Database, "database"},
                                                  {Channel::Profile, "profile"},
                                                  {Channel::Updater, "updater"},
                                                  {Channel::Ui, "ui"},
                                                  {Channel::Plugin, "plugin"},
                                                  {Channel::Security, "security"}}};

/// Fixed-width level tag so text logs stay column-aligned.
std::string_view paddedLevel(Level level) noexcept
{
    switch (level) {
    case Level::Trace: return "TRACE";
    case Level::Debug: return "DEBUG";
    case Level::Info:  return "INFO ";
    case Level::Warn:  return "WARN ";
    case Level::Error: return "ERROR";
    case Level::Fatal: return "FATAL";
    case Level::Off:   return "OFF  ";
    }
    return "?????";
}

} // namespace

std::string_view toString(Level level) noexcept
{
    for (const auto& entry : kLevels) {
        if (entry.level == level) {
            return entry.name;
        }
    }
    return "unknown";
}

bool parseLevel(std::string_view text, Level& out) noexcept
{
    for (const auto& entry : kLevels) {
        if (str::equalsIgnoreCase(text, entry.name)) {
            out = entry.level;
            return true;
        }
    }
    // Accept the common aliases seen in config files and command lines.
    if (str::equalsIgnoreCase(text, "warning")) {
        out = Level::Warn;
        return true;
    }
    if (str::equalsIgnoreCase(text, "verbose")) {
        out = Level::Trace;
        return true;
    }
    return false;
}

std::string_view toString(Channel channel) noexcept
{
    for (const auto& entry : kChannels) {
        if (entry.channel == channel) {
            return entry.name;
        }
    }
    return "unknown";
}

bool parseChannel(std::string_view text, Channel& out) noexcept
{
    for (const auto& entry : kChannels) {
        if (str::equalsIgnoreCase(text, entry.name)) {
            out = entry.channel;
            return true;
        }
    }
    return false;
}

std::string formatTimestamp(SystemTime timestamp)
{
    using namespace std::chrono;

    const auto since = timestamp.time_since_epoch();
    const auto secs  = duration_cast<seconds>(since);
    const auto millis = duration_cast<milliseconds>(since - secs);

    const std::time_t raw = static_cast<std::time_t>(secs.count());
    std::tm utc{};
    if (::gmtime_s(&utc, &raw) != 0) {
        return "0000-00-00T00:00:00.000Z";
    }

    char buffer[40]{};
    std::snprintf(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday, utc.tm_hour, utc.tm_min,
                  utc.tm_sec, static_cast<int>(millis.count()));
    return std::string{buffer};
}

std::string formatText(const LogRecord& record)
{
    std::string out;
    out.reserve(128 + record.message.size());

    out.append(formatTimestamp(record.timestamp));
    out.push_back(' ');
    out.append(paddedLevel(record.level));
    out.append(" [");
    out.append(toString(record.channel));
    out.append("] ");
    out.append(record.message);

    if (!record.fields.empty()) {
        out.append(" {");
        for (std::size_t i = 0; i < record.fields.size(); ++i) {
            if (i != 0) {
                out.push_back(' ');
            }
            out.append(record.fields[i].key);
            out.push_back('=');
            out.append(record.fields[i].value);
        }
        out.push_back('}');
    }

    if (!record.sessionId.empty()) {
        out.append(" session=");
        out.append(record.sessionId);
    }

    return out;
}

std::string formatJsonLine(const LogRecord& record)
{
    Json entry{
        {"ts", formatTimestamp(record.timestamp)},
        {"level", toString(record.level)},
        {"channel", toString(record.channel)},
        {"msg", record.message},
        {"tid", record.threadId},
    };

    if (!record.sessionId.empty()) {
        entry["session"] = record.sessionId;
    }
    if (!record.fields.empty()) {
        Json fields = Json::object();
        for (const auto& field : record.fields) {
            fields[field.key] = field.value;
        }
        entry["fields"] = std::move(fields);
    }
    if (record.location.file != nullptr) {
        // Only the file name - full build paths leak the build machine layout.
        std::string_view file{record.location.file};
        const std::size_t slash = file.find_last_of("/\\");
        if (slash != std::string_view::npos) {
            file = file.substr(slash + 1);
        }
        entry["src"] = std::string{file} + ":" + std::to_string(record.location.line);
    }

    return entry.dump();
}

} // namespace nova::logs
