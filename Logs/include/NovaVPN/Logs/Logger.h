// NovaVPN - Logs/Logger.h
// Asynchronous, non-blocking logger.
//
// Design constraints that shaped this:
//   * The tunnel data path may log; it must never block on file I/O. Records go
//     into a bounded queue and a dedicated drain thread feeds the sinks.
//   * When the queue is full, records are dropped and counted rather than
//     stalling the producer. The drop count is emitted once the queue recovers,
//     so a log gap is always visible instead of silent.
//   * Secrets must never reach a sink. Field values pass through a redactor
//     when diagnostics.redactLogs is on (the default).
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Logs/Sink.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace nova::logs {

struct LoggerOptions {
    /// Records below this level are discarded at the call site, before any
    /// formatting cost is paid.
    Level       minimumLevel = Level::Info;
    /// Maximum queued records before dropping. ~8k records ≈ a few MB.
    std::size_t queueCapacity = 8192;
    /// Replace field values that look like secrets with "***".
    bool        redact = true;
    /// Emitted with every record so a support bundle can be tied to a machine.
    std::string instanceId;
};

class Logger final {
public:
    explicit Logger(LoggerOptions options = {});
    ~Logger();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    /// Process-wide logger. Created by the service/UI host at startup; the
    /// default instance writes to the debugger only until configure() runs.
    [[nodiscard]] static Logger& instance();

    void addSink(SinkPtr sink);
    void removeAllSinks();

    [[nodiscard]] Level minimumLevel() const noexcept
    {
        return m_minimumLevel.load(std::memory_order_relaxed);
    }
    void setMinimumLevel(Level level) noexcept
    {
        m_minimumLevel.store(level, std::memory_order_relaxed);
    }

    /// Per-channel override, e.g. Trace for Tunnel while everything else stays
    /// at Info. Set to Level::Off to silence a channel entirely.
    void setChannelLevel(Channel channel, Level level) noexcept;
    [[nodiscard]] Level channelLevel(Channel channel) const noexcept;

    /// Cheap predicate used by the logging macros to skip argument evaluation.
    [[nodiscard]] bool isEnabled(Level level, Channel channel) const noexcept
    {
        return level >= minimumLevel() && level >= channelLevel(channel);
    }

    /// Enqueues a record. Never blocks; returns false if the record was dropped
    /// because the queue was full.
    bool submit(LogRecord record);

    /// Blocks until every queued record has reached the sinks.
    void flush();

    /// Number of records dropped since startup.
    [[nodiscard]] u64 droppedCount() const noexcept
    {
        return m_dropped.load(std::memory_order_relaxed);
    }

    /// Associates subsequent records from this thread with a session id, so all
    /// logs for one connection attempt can be extracted together.
    static void setThreadSessionId(std::string sessionId);
    [[nodiscard]] static const std::string& threadSessionId() noexcept;

private:
    void drainLoop();
    void deliver(const LogRecord& record);

    LoggerOptions            m_options;
    std::atomic<Level>       m_minimumLevel;
    std::atomic<Level>       m_channelLevels[32];

    mutable std::mutex       m_sinkMutex;
    std::vector<SinkPtr>     m_sinks;

    std::mutex               m_queueMutex;
    std::condition_variable  m_queueCv;
    std::condition_variable  m_drainedCv;
    std::deque<LogRecord>    m_queue;
    bool                     m_stopping = false;
    bool                     m_draining = false;

    std::atomic<u64>         m_dropped{0};
    std::thread              m_worker;
};

/// Builder used by the logging macros. Collects fields fluently and submits on
/// destruction: NOVA_LOG_INFO(Channel::Tunnel, "connected").field("mtu", 1420);
class RecordBuilder final {
public:
    RecordBuilder(Logger& logger, Level level, Channel channel, std::string message,
                  SourceLocation location);
    ~RecordBuilder();

    RecordBuilder(const RecordBuilder&) = delete;
    RecordBuilder& operator=(const RecordBuilder&) = delete;

    RecordBuilder& field(std::string key, std::string value);
    RecordBuilder& field(std::string key, const char* value);
    RecordBuilder& field(std::string key, bool value);
    RecordBuilder& field(std::string key, i64 value);
    RecordBuilder& field(std::string key, u64 value);
    RecordBuilder& field(std::string key, i32 value);
    RecordBuilder& field(std::string key, u32 value);
    RecordBuilder& field(std::string key, double value);

    /// Attaches code/message/platform code from a Status in one call.
    RecordBuilder& status(const Status& status);

    /// Marks a value as secret: it is replaced with "***" unless redaction is
    /// disabled, in which case it is truncated to a fingerprint.
    RecordBuilder& secret(std::string key, std::string_view value);

private:
    Logger&   m_logger;
    LogRecord m_record;
    bool      m_enabled;
};

} // namespace nova::logs

#define NOVA_LOG_LOCATION                                                                    \
    ::nova::logs::SourceLocation                                                             \
    {                                                                                        \
        __FILE__, __LINE__, __func__                                                         \
    }

#define NOVA_LOG(level, channel, message)                                                    \
    ::nova::logs::RecordBuilder(::nova::logs::Logger::instance(), (level), (channel),        \
                                (message), NOVA_LOG_LOCATION)

#define NOVA_LOG_TRACE(channel, message) NOVA_LOG(::nova::logs::Level::Trace, (channel), (message))
#define NOVA_LOG_DEBUG(channel, message) NOVA_LOG(::nova::logs::Level::Debug, (channel), (message))
#define NOVA_LOG_INFO(channel, message)  NOVA_LOG(::nova::logs::Level::Info,  (channel), (message))
#define NOVA_LOG_WARN(channel, message)  NOVA_LOG(::nova::logs::Level::Warn,  (channel), (message))
#define NOVA_LOG_ERROR(channel, message) NOVA_LOG(::nova::logs::Level::Error, (channel), (message))
#define NOVA_LOG_FATAL(channel, message) NOVA_LOG(::nova::logs::Level::Fatal, (channel), (message))
