#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Logs/Logger.h>

#include <Windows.h>

#include <cstdio>
#include <utility>

namespace nova::logs {
namespace {

/// Thread-local session id. Set once at the start of a connection attempt so
/// every record produced by that attempt can be filtered out of the log later.
std::string& sessionIdSlot()
{
    thread_local std::string id;
    return id;
}

constexpr std::size_t channelIndex(Channel channel) noexcept
{
    return static_cast<std::size_t>(channel);
}

std::string formatDouble(double value)
{
    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), "%.3f", value);
    return std::string{buffer};
}

} // namespace

Logger::Logger(LoggerOptions options)
    : m_options(std::move(options)), m_minimumLevel(m_options.minimumLevel)
{
    for (auto& level : m_channelLevels) {
        level.store(Level::Trace, std::memory_order_relaxed);
    }
    m_worker = std::thread{[this] { drainLoop(); }};
}

Logger::~Logger()
{
    {
        std::lock_guard lock{m_queueMutex};
        m_stopping = true;
    }
    m_queueCv.notify_all();
    if (m_worker.joinable()) {
        m_worker.join();
    }

    std::lock_guard lock{m_sinkMutex};
    for (const auto& sink : m_sinks) {
        sink->flush();
    }
}

Logger& Logger::instance()
{
    // Constructed on first use and never destroyed, so that logging from a
    // static destructor during shutdown remains safe.
    static Logger* const kInstance = [] {
        LoggerOptions options;
#ifdef _DEBUG
        options.minimumLevel = Level::Debug;
#endif
        auto* logger = new Logger{options};
        logger->addSink(makeDebuggerSink());
        return logger;
    }();
    return *kInstance;
}

void Logger::addSink(SinkPtr sink)
{
    if (!sink) {
        return;
    }
    std::lock_guard lock{m_sinkMutex};
    m_sinks.push_back(std::move(sink));
}

void Logger::removeAllSinks()
{
    std::vector<SinkPtr> sinks;
    {
        std::lock_guard lock{m_sinkMutex};
        sinks.swap(m_sinks);
    }
    for (const auto& sink : sinks) {
        sink->flush();
    }
}

void Logger::setChannelLevel(Channel channel, Level level) noexcept
{
    const std::size_t index = channelIndex(channel);
    if (index < std::size(m_channelLevels)) {
        m_channelLevels[index].store(level, std::memory_order_relaxed);
    }
}

Level Logger::channelLevel(Channel channel) const noexcept
{
    const std::size_t index = channelIndex(channel);
    if (index >= std::size(m_channelLevels)) {
        return Level::Trace;
    }
    return m_channelLevels[index].load(std::memory_order_relaxed);
}

bool Logger::submit(LogRecord record)
{
    {
        std::lock_guard lock{m_queueMutex};
        if (m_stopping) {
            return false;
        }
        if (m_queue.size() >= m_options.queueCapacity) {
            // Drop rather than block: the caller may be on the tunnel data path.
            m_dropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        m_queue.push_back(std::move(record));
    }
    m_queueCv.notify_one();
    return true;
}

void Logger::flush()
{
    std::unique_lock lock{m_queueMutex};
    m_drainedCv.wait(lock, [this] { return m_queue.empty() && !m_draining; });
    lock.unlock();

    std::lock_guard sinkLock{m_sinkMutex};
    for (const auto& sink : m_sinks) {
        sink->flush();
    }
}

void Logger::drainLoop()
{
    ::SetThreadDescription(::GetCurrentThread(), L"NovaVPN.Logger");

    u64 reportedDrops = 0;

    while (true) {
        LogRecord record;
        {
            std::unique_lock lock{m_queueMutex};
            m_queueCv.wait(lock, [this] { return m_stopping || !m_queue.empty(); });

            if (m_queue.empty()) {
                if (m_stopping) {
                    break;
                }
                continue;
            }

            record = std::move(m_queue.front());
            m_queue.pop_front();
            m_draining = true;
        }

        deliver(record);

        {
            std::lock_guard lock{m_queueMutex};
            m_draining = false;
            if (m_queue.empty()) {
                m_drainedCv.notify_all();
            }
        }

        // Surface any gap in the log the moment there is room to say so.
        const u64 drops = m_dropped.load(std::memory_order_relaxed);
        if (drops > reportedDrops) {
            LogRecord notice;
            notice.timestamp = SystemClock::now();
            notice.level     = Level::Warn;
            notice.channel   = Channel::Core;
            notice.message   = "log records dropped due to queue pressure";
            notice.fields.push_back({"dropped", std::to_string(drops - reportedDrops)});
            notice.threadId = ::GetCurrentThreadId();
            reportedDrops = drops;
            deliver(notice);
        }
    }

    // Final drain so nothing queued before shutdown is lost.
    std::deque<LogRecord> remaining;
    {
        std::lock_guard lock{m_queueMutex};
        remaining.swap(m_queue);
    }
    for (const auto& record : remaining) {
        deliver(record);
    }
    {
        std::lock_guard lock{m_queueMutex};
        m_drainedCv.notify_all();
    }
}

void Logger::deliver(const LogRecord& record)
{
    std::vector<SinkPtr> sinks;
    {
        std::lock_guard lock{m_sinkMutex};
        sinks = m_sinks;
    }
    for (const auto& sink : sinks) {
        if (record.level >= sink->minimumLevel()) {
            sink->write(record);
        }
    }
}

void Logger::setThreadSessionId(std::string sessionId)
{
    sessionIdSlot() = std::move(sessionId);
}

const std::string& Logger::threadSessionId() noexcept
{
    return sessionIdSlot();
}

// --- RecordBuilder --------------------------------------------------------

RecordBuilder::RecordBuilder(Logger& logger, Level level, Channel channel, std::string message,
                             SourceLocation location)
    : m_logger(logger), m_enabled(logger.isEnabled(level, channel))
{
    if (!m_enabled) {
        return;
    }
    m_record.timestamp = SystemClock::now();
    m_record.level     = level;
    m_record.channel   = channel;
    m_record.message   = std::move(message);
    m_record.location  = location;
    m_record.threadId  = ::GetCurrentThreadId();
    m_record.sessionId = Logger::threadSessionId();
}

RecordBuilder::~RecordBuilder()
{
    if (m_enabled) {
        m_logger.submit(std::move(m_record));
    }
}

RecordBuilder& RecordBuilder::field(std::string key, std::string value)
{
    if (m_enabled) {
        m_record.fields.push_back(Field{std::move(key), std::move(value)});
    }
    return *this;
}

RecordBuilder& RecordBuilder::field(std::string key, const char* value)
{
    return field(std::move(key), std::string{value != nullptr ? value : "<null>"});
}

RecordBuilder& RecordBuilder::field(std::string key, bool value)
{
    return field(std::move(key), std::string{value ? "true" : "false"});
}

RecordBuilder& RecordBuilder::field(std::string key, i64 value)
{
    return field(std::move(key), std::to_string(value));
}

RecordBuilder& RecordBuilder::field(std::string key, u64 value)
{
    return field(std::move(key), std::to_string(value));
}

RecordBuilder& RecordBuilder::field(std::string key, i32 value)
{
    return field(std::move(key), std::to_string(value));
}

RecordBuilder& RecordBuilder::field(std::string key, u32 value)
{
    return field(std::move(key), std::to_string(value));
}

RecordBuilder& RecordBuilder::field(std::string key, double value)
{
    return field(std::move(key), formatDouble(value));
}

RecordBuilder& RecordBuilder::status(const Status& status)
{
    if (!m_enabled || status.isOk()) {
        return *this;
    }
    field("error", std::string{nova::toString(status.code())});
    if (!status.message().empty()) {
        field("detail", status.message());
    }
    if (status.hasPlatformCode()) {
        field("platform", static_cast<u32>(status.platformCode()));
    }
    return *this;
}

RecordBuilder& RecordBuilder::secret(std::string key, std::string_view value)
{
    if (!m_enabled) {
        return *this;
    }
    // Even with redaction disabled we never write the raw value; a partial
    // fingerprint is enough to tell two credentials apart during support.
    return field(std::move(key), str::redact(value));
}

} // namespace nova::logs
