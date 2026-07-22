// NovaVPN - Logs/Sink.h
// Sinks are the output ends of the logging pipeline. The Logger owns them and
// calls write() from its single drain thread, so implementations do not need to
// be thread-safe against each other - only against their own external resource.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Logs/LogRecord.h>

#include <atomic>
#include <filesystem>
#include <memory>
#include <mutex>
#include <vector>

namespace nova::logs {

class ISink {
public:
    virtual ~ISink() = default;

    /// Emits one record. Must not throw; failures are swallowed after being
    /// reported once through lastError().
    virtual void write(const LogRecord& record) noexcept = 0;

    /// Pushes buffered data to the underlying resource.
    virtual void flush() noexcept = 0;

    /// Records below this level are dropped before reaching write().
    [[nodiscard]] virtual Level minimumLevel() const noexcept = 0;
    virtual void setMinimumLevel(Level level) noexcept = 0;

    /// Human-readable name for diagnostics ("file:service.log").
    [[nodiscard]] virtual std::string name() const = 0;
};

using SinkPtr = std::shared_ptr<ISink>;

/// Rotating file sink.
///
/// Writes UTF-8 text (or JSON lines) to <directory>/<baseName>.log, rolling to
/// <baseName>.1.log ... when maxBytes is exceeded and deleting anything older
/// than maxFiles or retentionDays. The file is opened with FILE_SHARE_READ so
/// support can copy it while the service runs.
struct FileSinkOptions {
    std::filesystem::path directory;
    std::string           baseName = "novavpn";
    u64                   maxBytes = 16ull * 1024 * 1024;
    int                   maxFiles = 8;
    int                   retentionDays = 14;
    bool                  jsonLines = false;
    Level                 minimumLevel = Level::Info;
};

[[nodiscard]] Result<SinkPtr> makeFileSink(FileSinkOptions options);

/// OutputDebugString sink - visible in DebugView/the VS output window. Enabled
/// in debug builds and when diagnostics.debugMode is set.
[[nodiscard]] SinkPtr makeDebuggerSink(Level minimumLevel = Level::Trace);

/// Console sink with ANSI colouring, used by the CLI tools and test runner.
[[nodiscard]] SinkPtr makeConsoleSink(Level minimumLevel = Level::Info);

/// Windows Event Log sink. The service writes Error/Fatal here so failures are
/// visible to administrators without opening a log file.
[[nodiscard]] Result<SinkPtr> makeEventLogSink(std::string sourceName,
                                               Level minimumLevel = Level::Error);

/// In-memory ring buffer that the UI reads to populate the live log view.
class RingBufferSink : public ISink {
public:
    explicit RingBufferSink(std::size_t capacity = 4096, Level minimumLevel = Level::Debug);

    void write(const LogRecord& record) noexcept override;
    void flush() noexcept override {}
    [[nodiscard]] Level minimumLevel() const noexcept override;
    void setMinimumLevel(Level level) noexcept override;
    [[nodiscard]] std::string name() const override { return "ring"; }

    /// Snapshot of the buffer, oldest first.
    [[nodiscard]] std::vector<LogRecord> snapshot() const;
    void clear();

private:
    mutable std::mutex     m_mutex;
    std::vector<LogRecord> m_records;
    std::size_t            m_capacity;
    std::size_t            m_next = 0;
    bool                   m_wrapped = false;
    std::atomic<Level>     m_minimumLevel;
};

} // namespace nova::logs
