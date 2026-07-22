#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/Handle.h>
#include <NovaVPN/Core/Paths.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Sink.h>

#include <Windows.h>

#include <algorithm>
#include <cstdio>
#include <system_error>
#include <utility>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace nova::logs {
namespace {

struct FileHandleTraits {
    using value_type = HANDLE;
    static value_type invalid() noexcept { return INVALID_HANDLE_VALUE; }
    static void close(value_type handle) noexcept { ::CloseHandle(handle); }
};
using FileHandle = win::UniqueResource<FileHandleTraits>;

struct EventSourceTraits {
    using value_type = HANDLE;
    static value_type invalid() noexcept { return nullptr; }
    static void close(value_type handle) noexcept { ::DeregisterEventSource(handle); }
};
using EventSourceHandle = win::UniqueResource<EventSourceTraits>;

// -------------------------------------------------------------------------
// File sink
// -------------------------------------------------------------------------
class FileSink final : public ISink {
public:
    explicit FileSink(FileSinkOptions options)
        : m_options(std::move(options)), m_minimumLevel(m_options.minimumLevel)
    {
    }

    Status open()
    {
        NOVA_RETURN_IF_ERROR(paths::ensureDirectory(m_options.directory));
        return openCurrent();
    }

    void write(const LogRecord& record) noexcept override
    {
        std::string line = m_options.jsonLines ? formatJsonLine(record) : formatText(record);
        line.append("\r\n"); // CRLF so Notepad renders support logs correctly.

        std::lock_guard lock{m_mutex};
        if (!m_handle) {
            return;
        }

        if (m_bytesWritten + line.size() > m_options.maxBytes) {
            rotateLocked();
        }

        DWORD written = 0;
        if (::WriteFile(m_handle.get(), line.data(), static_cast<DWORD>(line.size()), &written,
                        nullptr) == FALSE) {
            // A failing log sink must not take the process down and must not
            // spam: close the handle and stay silent until the next rotation.
            m_handle.reset();
            return;
        }
        m_bytesWritten += written;
    }

    void flush() noexcept override
    {
        std::lock_guard lock{m_mutex};
        if (m_handle) {
            ::FlushFileBuffers(m_handle.get());
        }
    }

    [[nodiscard]] Level minimumLevel() const noexcept override
    {
        return m_minimumLevel.load(std::memory_order_relaxed);
    }

    void setMinimumLevel(Level level) noexcept override
    {
        m_minimumLevel.store(level, std::memory_order_relaxed);
    }

    [[nodiscard]] std::string name() const override
    {
        return "file:" + m_options.baseName;
    }

private:
    [[nodiscard]] std::filesystem::path pathForIndex(int index) const
    {
        std::string fileName = m_options.baseName;
        if (index > 0) {
            fileName += "." + std::to_string(index);
        }
        fileName += ".log";
        return m_options.directory / fileName;
    }

    Status openCurrent()
    {
        const std::filesystem::path path = pathForIndex(0);

        // FILE_SHARE_READ|DELETE lets support copy or move the log while the
        // service holds it open.
        FileHandle handle{::CreateFileW(path.c_str(), FILE_APPEND_DATA,
                                        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (!handle) {
            return win::lastError("CreateFile(" + path.string() + ")");
        }

        LARGE_INTEGER size{};
        if (::GetFileSizeEx(handle.get(), &size) != FALSE) {
            m_bytesWritten = static_cast<u64>(size.QuadPart);
        } else {
            m_bytesWritten = 0;
        }

        std::lock_guard lock{m_mutex};
        m_handle = std::move(handle);
        return Status::ok();
    }

    /// Caller must hold m_mutex.
    void rotateLocked() noexcept
    {
        m_handle.reset();

        std::error_code ec;
        // Shift novavpn.(n-1).log -> novavpn.n.log, dropping the oldest.
        const std::filesystem::path oldest = pathForIndex(m_options.maxFiles - 1);
        std::filesystem::remove(oldest, ec);

        for (int index = m_options.maxFiles - 2; index >= 0; --index) {
            const std::filesystem::path from = pathForIndex(index);
            if (!std::filesystem::exists(from, ec)) {
                continue;
            }
            std::filesystem::rename(from, pathForIndex(index + 1), ec);
        }

        purgeExpiredLocked();

        FileHandle handle{::CreateFileW(pathForIndex(0).c_str(), FILE_APPEND_DATA,
                                        FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (handle) {
            m_handle = std::move(handle);
            m_bytesWritten = 0;
        }
    }

    /// Caller must hold m_mutex.
    void purgeExpiredLocked() noexcept
    {
        if (m_options.retentionDays <= 0) {
            return;
        }

        std::error_code ec;
        const auto cutoff = std::filesystem::file_time_type::clock::now() -
                            std::chrono::hours{24 * m_options.retentionDays};

        for (int index = 1; index < m_options.maxFiles; ++index) {
            const std::filesystem::path path = pathForIndex(index);
            if (!std::filesystem::exists(path, ec)) {
                continue;
            }
            const auto written = std::filesystem::last_write_time(path, ec);
            if (!ec && written < cutoff) {
                std::filesystem::remove(path, ec);
            }
        }
    }

    FileSinkOptions    m_options;
    std::atomic<Level> m_minimumLevel;
    std::mutex         m_mutex;
    FileHandle         m_handle;
    u64                m_bytesWritten = 0;
};

// -------------------------------------------------------------------------
// Debugger sink
// -------------------------------------------------------------------------
class DebuggerSink final : public ISink {
public:
    explicit DebuggerSink(Level minimumLevel) : m_minimumLevel(minimumLevel) {}

    void write(const LogRecord& record) noexcept override
    {
        const std::string line = formatText(record) + "\n";
        ::OutputDebugStringW(win::toWide(line).c_str());
    }

    void flush() noexcept override {}

    [[nodiscard]] Level minimumLevel() const noexcept override
    {
        return m_minimumLevel.load(std::memory_order_relaxed);
    }
    void setMinimumLevel(Level level) noexcept override
    {
        m_minimumLevel.store(level, std::memory_order_relaxed);
    }
    [[nodiscard]] std::string name() const override { return "debugger"; }

private:
    std::atomic<Level> m_minimumLevel;
};

// -------------------------------------------------------------------------
// Console sink
// -------------------------------------------------------------------------
class ConsoleSink final : public ISink {
public:
    explicit ConsoleSink(Level minimumLevel) : m_minimumLevel(minimumLevel)
    {
        // Opt into ANSI processing so the colour codes below render instead of
        // appearing literally in redirected output.
        const HANDLE out = ::GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (out != INVALID_HANDLE_VALUE && ::GetConsoleMode(out, &mode) != FALSE) {
            m_colour = ::SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != FALSE;
        }
    }

    void write(const LogRecord& record) noexcept override
    {
        const char* colour = "";
        if (m_colour) {
            switch (record.level) {
            case Level::Trace: colour = "\x1b[90m"; break;
            case Level::Debug: colour = "\x1b[37m"; break;
            case Level::Info:  colour = "\x1b[36m"; break;
            case Level::Warn:  colour = "\x1b[33m"; break;
            case Level::Error: colour = "\x1b[31m"; break;
            case Level::Fatal: colour = "\x1b[97;41m"; break;
            case Level::Off:   break;
            }
        }

        std::lock_guard lock{m_mutex};
        std::fputs(colour, stdout);
        std::fputs(formatText(record).c_str(), stdout);
        if (m_colour) {
            std::fputs("\x1b[0m", stdout);
        }
        std::fputc('\n', stdout);
    }

    void flush() noexcept override
    {
        std::lock_guard lock{m_mutex};
        std::fflush(stdout);
    }

    [[nodiscard]] Level minimumLevel() const noexcept override
    {
        return m_minimumLevel.load(std::memory_order_relaxed);
    }
    void setMinimumLevel(Level level) noexcept override
    {
        m_minimumLevel.store(level, std::memory_order_relaxed);
    }
    [[nodiscard]] std::string name() const override { return "console"; }

private:
    std::atomic<Level> m_minimumLevel;
    std::mutex         m_mutex;
    bool               m_colour = false;
};

// -------------------------------------------------------------------------
// Windows Event Log sink
// -------------------------------------------------------------------------
class EventLogSink final : public ISink {
public:
    EventLogSink(EventSourceHandle source, std::string sourceName, Level minimumLevel)
        : m_source(std::move(source)), m_sourceName(std::move(sourceName)),
          m_minimumLevel(minimumLevel)
    {
    }

    void write(const LogRecord& record) noexcept override
    {
        if (!m_source) {
            return;
        }

        WORD type = EVENTLOG_INFORMATION_TYPE;
        switch (record.level) {
        case Level::Warn:  type = EVENTLOG_WARNING_TYPE; break;
        case Level::Error:
        case Level::Fatal: type = EVENTLOG_ERROR_TYPE; break;
        default:           type = EVENTLOG_INFORMATION_TYPE; break;
        }

        const std::wstring text = win::toWide(formatText(record));
        LPCWSTR strings[1] = {text.c_str()};

        // Without a registered message DLL the viewer shows the inserted string
        // preceded by a "description not found" note; the content is still
        // readable, which is what matters for administrator triage.
        ::ReportEventW(m_source.get(), type, /*category=*/0, /*eventId=*/1000, nullptr,
                       /*numStrings=*/1, /*dataSize=*/0, strings, nullptr);
    }

    void flush() noexcept override {}

    [[nodiscard]] Level minimumLevel() const noexcept override
    {
        return m_minimumLevel.load(std::memory_order_relaxed);
    }
    void setMinimumLevel(Level level) noexcept override
    {
        m_minimumLevel.store(level, std::memory_order_relaxed);
    }
    [[nodiscard]] std::string name() const override { return "eventlog:" + m_sourceName; }

private:
    EventSourceHandle  m_source;
    std::string        m_sourceName;
    std::atomic<Level> m_minimumLevel;
};

} // namespace

Result<SinkPtr> makeFileSink(FileSinkOptions options)
{
    if (options.maxFiles < 1) {
        options.maxFiles = 1;
    }
    if (options.maxBytes < 64 * 1024) {
        options.maxBytes = 64 * 1024;
    }

    auto sink = std::make_shared<FileSink>(std::move(options));
    NOVA_RETURN_IF_ERROR(sink->open());
    return SinkPtr{std::move(sink)};
}

SinkPtr makeDebuggerSink(Level minimumLevel)
{
    return std::make_shared<DebuggerSink>(minimumLevel);
}

SinkPtr makeConsoleSink(Level minimumLevel)
{
    return std::make_shared<ConsoleSink>(minimumLevel);
}

Result<SinkPtr> makeEventLogSink(std::string sourceName, Level minimumLevel)
{
    EventSourceHandle source{::RegisterEventSourceW(nullptr, win::toWide(sourceName).c_str())};
    if (!source) {
        return win::lastError("RegisterEventSource(" + sourceName + ")");
    }
    return SinkPtr{std::make_shared<EventLogSink>(std::move(source), std::move(sourceName),
                                                  minimumLevel)};
}

// -------------------------------------------------------------------------
// Ring buffer sink
// -------------------------------------------------------------------------
RingBufferSink::RingBufferSink(std::size_t capacity, Level minimumLevel)
    : m_capacity(capacity == 0 ? 1 : capacity), m_minimumLevel(minimumLevel)
{
    m_records.resize(m_capacity);
}

void RingBufferSink::write(const LogRecord& record) noexcept
{
    std::lock_guard lock{m_mutex};
    m_records[m_next] = record;
    m_next = (m_next + 1) % m_capacity;
    if (m_next == 0) {
        m_wrapped = true;
    }
}

Level RingBufferSink::minimumLevel() const noexcept
{
    return m_minimumLevel.load(std::memory_order_relaxed);
}

void RingBufferSink::setMinimumLevel(Level level) noexcept
{
    m_minimumLevel.store(level, std::memory_order_relaxed);
}

std::vector<LogRecord> RingBufferSink::snapshot() const
{
    std::lock_guard lock{m_mutex};

    std::vector<LogRecord> out;
    if (m_wrapped) {
        out.reserve(m_capacity);
        out.insert(out.end(), m_records.begin() + static_cast<std::ptrdiff_t>(m_next),
                   m_records.end());
        out.insert(out.end(), m_records.begin(),
                   m_records.begin() + static_cast<std::ptrdiff_t>(m_next));
    } else {
        out.reserve(m_next);
        out.insert(out.end(), m_records.begin(),
                   m_records.begin() + static_cast<std::ptrdiff_t>(m_next));
    }
    return out;
}

void RingBufferSink::clear()
{
    std::lock_guard lock{m_mutex};
    std::fill(m_records.begin(), m_records.end(), LogRecord{});
    m_next    = 0;
    m_wrapped = false;
}

} // namespace nova::logs
