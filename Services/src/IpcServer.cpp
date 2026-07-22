#include <NovaVPN/Core/Handle.h>
#include <NovaVPN/Core/Version.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Services/IpcServer.h>

#include <Windows.h>
#include <sddl.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "advapi32.lib")

using nova::logs::Channel;

namespace nova::ipc {
namespace {

struct HandleTraits {
    using value_type = HANDLE;
    static value_type invalid() noexcept { return INVALID_HANDLE_VALUE; }
    static void close(value_type handle) noexcept { ::CloseHandle(handle); }
};
using PipeHandle = win::UniqueResource<HandleTraits>;

struct EventTraits {
    using value_type = HANDLE;
    static value_type invalid() noexcept { return nullptr; }
    static void close(value_type handle) noexcept { ::CloseHandle(handle); }
};
using EventHandle = win::UniqueResource<EventTraits>;

std::wstring fullPipePath(const std::string& name)
{
    return L"\\\\.\\pipe\\" + win::toWide(name);
}

/// DACL: SYSTEM and Administrators get full control, the built-in Users group
/// gets generic read/write (enough to connect and exchange frames) and nothing
/// else. This is the boundary that stops an arbitrary process from gaining a
/// privileged handle to the service.
Result<PSECURITY_DESCRIPTOR> buildPipeSecurity()
{
    // D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;BU)
    static constexpr const wchar_t* kSddl =
        L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;BU)";

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(kSddl, SDDL_REVISION_1,
                                                               &descriptor, nullptr) == FALSE) {
        return win::lastError("ConvertStringSecurityDescriptorToSecurityDescriptor(pipe)");
    }
    return descriptor;
}

/// Reads exactly `size` bytes or fails. Honours a stop signal between reads.
Status readExact(HANDLE pipe, void* buffer, DWORD size)
{
    auto* cursor = static_cast<u8*>(buffer);
    DWORD remaining = size;
    while (remaining > 0) {
        DWORD read = 0;
        if (::ReadFile(pipe, cursor, remaining, &read, nullptr) == FALSE) {
            return win::lastError("ReadFile(pipe)");
        }
        if (read == 0) {
            return Status{ErrorCode::ConnectionReset, "pipe closed by peer"};
        }
        cursor += read;
        remaining -= read;
    }
    return Status::ok();
}

Status writeAll(HANDLE pipe, const u8* data, std::size_t size)
{
    std::size_t remaining = size;
    while (remaining > 0) {
        DWORD written = 0;
        const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(remaining, 1u << 20));
        if (::WriteFile(pipe, data, chunk, &written, nullptr) == FALSE) {
            return win::lastError("WriteFile(pipe)");
        }
        data += written;
        remaining -= written;
    }
    return Status::ok();
}

/// Reads one length-prefixed frame. Enforces the size cap on the prefix alone.
Result<Json> readFrame(HANDLE pipe)
{
    u8 prefix[4]{};
    NOVA_RETURN_IF_ERROR(readExact(pipe, prefix, 4));

    NOVA_ASSIGN_OR_RETURN(const u32 length, readFrameLength(std::span{prefix, 4}));

    std::vector<u8> body(length);
    NOVA_RETURN_IF_ERROR(readExact(pipe, body.data(), length));
    return parseFrame(body);
}

class IpcServer final : public IIpcServer {
public:
    explicit IpcServer(std::string serviceVersion) : m_serviceVersion(std::move(serviceVersion))
    {
    }

    ~IpcServer() override { stop(); }

    Status setHandler(Method method, RequestHandler handler) override
    {
        if (!handler) {
            return err::invalidArgument("null handler");
        }
        std::lock_guard lock{m_handlerMutex};
        if (m_handlers.count(method) != 0) {
            return err::alreadyExists("handler already set for " + std::string{toString(method)});
        }
        m_handlers.emplace(method, std::move(handler));
        return Status::ok();
    }

    Status start(const std::string& pipeName) override
    {
        std::lock_guard lock{m_lifecycleMutex};
        if (m_running) {
            return err::invalidState("IPC server already running");
        }
        m_pipePath = fullPipePath(pipeName);
        m_running  = true;
        m_stopping = false;

        // A manual-reset event the listener signals once the first pipe
        // instance exists, so a client that connects immediately after start()
        // returns does not race the listener into a NotFound.
        m_readyEvent.reset(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!m_readyEvent) {
            m_running = false;
            return win::lastError("CreateEvent(ipc ready)");
        }

        m_listener = std::thread([this] { listenLoop(); });

        if (::WaitForSingleObject(m_readyEvent.get(), 5000) != WAIT_OBJECT_0) {
            m_stopping = true;
            wakeListener();
            if (m_listener.joinable()) {
                m_listener.join();
            }
            m_running = false;
            return Status{ErrorCode::IpcTransport, "IPC server did not become ready"};
        }

        NOVA_LOG_INFO(Channel::Ipc, "IPC server listening").field("pipe", pipeName);
        return Status::ok();
    }

    void stop() override
    {
        {
            std::lock_guard lock{m_lifecycleMutex};
            if (!m_running) {
                return;
            }
            m_stopping = true;
        }

        // Nudge the listener out of ConnectNamedPipe by connecting to the pipe
        // ourselves, then let it observe the stop flag and exit.
        wakeListener();
        if (m_listener.joinable()) {
            m_listener.join();
        }

        // Close all live connections and wait for their threads.
        std::vector<std::thread> workers;
        {
            std::lock_guard lock{m_connMutex};
            for (auto& [id, conn] : m_connections) {
                if (conn->pipe) {
                    ::CancelIoEx(conn->pipe.get(), nullptr);
                    ::DisconnectNamedPipe(conn->pipe.get());
                }
            }
        }
        {
            std::lock_guard lock{m_workerMutex};
            workers.swap(m_workers);
        }
        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }

        {
            std::lock_guard lock{m_connMutex};
            m_connections.clear();
        }
        std::lock_guard lock{m_lifecycleMutex};
        m_running = false;
        NOVA_LOG_INFO(Channel::Ipc, "IPC server stopped");
    }

    void broadcast(const Event& event) override
    {
        auto framed = frame(encode(event));
        if (framed.isError()) {
            return;
        }

        std::vector<std::shared_ptr<Connection>> targets;
        {
            std::lock_guard lock{m_connMutex};
            for (auto& [id, conn] : m_connections) {
                if (conn->ready.load(std::memory_order_acquire)) {
                    targets.push_back(conn);
                }
            }
        }

        for (auto& conn : targets) {
            // Serialise writes per connection so an event never interleaves with
            // a response mid-frame.
            std::lock_guard lock{conn->writeMutex};
            if (conn->pipe) {
                (void)writeAll(conn->pipe.get(), framed.value().data(), framed.value().size());
            }
        }
    }

    std::size_t connectionCount() const override
    {
        std::lock_guard lock{m_connMutex};
        return m_connections.size();
    }

    bool isRunning() const override
    {
        std::lock_guard lock{m_lifecycleMutex};
        return m_running;
    }

private:
    struct Connection {
        u64        id = 0;
        PipeHandle pipe;
        std::mutex writeMutex;
        std::atomic<bool> ready{false}; // true once Hello has completed
    };

    void wakeListener()
    {
        // A client open of the pipe unblocks ConnectNamedPipe; we open and
        // immediately close.
        HANDLE h = ::CreateFileW(m_pipePath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0,
                                 nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            ::CloseHandle(h);
        }
    }

    void listenLoop()
    {
        ::SetThreadDescription(::GetCurrentThread(), L"NovaVPN.IpcListener");

        auto security = buildPipeSecurity();
        if (security.isError()) {
            NOVA_LOG_ERROR(Channel::Ipc, "cannot build pipe security").status(security.status());
            return;
        }

        SECURITY_ATTRIBUTES attributes{};
        attributes.nLength              = sizeof(attributes);
        attributes.lpSecurityDescriptor = security.value();
        attributes.bInheritHandle       = FALSE;

        while (!m_stopping.load(std::memory_order_acquire)) {
            PipeHandle pipe{::CreateNamedPipeW(
                m_pipePath.c_str(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, &attributes)};

            if (!pipe) {
                NOVA_LOG_ERROR(Channel::Ipc, "CreateNamedPipe failed")
                    .status(win::lastError("CreateNamedPipe"));
                if (m_readyEvent) {
                    ::SetEvent(m_readyEvent.get()); // unblock start(), which will fail out
                }
                break;
            }

            // The pipe instance now exists; let start() return.
            if (m_readyEvent) {
                ::SetEvent(m_readyEvent.get());
            }

            const BOOL connected =
                ::ConnectNamedPipe(pipe.get(), nullptr) != FALSE ||
                ::GetLastError() == ERROR_PIPE_CONNECTED;

            if (m_stopping.load(std::memory_order_acquire)) {
                break;
            }
            if (!connected) {
                continue;
            }

            const u64 id = m_nextConnectionId.fetch_add(1);
            auto conn    = std::make_shared<Connection>();
            conn->id     = id;
            conn->pipe   = std::move(pipe);

            {
                std::lock_guard lock{m_connMutex};
                m_connections.emplace(id, conn);
            }
            std::lock_guard lock{m_workerMutex};
            m_workers.emplace_back([this, conn] { serveConnection(conn); });
        }

        ::LocalFree(security.value());
    }

    void serveConnection(std::shared_ptr<Connection> conn)
    {
        ::SetThreadDescription(::GetCurrentThread(), L"NovaVPN.IpcConn");

        const bool isAdmin = callerIsAdministrator(conn->pipe.get());
        bool helloDone = false;

        while (!m_stopping.load(std::memory_order_acquire)) {
            auto frameResult = readFrame(conn->pipe.get());
            if (frameResult.isError()) {
                break; // peer closed or protocol error
            }

            auto decoded = decodeRequest(frameResult.value());
            Response response;
            if (decoded.isError()) {
                response = makeError(0, decoded.status());
            } else {
                response = dispatch(decoded.value(), isAdmin, conn->id, helloDone);
            }

            auto framed = frame(encode(response));
            if (framed.isError()) {
                break;
            }
            {
                std::lock_guard lock{conn->writeMutex};
                if (writeAll(conn->pipe.get(), framed.value().data(), framed.value().size())
                        .isError()) {
                    break;
                }
            }
            if (response.success && helloDone) {
                conn->ready.store(true, std::memory_order_release);
            }
        }

        removeConnection(conn->id);
    }

    Response dispatch(const Request& request, bool isAdmin, u64 connectionId, bool& helloDone)
    {
        // Hello must come first and negotiates the protocol version.
        if (!helloDone) {
            if (request.method != Method::Hello) {
                return makeError(request.id,
                                 Status{ErrorCode::IpcProtocol,
                                        "first request must be Hello"});
            }
            HelloResult result;
            result.protocolVersion       = version::kIpcProtocol;
            result.serviceVersion        = m_serviceVersion;
            result.callerIsAdministrator = isAdmin;
            result.uptime = std::chrono::duration_cast<Seconds>(SteadyClock::now() - m_startedAt);
            helloDone = true;
            return makeSuccess(request.id, encode(result));
        }

        // Privileged methods require an elevated caller, checked against the
        // real token - never the client's say-so.
        if (requiresAdministrator(request.method) && !isAdmin) {
            return makeError(request.id,
                             Status{ErrorCode::PermissionDenied,
                                    std::string{toString(request.method)} +
                                        " requires administrator privileges"});
        }

        RequestHandler handler;
        {
            std::lock_guard lock{m_handlerMutex};
            if (const auto it = m_handlers.find(request.method); it != m_handlers.end()) {
                handler = it->second;
            }
        }
        if (!handler) {
            return makeError(request.id,
                             Status{ErrorCode::NotImplemented,
                                    "no handler for " + std::string{toString(request.method)}});
        }

        RequestContext context;
        context.request              = request;
        context.callerIsAdministrator = isAdmin;
        context.connectionId          = connectionId;
        return handler(context);
    }

    static bool callerIsAdministrator(HANDLE pipe)
    {
        if (::ImpersonateNamedPipeClient(pipe) == FALSE) {
            return false;
        }

        HANDLE token = nullptr;
        bool isAdmin = false;
        if (::OpenThreadToken(::GetCurrentThread(), TOKEN_QUERY, TRUE, &token) != FALSE) {
            TOKEN_ELEVATION elevation{};
            DWORD size = sizeof(elevation);
            if (::GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation),
                                      &size) != FALSE) {
                isAdmin = elevation.TokenIsElevated != 0;
            }
            ::CloseHandle(token);
        }
        ::RevertToSelf();
        return isAdmin;
    }

    void removeConnection(u64 id)
    {
        std::lock_guard lock{m_connMutex};
        m_connections.erase(id);
    }

    std::string  m_serviceVersion;
    std::wstring m_pipePath;
    SteadyTime   m_startedAt = SteadyClock::now();

    mutable std::mutex m_lifecycleMutex;
    bool               m_running = false;
    std::atomic<bool>  m_stopping{false};
    std::thread        m_listener;
    EventHandle        m_readyEvent;

    mutable std::mutex m_handlerMutex;
    std::unordered_map<Method, RequestHandler> m_handlers;

    mutable std::mutex m_connMutex;
    std::unordered_map<u64, std::shared_ptr<Connection>> m_connections;
    std::atomic<u64>   m_nextConnectionId{1};

    std::mutex               m_workerMutex;
    std::vector<std::thread> m_workers;
};

} // namespace

IpcServerPtr makeIpcServer(std::string serviceVersion)
{
    return std::make_shared<IpcServer>(std::move(serviceVersion));
}

} // namespace nova::ipc
