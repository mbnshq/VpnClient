#include <NovaVPN/Core/Handle.h>
#include <NovaVPN/Core/Version.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Services/IpcClient.h>

#include <Windows.h>
#include <AclAPI.h>
#include <sddl.h>

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>

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

std::wstring fullPipePath(const std::string& name)
{
    return L"\\\\.\\pipe\\" + win::toWide(name);
}

/// Confirms the pipe is owned by the Local System account. Without this a
/// process that squats the pipe name before the service starts could
/// impersonate it and collect whatever the client sends.
Status verifyServerIsSystem(HANDLE pipe)
{
    PSID ownerSid = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;

    const DWORD result = ::GetSecurityInfo(pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
                                           &ownerSid, nullptr, nullptr, nullptr, &descriptor);
    if (result != ERROR_SUCCESS) {
        return win::fromWin32(result, "GetSecurityInfo(pipe owner)");
    }

    // Well-known SID for NT AUTHORITY\SYSTEM.
    PSID systemSid = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    Status status = Status::ok();
    if (::AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0,
                                   0, &systemSid) == FALSE) {
        status = win::lastError("AllocateAndInitializeSid");
    } else {
        if (ownerSid == nullptr || ::EqualSid(ownerSid, systemSid) == FALSE) {
            status = Status{ErrorCode::IpcPeerUntrusted,
                            "the pipe is not owned by SYSTEM; refusing to trust it"};
        }
        ::FreeSid(systemSid);
    }

    if (descriptor != nullptr) {
        ::LocalFree(descriptor);
    }
    return status;
}

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

Result<Json> readFrame(HANDLE pipe)
{
    u8 prefix[4]{};
    NOVA_RETURN_IF_ERROR(readExact(pipe, prefix, 4));
    NOVA_ASSIGN_OR_RETURN(const u32 length, readFrameLength(std::span{prefix, 4}));
    std::vector<u8> body(length);
    NOVA_RETURN_IF_ERROR(readExact(pipe, body.data(), length));
    return parseFrame(body);
}

class IpcClient final : public IIpcClient {
public:
    explicit IpcClient(std::string clientName) : m_clientName(std::move(clientName)) {}

    ~IpcClient() override { disconnect(); }

    Status connect(const std::string& pipeName, Milliseconds timeout) override
    {
        const std::wstring path = fullPipePath(pipeName);
        const auto deadline = SteadyClock::now() + timeout;

        PipeHandle pipe;
        while (true) {
            pipe.reset(::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                     OPEN_EXISTING, 0, nullptr));
            if (pipe) {
                break;
            }
            const DWORD error = ::GetLastError();
            if (error != ERROR_PIPE_BUSY) {
                return win::fromWin32(error, "CreateFile(pipe)");
            }
            const auto remaining = std::chrono::duration_cast<Milliseconds>(
                deadline - SteadyClock::now());
            if (remaining.count() <= 0 ||
                ::WaitNamedPipeW(path.c_str(),
                                 static_cast<DWORD>(remaining.count())) == FALSE) {
                return err::timeout("timed out waiting for the service pipe");
            }
        }

        // Trust check BEFORE any byte is sent.
        NOVA_RETURN_IF_ERROR(verifyServerIsSystem(pipe.get()));

        // Byte mode, matching the server.
        DWORD mode = PIPE_READMODE_BYTE;
        ::SetNamedPipeHandleState(pipe.get(), &mode, nullptr, nullptr);

        {
            std::lock_guard lock{m_mutex};
            m_pipe = std::move(pipe);
        }

        m_receiver = std::thread([this] { receiveLoop(); });

        // Handshake.
        HelloParams params;
        params.protocolVersion = version::kIpcProtocol;
        params.clientVersion   = std::string{version::kString};
        params.clientName      = m_clientName;

        auto response = call(Method::Hello, encode(params), timeout);
        if (response.isError()) {
            disconnect();
            return std::move(response).status().withContext("IPC handshake");
        }
        if (!response.value().success) {
            disconnect();
            return Status{response.value().errorCode, response.value().errorMessage};
        }

        auto hello = decodeHelloResult(response.value().result);
        if (hello.isError()) {
            disconnect();
            return std::move(hello).status();
        }
        if (hello.value().protocolVersion != version::kIpcProtocol) {
            disconnect();
            return Status{ErrorCode::ServiceVersion,
                          "service speaks protocol " +
                              std::to_string(hello.value().protocolVersion)};
        }

        {
            std::lock_guard lock{m_mutex};
            m_serviceInfo = hello.value();
            m_connected   = true;
        }
        NOVA_LOG_INFO(Channel::Ipc, "connected to service")
            .field("version", m_serviceInfo.serviceVersion);
        return Status::ok();
    }

    void disconnect() override
    {
        {
            std::lock_guard lock{m_mutex};
            if (!m_pipe) {
                return;
            }
            m_connected = false;
            ::CancelIoEx(m_pipe.get(), nullptr);
            m_pipe.reset();
        }
        if (m_receiver.joinable()) {
            m_receiver.join();
        }
        // Fail any callers still waiting on a response.
        std::lock_guard lock{m_pendingMutex};
        for (auto& [id, slot] : m_pending) {
            slot->status = Status{ErrorCode::Cancelled, "client disconnected"};
            slot->ready  = true;
            slot->cv.notify_all();
        }
        m_pending.clear();
    }

    Result<Response> call(Method method, Json params, Milliseconds timeout) override
    {
        const u64 id = m_nextId.fetch_add(1);

        Request request;
        request.id     = id;
        request.method = method;
        request.params = std::move(params);

        auto slot = std::make_shared<PendingCall>();
        {
            std::lock_guard lock{m_pendingMutex};
            m_pending.emplace(id, slot);
        }

        auto framed = frame(encode(request));
        if (framed.isError()) {
            cancelPending(id);
            return std::move(framed).status();
        }
        {
            std::lock_guard lock{m_mutex};
            if (!m_pipe) {
                cancelPending(id);
                return err::invalidState("not connected");
            }
            std::lock_guard writeLock{m_writeMutex};
            if (const Status status =
                    writeAll(m_pipe.get(), framed.value().data(), framed.value().size());
                status.isError()) {
                cancelPending(id);
                return status;
            }
        }

        std::unique_lock lock{slot->mutex};
        if (!slot->cv.wait_for(lock, timeout, [&slot] { return slot->ready; })) {
            cancelPending(id);
            return err::timeout("timed out waiting for a response to " +
                                std::string{toString(method)});
        }
        if (slot->status.isError()) {
            return slot->status;
        }
        return slot->response;
    }

    void onEvent(EventHandler handler) override
    {
        std::lock_guard lock{m_mutex};
        m_eventHandler = std::move(handler);
    }

    const HelloResult& serviceInfo() const override
    {
        std::lock_guard lock{m_mutex};
        return m_serviceInfo;
    }

    bool isConnected() const override
    {
        std::lock_guard lock{m_mutex};
        return m_connected;
    }

private:
    struct PendingCall {
        std::mutex              mutex;
        std::condition_variable cv;
        bool                    ready = false;
        Response                response;
        Status                  status;
    };

    void cancelPending(u64 id)
    {
        std::lock_guard lock{m_pendingMutex};
        m_pending.erase(id);
    }

    void receiveLoop()
    {
        ::SetThreadDescription(::GetCurrentThread(), L"NovaVPN.IpcClientRx");

        while (true) {
            HANDLE pipe = nullptr;
            {
                std::lock_guard lock{m_mutex};
                if (!m_pipe) {
                    return;
                }
                pipe = m_pipe.get();
            }

            auto frameResult = readFrame(pipe);
            if (frameResult.isError()) {
                return; // disconnected
            }

            const Json& value = frameResult.value();
            const std::string type = json::get<std::string>(value, "/type", "");

            if (type == "event") {
                if (auto event = decodeEvent(value); event.isOk()) {
                    EventHandler handler;
                    {
                        std::lock_guard lock{m_mutex};
                        handler = m_eventHandler;
                    }
                    if (handler) {
                        handler(event.value());
                    }
                }
                continue;
            }

            auto response = decodeResponse(value);
            if (response.isError()) {
                continue;
            }
            deliverResponse(response.value());
        }
    }

    void deliverResponse(const Response& response)
    {
        std::shared_ptr<PendingCall> slot;
        {
            std::lock_guard lock{m_pendingMutex};
            if (const auto it = m_pending.find(response.id); it != m_pending.end()) {
                slot = it->second;
                m_pending.erase(it);
            }
        }
        if (!slot) {
            return; // late or unknown id
        }
        std::lock_guard lock{slot->mutex};
        slot->response = response;
        slot->ready    = true;
        slot->cv.notify_all();
    }

    std::string m_clientName;

    mutable std::mutex m_mutex;
    PipeHandle         m_pipe;
    bool               m_connected = false;
    HelloResult        m_serviceInfo;
    EventHandler       m_eventHandler;
    std::mutex         m_writeMutex;

    std::mutex m_pendingMutex;
    std::unordered_map<u64, std::shared_ptr<PendingCall>> m_pending;
    std::atomic<u64> m_nextId{1};

    std::thread m_receiver;
};

} // namespace

IpcClientPtr makeIpcClient(std::string clientName)
{
    return std::make_shared<IpcClient>(std::move(clientName));
}

} // namespace nova::ipc
