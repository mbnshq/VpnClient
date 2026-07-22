// End-to-end IPC over a real named pipe: an in-process server and client on a
// unique pipe name. The client's SYSTEM-owner check is relaxed for the test by
// running both ends in the same (non-SYSTEM) process - so these focus on the
// framing, dispatch, handshake, authorisation and event paths. The owner check
// itself is covered by the IpcPeerUntrusted path in a separate assertion.
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Core/Version.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Services/IpcClient.h>
#include <NovaVPN/Services/IpcServer.h>

#include <catch2/catch_test_macros.hpp>

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using namespace nova;
using namespace nova::ipc;

namespace {

std::string uniquePipeName()
{
    return "NovaVPN.Test." + Uuid::generate().toString();
}

constexpr Milliseconds kTimeout{5000};

} // namespace

// The client verifies the pipe owner is SYSTEM. In the test process the pipe is
// owned by the (non-SYSTEM) test user, so connect must refuse with
// IpcPeerUntrusted. This proves the anti-impersonation gate fires; the
// remaining tests bypass it by testing server dispatch directly.
TEST_CASE("the client refuses a pipe not owned by SYSTEM", "[ipc][security]")
{
    const std::string pipe = uniquePipeName();

    auto server = makeIpcServer(std::string{version::kString});
    REQUIRE(server->start(pipe).isOk());

    auto client = makeIpcClient("test");
    const Status status = client->connect(pipe, kTimeout);

    REQUIRE(status.isError());
    REQUIRE(status.code() == ErrorCode::IpcPeerUntrusted);

    server->stop();
}

// To exercise the request/response and event paths without SYSTEM, drive the
// server through a lightweight raw client that skips the owner check. This is
// the same wire format the real client speaks.
namespace {

class RawClient {
public:
    ~RawClient() { close(); }

    Status connect(const std::string& pipeName)
    {
        const std::wstring path = L"\\\\.\\pipe\\" + win::toWide(pipeName);
        for (int attempt = 0; attempt < 50; ++attempt) {
            m_pipe = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                   OPEN_EXISTING, 0, nullptr);
            if (m_pipe != INVALID_HANDLE_VALUE) {
                DWORD mode = PIPE_READMODE_BYTE;
                ::SetNamedPipeHandleState(m_pipe, &mode, nullptr, nullptr);
                return Status::ok();
            }
            std::this_thread::sleep_for(Milliseconds{20});
        }
        return err::timeout("could not open test pipe");
    }

    Result<Response> call(u64 id, Method method, Json params)
    {
        Request request;
        request.id     = id;
        request.method = method;
        request.params = std::move(params);

        auto framed = frame(encode(request));
        if (framed.isError()) {
            return framed.status();
        }
        DWORD written = 0;
        ::WriteFile(m_pipe, framed.value().data(), static_cast<DWORD>(framed.value().size()),
                    &written, nullptr);

        // Read frames until we get the matching response (skip events).
        for (int i = 0; i < 20; ++i) {
            u8 prefix[4]{};
            if (!readExact(prefix, 4)) {
                return err::io("read prefix");
            }
            auto length = readFrameLength(std::span{prefix, 4});
            if (length.isError()) {
                return length.status();
            }
            std::vector<u8> body(length.value());
            if (!readExact(body.data(), length.value())) {
                return err::io("read body");
            }
            auto parsed = parseFrame(body);
            if (parsed.isError()) {
                return parsed.status();
            }
            if (json::get<std::string>(parsed.value(), "/type", "") == "response") {
                return decodeResponse(parsed.value());
            }
        }
        return err::timeout("no response");
    }

    void close()
    {
        if (m_pipe != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_pipe);
            m_pipe = INVALID_HANDLE_VALUE;
        }
    }

private:
    bool readExact(void* buffer, DWORD size)
    {
        auto* cursor = static_cast<u8*>(buffer);
        DWORD remaining = size;
        while (remaining > 0) {
            DWORD read = 0;
            if (::ReadFile(m_pipe, cursor, remaining, &read, nullptr) == FALSE || read == 0) {
                return false;
            }
            cursor += read;
            remaining -= read;
        }
        return true;
    }

    HANDLE m_pipe = INVALID_HANDLE_VALUE;
};

} // namespace

TEST_CASE("Hello must be the first request", "[ipc]")
{
    const std::string pipe = uniquePipeName();
    auto server = makeIpcServer(std::string{version::kString});
    REQUIRE(server->start(pipe).isOk());

    RawClient client;
    REQUIRE(client.connect(pipe).isOk());

    // A non-Hello first request is rejected.
    auto premature = client.call(1, Method::ListProfiles, Json::object());
    REQUIRE(premature.isOk());
    REQUIRE_FALSE(premature.value().success);
    REQUIRE(premature.value().errorCode == ErrorCode::IpcProtocol);

    server->stop();
}

TEST_CASE("a registered handler serves requests after Hello", "[ipc]")
{
    const std::string pipe = uniquePipeName();
    auto server = makeIpcServer(std::string{version::kString});

    std::atomic<int> calls{0};
    REQUIRE(server
                ->setHandler(Method::GetServiceInfo,
                             [&calls](const RequestContext& ctx) {
                                 ++calls;
                                 return makeSuccess(ctx.request.id, Json{{"ok", true}});
                             })
                .isOk());
    REQUIRE(server->start(pipe).isOk());

    RawClient client;
    REQUIRE(client.connect(pipe).isOk());

    HelloParams params;
    params.protocolVersion = version::kIpcProtocol;
    params.clientName      = "raw";
    auto hello = client.call(1, Method::Hello, encode(params));
    REQUIRE(hello.isOk());
    REQUIRE(hello.value().success);

    auto response = client.call(2, Method::GetServiceInfo, Json::object());
    REQUIRE(response.isOk());
    REQUIRE(response.value().success);
    REQUIRE(response.value().result["ok"] == true);
    REQUIRE(calls.load() == 1);

    server->stop();
}

TEST_CASE("a privileged method is refused for a non-admin caller",
          "[ipc][security]")
{
    const std::string pipe = uniquePipeName();
    auto server = makeIpcServer(std::string{version::kString});

    // Register a handler that must never be reached by a non-admin caller.
    std::atomic<int> reached{0};
    REQUIRE(server
                ->setHandler(Method::SetFirewallPolicy,
                             [&reached](const RequestContext& ctx) {
                                 ++reached;
                                 return makeSuccess(ctx.request.id, Json::object());
                             })
                .isOk());
    REQUIRE(server->start(pipe).isOk());

    RawClient client;
    REQUIRE(client.connect(pipe).isOk());

    HelloParams params;
    params.protocolVersion = version::kIpcProtocol;
    auto hello = client.call(1, Method::Hello, encode(params));
    REQUIRE(hello.isOk());

    // The test process is not elevated, so a privileged method is refused
    // before the handler runs.
    auto denied = client.call(2, Method::SetFirewallPolicy, Json::object());
    REQUIRE(denied.isOk());
    REQUIRE_FALSE(denied.value().success);
    REQUIRE(denied.value().errorCode == ErrorCode::PermissionDenied);
    REQUIRE(reached.load() == 0);

    server->stop();
}

TEST_CASE("an unhandled method returns NotImplemented", "[ipc]")
{
    const std::string pipe = uniquePipeName();
    auto server = makeIpcServer(std::string{version::kString});
    REQUIRE(server->start(pipe).isOk());

    RawClient client;
    REQUIRE(client.connect(pipe).isOk());
    HelloParams params;
    params.protocolVersion = version::kIpcProtocol;
    REQUIRE(client.call(1, Method::Hello, encode(params)).isOk());

    auto response = client.call(2, Method::GetTunnels, Json::object());
    REQUIRE(response.isOk());
    REQUIRE_FALSE(response.value().success);
    REQUIRE(response.value().errorCode == ErrorCode::NotImplemented);

    server->stop();
}

TEST_CASE("setting a handler twice is refused", "[ipc]")
{
    auto server = makeIpcServer(std::string{version::kString});
    auto handler = [](const RequestContext& ctx) {
        return makeSuccess(ctx.request.id, Json::object());
    };
    REQUIRE(server->setHandler(Method::GetServiceInfo, handler).isOk());
    REQUIRE(server->setHandler(Method::GetServiceInfo, handler).code() ==
            ErrorCode::AlreadyExists);
}

TEST_CASE("the server starts and stops cleanly and is idempotent", "[ipc]")
{
    const std::string pipe = uniquePipeName();
    auto server = makeIpcServer(std::string{version::kString});

    REQUIRE(server->start(pipe).isOk());
    REQUIRE(server->isRunning());
    REQUIRE(server->start(pipe).code() == ErrorCode::InvalidState); // already running

    server->stop();
    REQUIRE_FALSE(server->isRunning());
    server->stop(); // idempotent
}
