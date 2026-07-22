// IPC under load: many clients connecting and calling the same server
// concurrently, and a server started/stopped repeatedly. Asserts every call is
// answered correctly and nothing deadlocks.
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Core/Version.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Services/IpcServer.h>

#include <catch2/catch_test_macros.hpp>

#include <Windows.h>

#include <atomic>
#include <thread>
#include <vector>

using namespace nova;
using namespace nova::ipc;

namespace {

std::string uniquePipe()
{
    return "NovaVPN.Stress." + Uuid::generate().toString();
}

/// A minimal raw client that does Hello + one echo call and returns success.
bool doOneSession(const std::string& pipeName, int expectEcho)
{
    const std::wstring path = L"\\\\.\\pipe\\" + win::toWide(pipeName);
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 100; ++attempt) {
        pipe = ::CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                             OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) {
            break;
        }
        if (::GetLastError() == ERROR_PIPE_BUSY) {
            ::WaitNamedPipeW(path.c_str(), 2000);
        } else {
            std::this_thread::sleep_for(Milliseconds{5});
        }
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD mode = PIPE_READMODE_BYTE;
    ::SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    const auto writeFrame = [pipe](const Json& value) {
        auto framed = frame(value);
        if (framed.isError()) {
            return false;
        }
        DWORD written = 0;
        return ::WriteFile(pipe, framed.value().data(),
                           static_cast<DWORD>(framed.value().size()), &written, nullptr) != FALSE;
    };
    const auto readResponse = [pipe]() -> Json {
        u8 prefix[4]{};
        DWORD read = 0;
        DWORD off = 0;
        while (off < 4) {
            if (::ReadFile(pipe, prefix + off, 4 - off, &read, nullptr) == FALSE || read == 0) {
                return Json{};
            }
            off += read;
        }
        auto len = readFrameLength(std::span{prefix, 4});
        if (len.isError()) {
            return Json{};
        }
        std::vector<u8> body(len.value());
        off = 0;
        while (off < len.value()) {
            if (::ReadFile(pipe, body.data() + off, len.value() - off, &read, nullptr) == FALSE ||
                read == 0) {
                return Json{};
            }
            off += read;
        }
        auto parsed = parseFrame(body);
        return parsed.isOk() ? parsed.value() : Json{};
    };

    bool ok = true;

    // Hello.
    HelloParams hp;
    hp.protocolVersion = version::kIpcProtocol;
    writeFrame(encode(Request{1, Method::Hello, encode(hp)}));
    ok = ok && readResponse().contains("id");

    // Echo call.
    writeFrame(encode(Request{2, Method::GetServiceInfo, Json{{"echo", expectEcho}}}));
    Json response = readResponse();
    ok = ok && response["success"].get<bool>() &&
         response["result"]["echo"].get<int>() == expectEcho;

    ::CloseHandle(pipe);
    return ok;
}

} // namespace

TEST_CASE("the IPC server serves many concurrent clients correctly",
          "[stress][ipc]")
{
    const std::string pipe = uniquePipe();
    auto server = makeIpcServer(std::string{version::kString});

    // An echo handler so each client can verify it got its own answer.
    REQUIRE(server->setHandler(Method::GetServiceInfo, [](const RequestContext& ctx) {
                return makeSuccess(ctx.request.id,
                                   Json{{"echo", ctx.request.params.value("echo", -1)}});
            }).isOk());
    REQUIRE(server->start(pipe).isOk());

    constexpr int kClients = 24;
    std::atomic<int> succeeded{0};

    std::vector<std::thread> clients;
    for (int i = 0; i < kClients; ++i) {
        clients.emplace_back([&, i] {
            if (doOneSession(pipe, i)) {
                succeeded.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& c : clients) {
        c.join();
    }

    // Every client completed Hello + an echo that returned its own value.
    REQUIRE(succeeded.load() == kClients);

    server->stop();
    REQUIRE_FALSE(server->isRunning());
}

TEST_CASE("repeated server start/stop cycles are clean", "[stress][ipc]")
{
    // A server that is stood up and torn down repeatedly must leave no pipe
    // instance behind and must always accept a client on the next cycle.
    for (int cycle = 0; cycle < 15; ++cycle) {
        const std::string pipe = uniquePipe();
        auto server = makeIpcServer(std::string{version::kString});
        REQUIRE(server->setHandler(Method::GetServiceInfo, [](const RequestContext& ctx) {
                    return makeSuccess(ctx.request.id,
                                       Json{{"echo", ctx.request.params.value("echo", 0)}});
                }).isOk());
        REQUIRE(server->start(pipe).isOk());
        REQUIRE(doOneSession(pipe, cycle));
        server->stop();
    }
    SUCCEED("15 start/stop cycles completed cleanly");
}
