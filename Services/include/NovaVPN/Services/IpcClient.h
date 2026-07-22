// NovaVPN - Services/IpcClient.h
// The named-pipe client half of the channel. Used by the UI and by tests.
//
// The client verifies that the pipe's owner is SYSTEM before it sends anything,
// so a squatting process cannot impersonate the service and harvest
// credentials. It performs the Hello handshake on connect and rejects a service
// whose protocol version differs.
#pragma once

#include <NovaVPN/Core/Cancellation.h>
#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Services/IpcProtocol.h>

#include <functional>
#include <memory>
#include <string>

namespace nova::ipc {

/// Invoked when the service pushes an event. Runs on the client's receive
/// thread; handlers must be short and thread-safe.
using EventHandler = std::function<void(const Event&)>;

class IIpcClient {
public:
    virtual ~IIpcClient() = default;

    /// Connects, verifies the pipe owner is SYSTEM, and performs the Hello
    /// handshake. `timeout` bounds the whole sequence.
    [[nodiscard]] virtual Status connect(const std::string& pipeName, Milliseconds timeout) = 0;

    virtual void disconnect() = 0;

    /// Sends a request and waits for its matching response.
    [[nodiscard]] virtual Result<Response> call(Method method, Json params,
                                                Milliseconds timeout) = 0;

    /// Registers the handler for pushed events.
    virtual void onEvent(EventHandler handler) = 0;

    /// The handshake result captured at connect (service version, whether the
    /// caller is an administrator).
    [[nodiscard]] virtual const HelloResult& serviceInfo() const = 0;

    [[nodiscard]] virtual bool isConnected() const = 0;
};

using IpcClientPtr = std::shared_ptr<IIpcClient>;

/// Creates the Windows named-pipe client. `clientName` is reported in Hello.
[[nodiscard]] IpcClientPtr makeIpcClient(std::string clientName);

} // namespace nova::ipc
