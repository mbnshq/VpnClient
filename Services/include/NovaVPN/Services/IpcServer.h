// NovaVPN - Services/IpcServer.h
// The named-pipe server half of the UI <-> service channel.
//
// The service hosts this; the UI connects with IpcClient. Design points that
// matter for security and robustness:
//   * The pipe is created with a DACL granting the Users group connect access
//     and nothing else - no WRITE_DAC, no WRITE_OWNER.
//   * Each connection is served on its own thread. A slow or hostile client
//     therefore cannot stall the others or the service.
//   * A request larger than kMaxFrameBytes is refused on its length prefix,
//     before the body is read, so a client cannot make the service allocate
//     unbounded memory.
//   * The first message must be Hello; the server rejects any other method
//     until the protocol version is negotiated, and enforces the
//     administrator requirement of ipc::requiresAdministrator() by inspecting
//     the caller's token.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Services/IpcProtocol.h>

#include <functional>
#include <memory>
#include <string>

namespace nova::ipc {

/// Context passed to a request handler: the decoded request plus facts about
/// the caller the handler may need for authorisation decisions.
struct RequestContext {
    Request request;
    /// True when the connected client's token is an elevated administrator.
    bool    callerIsAdministrator = false;
    /// Opaque per-connection id, stable for the life of the connection.
    u64     connectionId = 0;
};

/// A handler turns a request into a response. Handlers run on the connection's
/// own thread and must be thread-safe with respect to the shared service state
/// they touch.
using RequestHandler = std::function<Response(const RequestContext&)>;

class IIpcServer {
public:
    virtual ~IIpcServer() = default;

    /// Registers the handler for one method. Replacing an existing handler is
    /// refused so a method can never be silently rebound.
    [[nodiscard]] virtual Status setHandler(Method method, RequestHandler handler) = 0;

    /// Begins listening on the pipe. Returns once the listener is accepting.
    [[nodiscard]] virtual Status start(const std::string& pipeName) = 0;

    /// Stops listening and closes every live connection.
    virtual void stop() = 0;

    /// Broadcasts an event to every connected client. Used by the service to
    /// push state changes, statistics ticks and challenges. Never blocks on a
    /// slow client - a client whose write queue is full is dropped.
    virtual void broadcast(const Event& event) = 0;

    /// Number of connected clients (diagnostics).
    [[nodiscard]] virtual std::size_t connectionCount() const = 0;

    [[nodiscard]] virtual bool isRunning() const = 0;
};

using IpcServerPtr = std::shared_ptr<IIpcServer>;

/// Creates the Windows named-pipe server. `serviceVersion` is reported in the
/// Hello handshake.
[[nodiscard]] IpcServerPtr makeIpcServer(std::string serviceVersion);

} // namespace nova::ipc
