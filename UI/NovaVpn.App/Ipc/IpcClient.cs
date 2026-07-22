using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace NovaVpn.App.Ipc;

/// <summary>
/// The UI half of the NovaVPN IPC channel. Mirrors the native client: a
/// length-prefixed JSON frame protocol over a named pipe, with the SYSTEM-owner
/// verification that stops a squatting process from impersonating the service,
/// and the Hello handshake that negotiates the protocol version.
/// </summary>
public sealed class IpcClient : IDisposable
{
    // Kept in lockstep with Core/Version.h (kIpcProtocol) and IpcProtocol.h.
    public const int ProtocolVersion = 1;
    private const uint MaxFrameBytes = 8u * 1024 * 1024;

    private readonly string _clientName;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly Dictionary<ulong, TaskCompletionSource<JsonObject>> _pending = new();
    private readonly object _pendingLock = new();

    private NamedPipeClientStream? _pipe;
    private CancellationTokenSource? _receiveCts;
    private Task? _receiveTask;
    private ulong _nextId = 1;

    public event Action<JsonObject>? EventReceived;
    public event Action? Disconnected;

    public bool IsConnected => _pipe?.IsConnected ?? false;
    public HelloResult? ServiceInfo { get; private set; }

    public IpcClient(string clientName) => _clientName = clientName;

    /// <summary>Connects, verifies the pipe owner is SYSTEM, and performs Hello.</summary>
    public async Task ConnectAsync(string pipeName, TimeSpan timeout, CancellationToken ct)
    {
        var pipe = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync((int)timeout.TotalMilliseconds, ct).ConfigureAwait(false);

        VerifyServerIsTrusted(pipe);

        _pipe = pipe;
        _receiveCts = new CancellationTokenSource();
        _receiveTask = Task.Run(() => ReceiveLoopAsync(_receiveCts.Token));

        var hello = new JsonObject
        {
            ["protocolVersion"] = ProtocolVersion,
            ["clientVersion"] = "0.1.0",
            ["clientName"] = _clientName,
        };
        var response = await CallAsync(Method.Hello, hello, timeout, ct).ConfigureAwait(false);
        if (!response.Success)
        {
            throw new IpcException(response.ErrorCode, response.ErrorMessage);
        }

        ServiceInfo = HelloResult.From(response.Result);
        if (ServiceInfo.ProtocolVersion != ProtocolVersion)
        {
            Dispose();
            throw new IpcException(
                "ServiceVersion",
                $"service speaks protocol {ServiceInfo.ProtocolVersion}, this client speaks {ProtocolVersion}");
        }
    }

    /// <summary>Sends a request and awaits the matching response.</summary>
    public async Task<IpcResponse> CallAsync(
        Method method, JsonObject? parameters, TimeSpan timeout, CancellationToken ct)
    {
        if (_pipe is null || !_pipe.IsConnected)
        {
            throw new IpcException("Unavailable", "not connected to the service");
        }

        ulong id = Interlocked.Increment(ref _nextId);
        var tcs = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_pendingLock)
        {
            _pending[id] = tcs;
        }

        var request = new JsonObject
        {
            ["type"] = "request",
            ["protocol"] = ProtocolVersion,
            ["id"] = id,
            ["method"] = (int)method,
            ["methodName"] = method.ToString(),
            ["params"] = parameters ?? new JsonObject(),
        };

        await WriteFrameAsync(request, ct).ConfigureAwait(false);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        try
        {
            JsonObject frame = await tcs.Task.WaitAsync(timeoutCts.Token).ConfigureAwait(false);
            return IpcResponse.From(frame);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            lock (_pendingLock) { _pending.Remove(id); }
            throw new IpcException("Timeout", $"no response to {method}");
        }
    }

    private async Task WriteFrameAsync(JsonObject frame, CancellationToken ct)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(frame);
        if (body.Length > MaxFrameBytes)
        {
            throw new IpcException("IpcProtocol", "frame exceeds the size limit");
        }

        var buffer = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, (uint)body.Length);
        body.CopyTo(buffer, 4);

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _pipe!.WriteAsync(buffer, ct).ConfigureAwait(false);
            await _pipe.FlushAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var prefix = new byte[4];
        try
        {
            while (!ct.IsCancellationRequested && _pipe is { IsConnected: true })
            {
                await ReadExactAsync(prefix, ct).ConfigureAwait(false);
                uint length = BinaryPrimitives.ReadUInt32LittleEndian(prefix);
                if (length == 0 || length > MaxFrameBytes)
                {
                    break;
                }

                var body = new byte[length];
                await ReadExactAsync(body, ct).ConfigureAwait(false);

                if (JsonNode.Parse(Encoding.UTF8.GetString(body)) is not JsonObject frame)
                {
                    continue;
                }

                string type = frame["type"]?.GetValue<string>() ?? "";
                if (type == "event")
                {
                    EventReceived?.Invoke(frame);
                }
                else if (type == "response")
                {
                    ulong id = frame["id"]?.GetValue<ulong>() ?? 0;
                    TaskCompletionSource<JsonObject>? slot;
                    lock (_pendingLock)
                    {
                        _pending.Remove(id, out slot);
                    }
                    slot?.TrySetResult(frame);
                }
            }
        }
        catch (Exception)
        {
            // Pipe closed or read failed - surface as a disconnect below.
        }

        FailPending();
        Disconnected?.Invoke();
    }

    private async Task ReadExactAsync(byte[] buffer, CancellationToken ct)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await _pipe!.ReadAsync(buffer.AsMemory(offset), ct).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
        }
    }

    private void FailPending()
    {
        lock (_pendingLock)
        {
            foreach (var slot in _pending.Values)
            {
                slot.TrySetException(new IpcException("Cancelled", "disconnected"));
            }
            _pending.Clear();
        }
    }

    /// <summary>
    /// Confirms the pipe is owned by a privileged account - Local System (the
    /// installed service) or the Administrators group (a service run elevated
    /// in console mode for development). Both require the creator to already be
    /// privileged, so a non-admin process cannot forge either ownership and
    /// impersonate the service; this is the anti-squatting gate.
    /// </summary>
    private static void VerifyServerIsTrusted(NamedPipeClientStream pipe)
    {
        var security = pipe.GetAccessControl();
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        if (owner is null || (!owner.Equals(system) && !owner.Equals(admins)))
        {
            pipe.Dispose();
            throw new IpcException("IpcPeerUntrusted",
                "the service pipe is not owned by a privileged account; refusing to trust it");
        }
    }

    public void Dispose()
    {
        _receiveCts?.Cancel();
        try { _pipe?.Dispose(); } catch { /* ignore */ }
        _receiveCts?.Dispose();
        _pipe = null;
    }
}
