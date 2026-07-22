// NovaVPN - Core/Status.h
// Error model. NovaVPN does not throw across module boundaries: every fallible
// operation returns Status or Result<T>. Exceptions are reserved for genuinely
// unrecoverable conditions (allocation failure) and are caught at thread roots.
#pragma once

#include <NovaVPN/Core/Types.h>

#include <string>
#include <string_view>
#include <utility>

namespace nova {

/// Stable, exhaustive error taxonomy. Values are part of the IPC contract and
/// the log format: append only, never renumber.
enum class ErrorCode : std::uint16_t {
    Ok = 0,

    // --- generic -----------------------------------------------------------
    Unknown            = 1,
    InvalidArgument    = 2,
    NotFound           = 3,
    AlreadyExists      = 4,
    PermissionDenied   = 5,
    Unavailable        = 6,
    Timeout            = 7,
    Cancelled          = 8,
    NotImplemented     = 9,
    OutOfMemory        = 10,
    InvalidState       = 11,
    Interrupted        = 12,

    // --- io / parsing ------------------------------------------------------
    IoError            = 100,
    ParseError         = 101,
    SerializationError = 102,
    ChecksumMismatch   = 103,

    // --- configuration -----------------------------------------------------
    ConfigInvalid      = 200,
    ConfigMissingField = 201,
    ProfileInvalid     = 202,
    ProfileLocked      = 203,

    // --- security ----------------------------------------------------------
    AuthFailed         = 300,
    CredentialsMissing = 301,
    CertificateInvalid = 302,
    CertificateExpired = 303,
    SignatureInvalid   = 304,
    CryptoFailure      = 305,
    IntegrityViolation = 306,

    // --- networking --------------------------------------------------------
    NetworkUnreachable = 400,
    DnsFailure         = 401,
    ConnectionRefused  = 402,
    ConnectionReset    = 403,
    HandshakeFailed    = 404,
    TlsError           = 405,
    ProtocolError      = 406,

    // --- tunnel / adapter --------------------------------------------------
    AdapterNotFound    = 500,
    AdapterBusy        = 501,
    DriverMissing      = 502,
    DriverVersion      = 503,
    TunnelSetupFailed  = 504,
    MtuNegotiation     = 505,

    // --- routing / firewall ------------------------------------------------
    RouteConflict      = 600,
    RouteApplyFailed   = 601,
    FirewallApplyFailed= 602,
    FirewallEngineBusy = 603,
    SplitTunnelFailed  = 604,
    LeakDetected       = 605,

    // --- service / ipc -----------------------------------------------------
    ServiceUnavailable = 700,
    ServiceVersion     = 701,
    IpcTransport       = 702,
    IpcProtocol        = 703,
    IpcPeerUntrusted   = 704,

    // --- update ------------------------------------------------------------
    UpdateUnavailable  = 800,
    UpdateDownload     = 801,
    UpdateVerify       = 802,
    UpdateApply        = 803,
};

[[nodiscard]] std::string_view toString(ErrorCode code) noexcept;

/// True when retrying the same operation later may succeed without user action.
[[nodiscard]] bool isTransient(ErrorCode code) noexcept;

/// Outcome of a fallible operation.
///
/// A Status carries the taxonomy code, a human-readable message meant for logs
/// and diagnostics, and optionally the raw platform error that produced it
/// (a Win32 code, HRESULT or OpenSSL error) so support can correlate.
class Status final {
public:
    Status() noexcept = default; ///< Constructs an Ok status.

    Status(ErrorCode code, std::string message) noexcept
        : m_code(code), m_message(std::move(message))
    {
    }

    Status(ErrorCode code, std::string message, u32 platformCode) noexcept
        : m_code(code), m_message(std::move(message)), m_platformCode(platformCode)
    {
    }

    [[nodiscard]] static Status ok() noexcept { return Status{}; }

    [[nodiscard]] bool isOk() const noexcept { return m_code == ErrorCode::Ok; }
    [[nodiscard]] bool isError() const noexcept { return m_code != ErrorCode::Ok; }
    explicit operator bool() const noexcept { return isOk(); }

    [[nodiscard]] ErrorCode code() const noexcept { return m_code; }
    [[nodiscard]] const std::string& message() const noexcept { return m_message; }
    [[nodiscard]] u32 platformCode() const noexcept { return m_platformCode; }
    [[nodiscard]] bool hasPlatformCode() const noexcept { return m_platformCode != 0; }
    [[nodiscard]] bool isTransient() const noexcept { return nova::isTransient(m_code); }

    /// Prefixes the message with additional context while preserving the code,
    /// e.g. `st.withContext("applying route 10.0.0.0/8")`.
    [[nodiscard]] Status withContext(std::string_view context) const;

    /// "InvalidArgument: port out of range (win32=87)"
    [[nodiscard]] std::string toString() const;

private:
    ErrorCode   m_code = ErrorCode::Ok;
    std::string m_message;
    u32         m_platformCode = 0;
};

/// Convenience factories - `return err::notFound("profile 'HK-01'");`
namespace err {

[[nodiscard]] Status make(ErrorCode code, std::string_view message);
[[nodiscard]] Status invalidArgument(std::string_view message);
[[nodiscard]] Status notFound(std::string_view message);
[[nodiscard]] Status alreadyExists(std::string_view message);
[[nodiscard]] Status permissionDenied(std::string_view message);
[[nodiscard]] Status invalidState(std::string_view message);
[[nodiscard]] Status notImplemented(std::string_view message);
[[nodiscard]] Status timeout(std::string_view message);
[[nodiscard]] Status cancelled(std::string_view message);
[[nodiscard]] Status io(std::string_view message);
[[nodiscard]] Status parse(std::string_view message);

} // namespace err

} // namespace nova

/// Propagates an error status out of the current function.
#define NOVA_RETURN_IF_ERROR(expr)                                                  \
    do {                                                                            \
        ::nova::Status nova_status_ = (expr);                                        \
        if (nova_status_.isError()) {                                                \
            return nova_status_;                                                     \
        }                                                                            \
    } while (false)
