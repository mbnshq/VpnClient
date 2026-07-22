#include <NovaVPN/Core/Status.h>

#include <string>

namespace nova {

std::string_view toString(ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::Ok:                  return "Ok";
    case ErrorCode::Unknown:             return "Unknown";
    case ErrorCode::InvalidArgument:     return "InvalidArgument";
    case ErrorCode::NotFound:            return "NotFound";
    case ErrorCode::AlreadyExists:       return "AlreadyExists";
    case ErrorCode::PermissionDenied:    return "PermissionDenied";
    case ErrorCode::Unavailable:         return "Unavailable";
    case ErrorCode::Timeout:             return "Timeout";
    case ErrorCode::Cancelled:           return "Cancelled";
    case ErrorCode::NotImplemented:      return "NotImplemented";
    case ErrorCode::OutOfMemory:         return "OutOfMemory";
    case ErrorCode::InvalidState:        return "InvalidState";
    case ErrorCode::Interrupted:         return "Interrupted";
    case ErrorCode::IoError:             return "IoError";
    case ErrorCode::ParseError:          return "ParseError";
    case ErrorCode::SerializationError:  return "SerializationError";
    case ErrorCode::ChecksumMismatch:    return "ChecksumMismatch";
    case ErrorCode::ConfigInvalid:       return "ConfigInvalid";
    case ErrorCode::ConfigMissingField:  return "ConfigMissingField";
    case ErrorCode::ProfileInvalid:      return "ProfileInvalid";
    case ErrorCode::ProfileLocked:       return "ProfileLocked";
    case ErrorCode::AuthFailed:          return "AuthFailed";
    case ErrorCode::CredentialsMissing:  return "CredentialsMissing";
    case ErrorCode::CertificateInvalid:  return "CertificateInvalid";
    case ErrorCode::CertificateExpired:  return "CertificateExpired";
    case ErrorCode::SignatureInvalid:    return "SignatureInvalid";
    case ErrorCode::CryptoFailure:       return "CryptoFailure";
    case ErrorCode::IntegrityViolation:  return "IntegrityViolation";
    case ErrorCode::NetworkUnreachable:  return "NetworkUnreachable";
    case ErrorCode::DnsFailure:          return "DnsFailure";
    case ErrorCode::ConnectionRefused:   return "ConnectionRefused";
    case ErrorCode::ConnectionReset:     return "ConnectionReset";
    case ErrorCode::HandshakeFailed:     return "HandshakeFailed";
    case ErrorCode::TlsError:            return "TlsError";
    case ErrorCode::ProtocolError:       return "ProtocolError";
    case ErrorCode::AdapterNotFound:     return "AdapterNotFound";
    case ErrorCode::AdapterBusy:         return "AdapterBusy";
    case ErrorCode::DriverMissing:       return "DriverMissing";
    case ErrorCode::DriverVersion:       return "DriverVersion";
    case ErrorCode::TunnelSetupFailed:   return "TunnelSetupFailed";
    case ErrorCode::MtuNegotiation:      return "MtuNegotiation";
    case ErrorCode::RouteConflict:       return "RouteConflict";
    case ErrorCode::RouteApplyFailed:    return "RouteApplyFailed";
    case ErrorCode::FirewallApplyFailed: return "FirewallApplyFailed";
    case ErrorCode::FirewallEngineBusy:  return "FirewallEngineBusy";
    case ErrorCode::SplitTunnelFailed:   return "SplitTunnelFailed";
    case ErrorCode::LeakDetected:        return "LeakDetected";
    case ErrorCode::ServiceUnavailable:  return "ServiceUnavailable";
    case ErrorCode::ServiceVersion:      return "ServiceVersion";
    case ErrorCode::IpcTransport:        return "IpcTransport";
    case ErrorCode::IpcProtocol:         return "IpcProtocol";
    case ErrorCode::IpcPeerUntrusted:    return "IpcPeerUntrusted";
    case ErrorCode::UpdateUnavailable:   return "UpdateUnavailable";
    case ErrorCode::UpdateDownload:      return "UpdateDownload";
    case ErrorCode::UpdateVerify:        return "UpdateVerify";
    case ErrorCode::UpdateApply:         return "UpdateApply";
    }
    return "Unrecognised";
}

bool isTransient(ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::Unavailable:
    case ErrorCode::Timeout:
    case ErrorCode::Interrupted:
    case ErrorCode::IoError:
    case ErrorCode::NetworkUnreachable:
    case ErrorCode::DnsFailure:
    case ErrorCode::ConnectionRefused:
    case ErrorCode::ConnectionReset:
    case ErrorCode::HandshakeFailed:
    case ErrorCode::AdapterBusy:
    case ErrorCode::FirewallEngineBusy:
    case ErrorCode::ServiceUnavailable:
    case ErrorCode::IpcTransport:
    case ErrorCode::UpdateDownload:
        return true;
    default:
        return false;
    }
}

Status Status::withContext(std::string_view context) const
{
    if (isOk()) {
        return *this;
    }

    std::string combined;
    combined.reserve(context.size() + m_message.size() + 2);
    combined.append(context);
    if (!m_message.empty()) {
        combined.append(": ");
        combined.append(m_message);
    }
    return Status{m_code, std::move(combined), m_platformCode};
}

std::string Status::toString() const
{
    std::string out{nova::toString(m_code)};
    if (!m_message.empty()) {
        out.append(": ");
        out.append(m_message);
    }
    if (m_platformCode != 0) {
        out.append(" (platform=");
        out.append(std::to_string(m_platformCode));
        out.push_back(')');
    }
    return out;
}

namespace err {

Status make(ErrorCode code, std::string_view message)
{
    return Status{code, std::string{message}};
}

Status invalidArgument(std::string_view message)  { return make(ErrorCode::InvalidArgument, message); }
Status notFound(std::string_view message)         { return make(ErrorCode::NotFound, message); }
Status alreadyExists(std::string_view message)    { return make(ErrorCode::AlreadyExists, message); }
Status permissionDenied(std::string_view message) { return make(ErrorCode::PermissionDenied, message); }
Status invalidState(std::string_view message)     { return make(ErrorCode::InvalidState, message); }
Status notImplemented(std::string_view message)   { return make(ErrorCode::NotImplemented, message); }
Status timeout(std::string_view message)          { return make(ErrorCode::Timeout, message); }
Status cancelled(std::string_view message)        { return make(ErrorCode::Cancelled, message); }
Status io(std::string_view message)               { return make(ErrorCode::IoError, message); }
Status parse(std::string_view message)            { return make(ErrorCode::ParseError, message); }

} // namespace err
} // namespace nova
