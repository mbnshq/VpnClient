#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Core/WinError.h>

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <limits>

#pragma comment(lib, "bcrypt.lib")

namespace nova {
namespace {

constexpr NTSTATUS kStatusSuccess = 0;

bool parseNibble(char c, u8& value) noexcept
{
    if (c >= '0' && c <= '9') {
        value = static_cast<u8>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
        value = static_cast<u8>(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
        value = static_cast<u8>(c - 'A' + 10);
    } else {
        return false;
    }
    return true;
}

} // namespace

Status randomBytes(std::span<u8> out) noexcept
{
    if (out.empty()) {
        return Status::ok();
    }
    const NTSTATUS status = ::BCryptGenRandom(nullptr, out.data(),
                                              static_cast<ULONG>(out.size()),
                                              BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != kStatusSuccess) {
        return Status{ErrorCode::CryptoFailure, "BCryptGenRandom failed",
                      static_cast<u32>(status)};
    }
    return Status::ok();
}

Result<u64> randomBelow(u64 bound) noexcept
{
    if (bound == 0) {
        return err::invalidArgument("randomBelow requires a positive bound");
    }

    // Rejection sampling: discard values in the biased tail so every outcome is
    // equally likely.
    const u64 limit = std::numeric_limits<u64>::max() - (std::numeric_limits<u64>::max() % bound);
    for (int attempt = 0; attempt < 64; ++attempt) {
        u64 value = 0;
        NOVA_RETURN_IF_ERROR(randomBytes(
            std::span{reinterpret_cast<u8*>(&value), sizeof(value)}));
        if (value < limit) {
            return value % bound;
        }
    }
    return Status{ErrorCode::CryptoFailure, "randomBelow exhausted rejection sampling attempts"};
}

Uuid Uuid::generate()
{
    Uuid uuid;
    for (int attempt = 0; attempt < 4; ++attempt) {
        if (randomBytes(std::span{uuid.m_bytes}).isError()) {
            continue;
        }
        // RFC 4122 section 4.4: set the version (4) and variant (10xx) bits.
        uuid.m_bytes[6] = static_cast<u8>((uuid.m_bytes[6] & 0x0F) | 0x40);
        uuid.m_bytes[8] = static_cast<u8>((uuid.m_bytes[8] & 0x3F) | 0x80);
        if (!uuid.isNil()) {
            return uuid;
        }
    }

    // The system CSPRNG is unavailable; there is no safe fallback for an
    // identity value, so fail loudly rather than emit a predictable id.
    ::RaiseFailFastException(nullptr, nullptr, 0);
    return uuid;
}

bool Uuid::tryParse(std::string_view text, Uuid& out) noexcept
{
    std::string_view body = str::trim(text);
    if (body.size() >= 2 && body.front() == '{' && body.back() == '}') {
        body = body.substr(1, body.size() - 2);
    }
    if (body.size() != 36) {
        return false;
    }
    if (body[8] != '-' || body[13] != '-' || body[18] != '-' || body[23] != '-') {
        return false;
    }

    std::array<u8, 16> bytes{};
    std::size_t byteIndex = 0;
    for (std::size_t i = 0; i < body.size();) {
        if (body[i] == '-') {
            ++i;
            continue;
        }
        u8 hi = 0;
        u8 lo = 0;
        if (i + 1 >= body.size() || !parseNibble(body[i], hi) || !parseNibble(body[i + 1], lo)) {
            return false;
        }
        if (byteIndex >= bytes.size()) {
            return false;
        }
        bytes[byteIndex++] = static_cast<u8>((hi << 4) | lo);
        i += 2;
    }
    if (byteIndex != bytes.size()) {
        return false;
    }

    out.m_bytes = bytes;
    return true;
}

bool Uuid::isNil() const noexcept
{
    return std::all_of(m_bytes.begin(), m_bytes.end(), [](u8 b) { return b == 0; });
}

std::string Uuid::toString() const
{
    const std::string hex = str::toHex(m_bytes.data(), m_bytes.size());
    std::string out;
    out.reserve(36);
    out.append(hex, 0, 8);
    out.push_back('-');
    out.append(hex, 8, 4);
    out.push_back('-');
    out.append(hex, 12, 4);
    out.push_back('-');
    out.append(hex, 16, 4);
    out.push_back('-');
    out.append(hex, 20, 12);
    return out;
}

} // namespace nova
