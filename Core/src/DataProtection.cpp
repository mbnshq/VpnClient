#include <NovaVPN/Core/DataProtection.h>
#include <NovaVPN/Core/WinError.h>

#include <Windows.h>
#include <dpapi.h>

#include <cstring>

#pragma comment(lib, "crypt32.lib")

namespace nova::crypto {
namespace {

// A non-null placeholder so a zero-length blob still has a valid pointer -
// CryptProtectData rejects pbData == nullptr even when cbData is 0.
u8 g_emptyBlobAnchor = 0;

DATA_BLOB makeBlob(std::span<const u8> data)
{
    DATA_BLOB blob{};
    blob.cbData = static_cast<DWORD>(data.size());
    // CryptProtectData does not modify the input; the const_cast is required by
    // the C API signature only.
    blob.pbData = data.empty() ? &g_emptyBlobAnchor : const_cast<BYTE*>(data.data());
    return blob;
}

} // namespace

Result<std::vector<u8>> seal(std::span<const u8> plaintext, ProtectionScope scope,
                             std::span<const u8> entropy)
{
    DATA_BLOB input   = makeBlob(plaintext);
    DATA_BLOB entropyBlob = makeBlob(entropy);
    DATA_BLOB output{};

    const DWORD flags =
        CRYPTPROTECT_UI_FORBIDDEN |
        (scope == ProtectionScope::Machine ? CRYPTPROTECT_LOCAL_MACHINE : 0u);

    if (::CryptProtectData(&input, L"NovaVPN", entropy.empty() ? nullptr : &entropyBlob, nullptr,
                           nullptr, flags, &output) == FALSE) {
        return win::lastError("CryptProtectData");
    }

    std::vector<u8> sealed(output.pbData, output.pbData + output.cbData);
    ::LocalFree(output.pbData);
    return sealed;
}

Result<std::vector<u8>> seal(std::string_view plaintext, ProtectionScope scope,
                             std::span<const u8> entropy)
{
    return seal(std::span{reinterpret_cast<const u8*>(plaintext.data()), plaintext.size()}, scope,
                entropy);
}

Result<SecureBuffer> unseal(std::span<const u8> ciphertext, std::span<const u8> entropy)
{
    DATA_BLOB input       = makeBlob(ciphertext);
    DATA_BLOB entropyBlob = makeBlob(entropy);
    DATA_BLOB output{};

    if (::CryptUnprotectData(&input, nullptr, entropy.empty() ? nullptr : &entropyBlob, nullptr,
                             nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output) == FALSE) {
        Status status = win::lastError("CryptUnprotectData");
        // A wrong entropy or a blob sealed on another machine surfaces as a
        // generic Win32 error; classify it as an integrity failure so callers
        // can distinguish "tampered/foreign" from "IO problem".
        return Status{ErrorCode::IntegrityViolation, status.message(), status.platformCode()};
    }

    // Copy into locked memory, then scrub and free the DPAPI output so the
    // plaintext exists only in the SecureBuffer.
    SecureBuffer buffer = SecureBuffer::copyFrom(
        std::span{reinterpret_cast<const std::byte*>(output.pbData), output.cbData});
    ::SecureZeroMemory(output.pbData, output.cbData);
    ::LocalFree(output.pbData);
    return buffer;
}

} // namespace nova::crypto
