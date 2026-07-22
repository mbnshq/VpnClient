#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/Json.h>
#include <NovaVPN/Core/SecureMemory.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Updater/Updater.h>

#include <Windows.h>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>

#include <cstring>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace nova::updater {
namespace {

constexpr NTSTATUS kOk = 0;

struct AlgProvider {
    BCRYPT_ALG_HANDLE handle = nullptr;
    ~AlgProvider()
    {
        if (handle != nullptr) {
            ::BCryptCloseAlgorithmProvider(handle, 0);
        }
    }
};

struct KeyHandle {
    BCRYPT_KEY_HANDLE handle = nullptr;
    ~KeyHandle()
    {
        if (handle != nullptr) {
            ::BCryptDestroyKey(handle);
        }
    }
};

struct HashHandle {
    BCRYPT_HASH_HANDLE handle = nullptr;
    ~HashHandle()
    {
        if (handle != nullptr) {
            ::BCryptDestroyHash(handle);
        }
    }
};

Result<std::array<u8, 32>> hashBytes(std::span<const u8> data)
{
    AlgProvider alg;
    if (::BCryptOpenAlgorithmProvider(&alg.handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != kOk) {
        return Status{ErrorCode::CryptoFailure, "BCryptOpenAlgorithmProvider(SHA256)"};
    }
    HashHandle hash;
    if (::BCryptCreateHash(alg.handle, &hash.handle, nullptr, 0, nullptr, 0, 0) != kOk) {
        return Status{ErrorCode::CryptoFailure, "BCryptCreateHash"};
    }
    if (!data.empty() &&
        ::BCryptHashData(hash.handle, const_cast<PUCHAR>(data.data()),
                         static_cast<ULONG>(data.size()), 0) != kOk) {
        return Status{ErrorCode::CryptoFailure, "BCryptHashData"};
    }
    std::array<u8, 32> digest{};
    if (::BCryptFinishHash(hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0) !=
        kOk) {
        return Status{ErrorCode::CryptoFailure, "BCryptFinishHash"};
    }
    return digest;
}

class SignatureVerifier final : public ISignatureVerifier {
public:
    explicit SignatureVerifier(std::vector<u8> publicKeyDer)
        : m_publicKeyDer(std::move(publicKeyDer))
    {
    }

    Status verifyManifest(std::span<const u8> payload,
                          std::span<const u8> signature) const override
    {
        if (signature.size() != 64) {
            return Status{ErrorCode::SignatureInvalid,
                          "ECDSA-P256 signature must be 64 bytes (r||s)"};
        }

        auto digest = hashBytes(payload);
        if (digest.isError()) {
            return digest.status();
        }

        // Import the SPKI DER public key, then verify the raw r||s signature
        // against the digest.
        AlgProvider alg;
        if (::BCryptOpenAlgorithmProvider(&alg.handle, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) !=
            kOk) {
            return Status{ErrorCode::CryptoFailure, "BCryptOpenAlgorithmProvider(ECDSA)"};
        }

        KeyHandle key;
        NOVA_RETURN_IF_ERROR(importPublicKey(alg.handle, key));

        const NTSTATUS status = ::BCryptVerifySignature(
            key.handle, nullptr, digest.value().data(),
            static_cast<ULONG>(digest.value().size()), const_cast<PUCHAR>(signature.data()),
            static_cast<ULONG>(signature.size()), 0);

        if (status != kOk) {
            return Status{ErrorCode::SignatureInvalid, "manifest signature does not verify",
                          static_cast<u32>(status)};
        }
        return Status::ok();
    }

    Status verifyAuthenticode(const std::filesystem::path& file) const override
    {
        const std::wstring widePath = file.wstring();

        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct      = sizeof(fileInfo);
        fileInfo.pcwszFilePath = widePath.c_str();

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA trustData{};
        trustData.cbStruct            = sizeof(trustData);
        trustData.dwUIChoice          = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice       = WTD_CHOICE_FILE;
        trustData.pFile               = &fileInfo;
        trustData.dwStateAction       = WTD_STATEACTION_VERIFY;

        const LONG result = ::WinVerifyTrust(nullptr, &action, &trustData);
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &action, &trustData);

        if (result != ERROR_SUCCESS) {
            return Status{ErrorCode::SignatureInvalid,
                          "Authenticode verification failed for " + file.string(),
                          static_cast<u32>(result)};
        }
        return Status::ok();
    }

    Status verifyHash(const std::filesystem::path& file,
                      std::string_view expectedHex) const override
    {
        auto actual = sha256File(file);
        if (actual.isError()) {
            return actual.status();
        }

        std::vector<u8> expected;
        if (!str::fromHex(expectedHex, expected) || expected.size() != 32) {
            return err::invalidArgument("expected hash is not a 32-byte hex string");
        }

        if (!constantTimeEquals(
                std::span{reinterpret_cast<const std::byte*>(actual.value().data()), 32},
                std::span{reinterpret_cast<const std::byte*>(expected.data()), 32})) {
            return Status{ErrorCode::ChecksumMismatch,
                          "file hash does not match the expected value"};
        }
        return Status::ok();
    }

private:
    /// Imports the DER SubjectPublicKeyInfo into a CNG key by extracting the
    /// 65-byte uncompressed EC point (0x04 || X || Y) and building the CNG
    /// BCRYPT_ECCPUBLIC_BLOB the verify API wants.
    Status importPublicKey(BCRYPT_ALG_HANDLE alg, KeyHandle& key) const
    {
        // Locate the uncompressed point. For a P-256 SPKI the last 65 bytes are
        // 0x04 || X(32) || Y(32).
        if (m_publicKeyDer.size() < 65) {
            return Status{ErrorCode::CertificateInvalid, "public key too small"};
        }
        const u8* point = nullptr;
        for (std::size_t i = 0; i + 65 <= m_publicKeyDer.size(); ++i) {
            if (m_publicKeyDer[i] == 0x04) {
                point = m_publicKeyDer.data() + i;
                // Heuristic: the uncompressed point is the tail of the SPKI.
                if (i + 65 == m_publicKeyDer.size()) {
                    break;
                }
            }
        }
        if (point == nullptr) {
            return Status{ErrorCode::CertificateInvalid,
                          "no uncompressed EC point in the public key"};
        }

        struct EccBlob {
            BCRYPT_ECCKEY_BLOB header;
            u8                 xy[64];
        } blob{};
        blob.header.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        blob.header.cbKey   = 32;
        std::memcpy(blob.xy, point + 1, 64); // skip the 0x04 prefix

        if (::BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key.handle,
                                  reinterpret_cast<PUCHAR>(&blob), sizeof(blob), 0) != kOk) {
            return Status{ErrorCode::CertificateInvalid, "BCryptImportKeyPair"};
        }
        return Status::ok();
    }

    std::vector<u8> m_publicKeyDer;
};

} // namespace

Result<std::array<u8, 32>> sha256(std::span<const u8> data)
{
    return hashBytes(data);
}

Result<std::array<u8, 32>> sha256File(const std::filesystem::path& path)
{
    NOVA_ASSIGN_OR_RETURN(auto bytes, file::readAll(path));
    return hashBytes(bytes);
}

Result<std::shared_ptr<ISignatureVerifier>> makeSignatureVerifier(std::span<const u8> publicKeyDer)
{
    if (publicKeyDer.empty()) {
        return err::invalidArgument("public key is empty");
    }
    return std::shared_ptr<ISignatureVerifier>{
        std::make_shared<SignatureVerifier>(
            std::vector<u8>{publicKeyDer.begin(), publicKeyDer.end()})};
}

int compareVersions(std::string_view a, std::string_view b)
{
    const auto ordinal = [](std::string_view v) -> u64 {
        u64 parts[4] = {0, 0, 0, 0};
        std::size_t index = 0;
        u64 current = 0;
        for (char c : v) {
            if (c == '.') {
                if (index < 4) {
                    parts[index++] = current;
                }
                current = 0;
            } else if (c >= '0' && c <= '9') {
                current = current * 10 + static_cast<u64>(c - '0');
            }
        }
        if (index < 4) {
            parts[index] = current;
        }
        return (parts[0] << 48) | (parts[1] << 32) | (parts[2] << 16) | parts[3];
    };

    const u64 oa = ordinal(a);
    const u64 ob = ordinal(b);
    if (oa < ob) {
        return -1;
    }
    return oa > ob ? 1 : 0;
}

Result<ReleaseInfo> parseManifest(std::string_view json, Channel channel)
{
    NOVA_ASSIGN_OR_RETURN(auto doc, json::parse(json));

    ReleaseInfo release;
    release.channel = channel;
    NOVA_ASSIGN_OR_RETURN(release.version, json::require<std::string>(doc, "/version"));
    release.releaseNotes      = json::get<std::string>(doc, "/releaseNotes", "");
    release.fullPackageUrl    = json::get<std::string>(doc, "/full/url", "");
    release.fullPackageSha256 = json::get<std::string>(doc, "/full/sha256", "");
    release.fullPackageSize   = json::get<u64>(doc, "/full/size", 0);
    release.deltaFromVersion  = json::get<std::string>(doc, "/delta/fromVersion", "");
    release.deltaPackageUrl   = json::get<std::string>(doc, "/delta/url", "");
    release.deltaPackageSha256 = json::get<std::string>(doc, "/delta/sha256", "");
    release.deltaPackageSize  = json::get<u64>(doc, "/delta/size", 0);
    release.isSecurityUpdate  = json::get<bool>(doc, "/securityUpdate", false);
    release.minimumUpgradeFrom = json::get<std::string>(doc, "/minimumUpgradeFrom", "");

    if (release.fullPackageUrl.empty() || release.fullPackageSha256.empty()) {
        return Status{ErrorCode::ParseError, "manifest is missing the full package url or hash"};
    }
    if (release.fullPackageSha256.size() != 64) {
        return Status{ErrorCode::ParseError, "manifest package hash is not a SHA-256 hex string"};
    }
    return release;
}

} // namespace nova::updater
