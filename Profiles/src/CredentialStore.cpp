#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Profiles/ProfileStore.h>

#include <Windows.h>
#include <wincred.h>

#include <cstring>

#pragma comment(lib, "advapi32.lib")

using nova::logs::Channel;

namespace nova::profiles {
namespace {

constexpr std::string_view kPrefix = "NovaVPN/";

/// The full vault target for a caller-supplied target name, namespaced so
/// NovaVPN entries never collide with other software in the machine vault.
/// Idempotent: a name that already carries the prefix is left alone.
std::wstring vaultTarget(const std::string& target)
{
    std::string full;
    if (str::startsWith(target, kPrefix)) {
        full = target;
    } else {
        full.reserve(kPrefix.size() + target.size());
        full.append(kPrefix);
        full.append(target);
    }
    return win::toWide(full);
}

class WindowsCredentialStore final : public ICredentialStore {
public:
    Status store(const std::string& target, const std::string& userName,
                 const SecureString& secret) override
    {
        if (target.empty()) {
            return err::invalidArgument("credential target is empty");
        }
        // CredWrite caps the blob at CRED_MAX_CREDENTIAL_BLOB_SIZE (5 * 512).
        // A private key PEM can exceed that, so oversize is a real error here,
        // not a truncation to be silently accepted.
        if (secret.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE) {
            return err::invalidArgument("secret exceeds the credential store blob limit");
        }

        const std::wstring wideTarget = vaultTarget(target);
        const std::wstring wideUser   = win::toWide(userName);

        CREDENTIALW credential{};
        credential.Type        = CRED_TYPE_GENERIC;
        credential.TargetName  = const_cast<LPWSTR>(wideTarget.c_str());
        credential.Persist     = CRED_PERSIST_LOCAL_MACHINE;
        credential.UserName    = wideUser.empty() ? nullptr
                                                  : const_cast<LPWSTR>(wideUser.c_str());
        credential.CredentialBlobSize = static_cast<DWORD>(secret.size());
        credential.CredentialBlob =
            reinterpret_cast<LPBYTE>(const_cast<char*>(secret.view().data()));

        if (::CredWriteW(&credential, 0) == FALSE) {
            return win::lastError("CredWrite(" + target + ")");
        }

        NOVA_LOG_DEBUG(Channel::Security, "stored credential")
            .field("target", std::string{kPrefix} + target)
            .field("hasUser", !userName.empty());
        return Status::ok();
    }

    Result<SecureString> retrieve(const std::string& target) override
    {
        PCREDENTIALW credential = nullptr;
        if (::CredReadW(vaultTarget(target).c_str(), CRED_TYPE_GENERIC, 0, &credential) ==
            FALSE) {
            return win::lastError("CredRead(" + target + ")");
        }

        // Copy straight into locked memory and zero the vault buffer before it
        // is freed, so the plaintext lives only in a SecureString.
        SecureString secret;
        if (credential->CredentialBlobSize > 0 && credential->CredentialBlob != nullptr) {
            secret.assign(std::string_view{
                reinterpret_cast<const char*>(credential->CredentialBlob),
                credential->CredentialBlobSize});
            secureZero(credential->CredentialBlob, credential->CredentialBlobSize);
        }
        ::CredFree(credential);
        return secret;
    }

    Result<std::string> userNameFor(const std::string& target) override
    {
        PCREDENTIALW credential = nullptr;
        if (::CredReadW(vaultTarget(target).c_str(), CRED_TYPE_GENERIC, 0, &credential) ==
            FALSE) {
            return win::lastError("CredRead(" + target + ")");
        }
        std::string userName =
            credential->UserName != nullptr ? win::toUtf8(credential->UserName) : std::string{};
        ::CredFree(credential);
        return userName;
    }

    Status erase(const std::string& target) override
    {
        if (::CredDeleteW(vaultTarget(target).c_str(), CRED_TYPE_GENERIC, 0) == FALSE) {
            const Status status = win::lastError("CredDelete(" + target + ")");
            // Deleting an absent credential is success from the caller's view:
            // the postcondition (no such credential) already holds.
            if (status.code() == ErrorCode::NotFound) {
                return Status::ok();
            }
            return status;
        }
        return Status::ok();
    }

    bool contains(const std::string& target) const override
    {
        PCREDENTIALW credential = nullptr;
        const BOOL found =
            ::CredReadW(vaultTarget(target).c_str(), CRED_TYPE_GENERIC, 0, &credential);
        if (found != FALSE) {
            ::CredFree(credential);
            return true;
        }
        return false;
    }
};

} // namespace

CredentialStorePtr makeCredentialStore()
{
    return std::make_shared<WindowsCredentialStore>();
}

std::string credentialTargetPrefix()
{
    return std::string{kPrefix};
}

} // namespace nova::profiles
