// NovaVPN - Core/SecureMemory.h
// Primitives for handling secrets (passwords, private keys, session keys, TOTP
// seeds). Rules enforced here:
//   * secrets never reach the pagefile   -> VirtualLock on the whole region
//   * secrets never survive a free       -> RtlSecureZeroMemory before release
//   * secrets never land in a crash dump -> pages excluded where the OS allows
//   * secrets never copy implicitly      -> move-only types
#pragma once

#include <NovaVPN/Core/Status.h>
#include <NovaVPN/Core/Types.h>

#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace nova {

/// Overwrites `bytes` with zeroes in a way the optimiser may not elide.
/// Safe to call with an empty span.
void secureZero(std::span<std::byte> bytes) noexcept;
void secureZero(void* data, std::size_t size) noexcept;

/// Zeroes and clears a std::string that held a secret. Note that a string that
/// has already been copied cannot be scrubbed retroactively - prefer
/// SecureBuffer/SecureString for anything long-lived.
void secureClear(std::string& value) noexcept;

/// Constant-time comparison. Runtime depends only on the length, so it is safe
/// for MAC/token/password-hash comparison.
[[nodiscard]] bool constantTimeEquals(std::span<const std::byte> a,
                                      std::span<const std::byte> b) noexcept;
[[nodiscard]] bool constantTimeEquals(std::string_view a, std::string_view b) noexcept;

/// Page-locked, self-zeroing byte buffer. Move-only: a secret has exactly one
/// owner at a time. Copying is available only through the explicit clone().
class SecureBuffer final {
public:
    SecureBuffer() noexcept = default;

    /// Allocates `size` locked, zero-initialised bytes.
    /// Throws std::bad_alloc if the reservation fails; the lock itself is best
    /// effort (it can fail when the process working-set quota is exhausted) and
    /// is reported by isLocked().
    explicit SecureBuffer(std::size_t size);

    /// Copies `data` into a fresh locked buffer.
    static SecureBuffer copyFrom(std::span<const std::byte> data);
    static SecureBuffer copyFrom(std::string_view text);

    ~SecureBuffer();

    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    [[nodiscard]] SecureBuffer clone() const;

    [[nodiscard]] std::byte* data() noexcept { return m_data; }
    [[nodiscard]] const std::byte* data() const noexcept { return m_data; }
    [[nodiscard]] std::size_t size() const noexcept { return m_size; }
    [[nodiscard]] bool empty() const noexcept { return m_size == 0; }
    [[nodiscard]] bool isLocked() const noexcept { return m_locked; }

    [[nodiscard]] std::span<std::byte> bytes() noexcept { return {m_data, m_size}; }
    [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return {m_data, m_size}; }

    /// Reinterprets the buffer as text. The returned view is only valid while
    /// this buffer lives and must not be copied into an unprotected string.
    [[nodiscard]] std::string_view view() const noexcept;

    /// Zeroes and releases the buffer immediately.
    void reset() noexcept;

private:
    std::byte*  m_data   = nullptr;
    std::size_t m_size   = 0;
    bool        m_locked = false;
};

/// Secret string with a SecureBuffer backing store. Use for passwords, PINs,
/// private key PEM blobs and auth tokens.
class SecureString final {
public:
    SecureString() noexcept = default;
    explicit SecureString(std::string_view text) : m_buffer(SecureBuffer::copyFrom(text)) {}

    SecureString(SecureString&&) noexcept = default;
    SecureString& operator=(SecureString&&) noexcept = default;
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    [[nodiscard]] SecureString clone() const;

    [[nodiscard]] std::string_view view() const noexcept { return m_buffer.view(); }
    [[nodiscard]] std::size_t size() const noexcept { return m_buffer.size(); }
    [[nodiscard]] bool empty() const noexcept { return m_buffer.empty(); }

    void assign(std::string_view text);
    void clear() noexcept { m_buffer.reset(); }

    /// Constant-time equality; never use operator== semantics on secrets.
    [[nodiscard]] bool equals(std::string_view other) const noexcept
    {
        return constantTimeEquals(view(), other);
    }

private:
    SecureBuffer m_buffer;
};

/// Excludes the calling process's secret pages from user-mode minidumps and
/// disables the "Werfault" full-heap capture. Called once during startup by the
/// service and the UI host.
Status hardenProcessAgainstDumps() noexcept;

} // namespace nova
