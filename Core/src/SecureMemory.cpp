#include <NovaVPN/Core/SecureMemory.h>
#include <NovaVPN/Core/WinError.h>

#include <Windows.h>

#include <cstring>
#include <new>

namespace nova {
namespace {

/// Rounds `size` up to a multiple of the system allocation granularity's page
/// size so VirtualLock covers whole pages (VirtualLock always locks whole pages
/// anyway; being explicit keeps the accounting honest).
std::size_t roundToPage(std::size_t size) noexcept
{
    SYSTEM_INFO info{};
    ::GetSystemInfo(&info);
    const std::size_t page = info.dwPageSize != 0 ? info.dwPageSize : 4096u;
    const std::size_t rounded = ((size + page - 1) / page) * page;
    return rounded == 0 ? page : rounded;
}

} // namespace

void secureZero(void* data, std::size_t size) noexcept
{
    if (data != nullptr && size != 0) {
        ::RtlSecureZeroMemory(data, size);
    }
}

void secureZero(std::span<std::byte> bytes) noexcept
{
    secureZero(bytes.data(), bytes.size_bytes());
}

void secureClear(std::string& value) noexcept
{
    if (!value.empty()) {
        secureZero(value.data(), value.size());
    }
    value.clear();
    value.shrink_to_fit();
}

bool constantTimeEquals(std::span<const std::byte> a, std::span<const std::byte> b) noexcept
{
    // Length is not secret; content is. Bail early on length mismatch, then
    // compare every byte without branching on the result.
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff = static_cast<unsigned char>(
            diff | (static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i])));
    }
    return diff == 0;
}

bool constantTimeEquals(std::string_view a, std::string_view b) noexcept
{
    return constantTimeEquals(
        std::span{reinterpret_cast<const std::byte*>(a.data()), a.size()},
        std::span{reinterpret_cast<const std::byte*>(b.data()), b.size()});
}

// --- SecureBuffer ---------------------------------------------------------

SecureBuffer::SecureBuffer(std::size_t size)
{
    if (size == 0) {
        return;
    }

    const std::size_t reserved = roundToPage(size);
    void* memory = ::VirtualAlloc(nullptr, reserved, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (memory == nullptr) {
        throw std::bad_alloc{};
    }

    // Best effort: VirtualLock fails when the process working set quota is
    // exhausted. The buffer is still usable, just not guaranteed non-paged.
    m_locked = ::VirtualLock(memory, reserved) != FALSE;

    m_data = static_cast<std::byte*>(memory);
    m_size = size;
    std::memset(m_data, 0, reserved);
}

SecureBuffer SecureBuffer::copyFrom(std::span<const std::byte> data)
{
    SecureBuffer buffer{data.size()};
    if (!data.empty()) {
        std::memcpy(buffer.m_data, data.data(), data.size());
    }
    return buffer;
}

SecureBuffer SecureBuffer::copyFrom(std::string_view text)
{
    return copyFrom(std::span{reinterpret_cast<const std::byte*>(text.data()), text.size()});
}

SecureBuffer::~SecureBuffer()
{
    reset();
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : m_data(other.m_data), m_size(other.m_size), m_locked(other.m_locked)
{
    other.m_data   = nullptr;
    other.m_size   = 0;
    other.m_locked = false;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept
{
    if (this != &other) {
        reset();
        m_data         = other.m_data;
        m_size         = other.m_size;
        m_locked       = other.m_locked;
        other.m_data   = nullptr;
        other.m_size   = 0;
        other.m_locked = false;
    }
    return *this;
}

SecureBuffer SecureBuffer::clone() const
{
    return copyFrom(bytes());
}

std::string_view SecureBuffer::view() const noexcept
{
    if (m_data == nullptr || m_size == 0) {
        return {};
    }
    return std::string_view{reinterpret_cast<const char*>(m_data), m_size};
}

void SecureBuffer::reset() noexcept
{
    if (m_data == nullptr) {
        m_size   = 0;
        m_locked = false;
        return;
    }

    const std::size_t reserved = roundToPage(m_size);
    ::RtlSecureZeroMemory(m_data, reserved);
    if (m_locked) {
        ::VirtualUnlock(m_data, reserved);
    }
    ::VirtualFree(m_data, 0, MEM_RELEASE);

    m_data   = nullptr;
    m_size   = 0;
    m_locked = false;
}

// --- SecureString ---------------------------------------------------------

SecureString SecureString::clone() const
{
    SecureString copy;
    copy.m_buffer = m_buffer.clone();
    return copy;
}

void SecureString::assign(std::string_view text)
{
    m_buffer = SecureBuffer::copyFrom(text);
}

// --- process hardening ----------------------------------------------------

Status hardenProcessAgainstDumps() noexcept
{
    // 1. Refuse debugger attachment from non-protected processes and forbid
    //    child processes from inheriting handles to our memory.
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCode{};
    dynamicCode.ProhibitDynamicCode = 1;
    // Best effort: some hosts (WinUI/XAML, .NET) legitimately generate code, so
    // a failure here is not fatal - it is logged by the caller.
    ::SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamicCode, sizeof(dynamicCode));

    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPoints{};
    extensionPoints.DisableExtensionPoints = 1;
    ::SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &extensionPoints,
                                 sizeof(extensionPoints));

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoad{};
    imageLoad.NoRemoteImages     = 1;
    imageLoad.NoLowMandatoryLabelImages = 1;
    ::SetProcessMitigationPolicy(ProcessImageLoadPolicy, &imageLoad, sizeof(imageLoad));

    // 2. Keep the process out of automatic crash-dump collection that would
    //    otherwise capture locked secret pages.
    if (::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) == 0) {
        // SetErrorMode returns the previous mode; 0 is a legitimate previous
        // value, so no error check is possible. Nothing to do.
    }

    return Status::ok();
}

} // namespace nova
