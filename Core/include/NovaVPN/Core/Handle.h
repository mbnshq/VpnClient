// NovaVPN - Core/Handle.h
// RAII wrappers for the Windows handle families used by the service, the tunnel
// and the firewall engine. Header-only so callers pay nothing for them.
#pragma once

#include <utility>

namespace nova::win {

/// Generic move-only owner for an opaque OS resource.
///
/// `Traits` must provide:
///   using value_type = <handle type>;
///   static value_type invalid() noexcept;
///   static void close(value_type) noexcept;
template <typename Traits>
class UniqueResource final {
public:
    using value_type = typename Traits::value_type;

    UniqueResource() noexcept : m_value(Traits::invalid()) {}
    explicit UniqueResource(value_type value) noexcept : m_value(value) {}

    ~UniqueResource() { reset(); }

    UniqueResource(UniqueResource&& other) noexcept
        : m_value(std::exchange(other.m_value, Traits::invalid()))
    {
    }

    UniqueResource& operator=(UniqueResource&& other) noexcept
    {
        if (this != &other) {
            reset();
            m_value = std::exchange(other.m_value, Traits::invalid());
        }
        return *this;
    }

    UniqueResource(const UniqueResource&) = delete;
    UniqueResource& operator=(const UniqueResource&) = delete;

    [[nodiscard]] value_type get() const noexcept { return m_value; }
    [[nodiscard]] bool isValid() const noexcept { return m_value != Traits::invalid(); }
    explicit operator bool() const noexcept { return isValid(); }

    /// Releases ownership without closing - for handing the handle to an API
    /// that takes ownership.
    [[nodiscard]] value_type release() noexcept
    {
        return std::exchange(m_value, Traits::invalid());
    }

    void reset(value_type value = Traits::invalid()) noexcept
    {
        if (m_value != Traits::invalid()) {
            Traits::close(m_value);
        }
        m_value = value;
    }

    /// Out-parameter form: `CreateFoo(&handle.put())`.
    [[nodiscard]] value_type* put() noexcept
    {
        reset();
        return &m_value;
    }

private:
    value_type m_value;
};

} // namespace nova::win
