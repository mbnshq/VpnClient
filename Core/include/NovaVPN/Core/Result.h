// NovaVPN - Core/Result.h
// Result<T> = value-or-Status. Thin, allocation-free wrapper over std::variant
// with the ergonomics the codebase relies on (NOVA_ASSIGN_OR_RETURN).
#pragma once

#include <NovaVPN/Core/Status.h>

#include <cassert>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

namespace nova {

template <typename T>
class [[nodiscard]] Result final {
    static_assert(!std::is_same_v<std::decay_t<T>, Status>,
                  "Result<Status> is meaningless - return Status directly.");
    static_assert(!std::is_reference_v<T>, "Result<T&> is not supported.");

public:
    using value_type = T;

    Result(T value) noexcept(std::is_nothrow_move_constructible_v<T>)
        : m_storage(std::in_place_index<0>, std::move(value))
    {
    }

    Result(Status status) : m_storage(std::in_place_index<1>, std::move(status))
    {
        assert(std::get<1>(m_storage).isError() && "Result must not carry an Ok status");
    }

    [[nodiscard]] bool isOk() const noexcept { return m_storage.index() == 0; }
    [[nodiscard]] bool isError() const noexcept { return m_storage.index() == 1; }
    explicit operator bool() const noexcept { return isOk(); }

    /// Precondition: isOk().
    [[nodiscard]] T& value() & noexcept
    {
        assert(isOk());
        return std::get<0>(m_storage);
    }
    [[nodiscard]] const T& value() const& noexcept
    {
        assert(isOk());
        return std::get<0>(m_storage);
    }
    [[nodiscard]] T&& value() && noexcept
    {
        assert(isOk());
        return std::move(std::get<0>(m_storage));
    }

    T* operator->() noexcept { return &value(); }
    const T* operator->() const noexcept { return &value(); }
    T& operator*() & noexcept { return value(); }
    const T& operator*() const& noexcept { return value(); }
    T&& operator*() && noexcept { return std::move(*this).value(); }

    /// Precondition: isError().
    [[nodiscard]] const Status& status() const& noexcept
    {
        assert(isError());
        return std::get<1>(m_storage);
    }
    [[nodiscard]] Status&& status() && noexcept
    {
        assert(isError());
        return std::move(std::get<1>(m_storage));
    }

    /// Ok() when the result holds a value, otherwise the carried error.
    [[nodiscard]] Status statusOrOk() const
    {
        return isError() ? std::get<1>(m_storage) : Status::ok();
    }

    /// Returns the value, or `fallback` when the result holds an error.
    template <typename U>
    [[nodiscard]] T valueOr(U&& fallback) const&
    {
        return isOk() ? std::get<0>(m_storage) : static_cast<T>(std::forward<U>(fallback));
    }

    [[nodiscard]] std::optional<T> toOptional() const&
    {
        return isOk() ? std::optional<T>{std::get<0>(m_storage)} : std::nullopt;
    }

    /// Applies `fn` to the contained value, propagating any error unchanged.
    template <typename Fn>
    [[nodiscard]] auto map(Fn&& fn) const& -> Result<std::invoke_result_t<Fn, const T&>>
    {
        using Out = Result<std::invoke_result_t<Fn, const T&>>;
        if (isError()) {
            return Out{std::get<1>(m_storage)};
        }
        return Out{std::forward<Fn>(fn)(std::get<0>(m_storage))};
    }

private:
    std::variant<T, Status> m_storage;
};

} // namespace nova

#define NOVA_DETAIL_CAT_(a, b) a##b
#define NOVA_DETAIL_CAT(a, b) NOVA_DETAIL_CAT_(a, b)

/// `NOVA_ASSIGN_OR_RETURN(auto cfg, parseConfig(path));`
/// Evaluates the expression once; on error returns the Status from the
/// enclosing function, otherwise binds the declaration to the value.
#define NOVA_ASSIGN_OR_RETURN(decl, expr)                                            \
    auto NOVA_DETAIL_CAT(nova_result_, __LINE__) = (expr);                           \
    if (NOVA_DETAIL_CAT(nova_result_, __LINE__).isError()) {                         \
        return std::move(NOVA_DETAIL_CAT(nova_result_, __LINE__)).status();          \
    }                                                                                \
    decl = std::move(NOVA_DETAIL_CAT(nova_result_, __LINE__)).value()
