// NovaVPN - Core/Cancellation.h
// Cooperative cancellation. Every long-running operation in NovaVPN (connect,
// reconnect back-off, update download, leak probe) takes a CancellationToken so
// that a disconnect request or a service stop never has to kill a thread.
#pragma once

#include <NovaVPN/Core/Types.h>

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace nova {

class CancellationToken;

/// Producer side. Owned by whoever can cancel the work.
class CancellationSource final {
public:
    CancellationSource();
    ~CancellationSource();

    CancellationSource(CancellationSource&&) noexcept = default;
    CancellationSource& operator=(CancellationSource&&) noexcept = default;
    CancellationSource(const CancellationSource&) = delete;
    CancellationSource& operator=(const CancellationSource&) = delete;

    /// Signals cancellation and runs every registered callback exactly once,
    /// on the calling thread. Idempotent and safe to call concurrently.
    void cancel();

    [[nodiscard]] bool isCancelled() const noexcept;
    [[nodiscard]] CancellationToken token() const noexcept;

private:
    friend class CancellationToken;

    struct State {
        mutable std::mutex              mutex;
        std::condition_variable         cv;
        bool                            cancelled = false;
        u64                             nextId = 1;
        std::vector<std::pair<u64, std::function<void()>>> callbacks;
    };

    std::shared_ptr<State> m_state;
};

/// Consumer side. Cheap to copy; safe to pass across threads.
class CancellationToken final {
public:
    CancellationToken() noexcept = default; ///< A token that is never cancelled.

    [[nodiscard]] bool isCancelled() const noexcept;

    /// Blocks until cancelled or `timeout` elapses.
    /// Returns true if cancellation happened, false on timeout.
    [[nodiscard]] bool waitFor(Milliseconds timeout) const;

    /// Registers `callback`, invoked once when cancellation occurs (immediately
    /// and synchronously if already cancelled). The returned handle unregisters
    /// on destruction, so a callback can never outlive its captured state.
    class Registration final {
    public:
        Registration() noexcept = default;
        ~Registration();
        Registration(Registration&& other) noexcept;
        Registration& operator=(Registration&& other) noexcept;
        Registration(const Registration&) = delete;
        Registration& operator=(const Registration&) = delete;

        /// True while the callback is still registered and could still fire.
        [[nodiscard]] bool isActive() const noexcept { return m_id != 0; }

        void reset() noexcept;

    private:
        friend class CancellationToken;
        Registration(std::shared_ptr<CancellationSource::State> state, u64 id) noexcept;

        std::weak_ptr<CancellationSource::State> m_state;
        u64 m_id = 0;
    };

    [[nodiscard]] Registration onCancelled(std::function<void()> callback) const;

private:
    friend class CancellationSource;
    explicit CancellationToken(std::shared_ptr<CancellationSource::State> state) noexcept
        : m_state(std::move(state))
    {
    }

    std::shared_ptr<CancellationSource::State> m_state;
};

} // namespace nova
