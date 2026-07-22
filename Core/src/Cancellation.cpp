#include <NovaVPN/Core/Cancellation.h>

#include <algorithm>
#include <thread>
#include <utility>

namespace nova {

CancellationSource::CancellationSource() : m_state(std::make_shared<State>()) {}

CancellationSource::~CancellationSource() = default;

void CancellationSource::cancel()
{
    if (!m_state) {
        return;
    }

    std::vector<std::pair<u64, std::function<void()>>> callbacks;
    {
        std::lock_guard lock{m_state->mutex};
        if (m_state->cancelled) {
            return;
        }
        m_state->cancelled = true;
        callbacks.swap(m_state->callbacks);
    }

    m_state->cv.notify_all();

    // Callbacks run outside the lock so a handler may query the token, register
    // further work or destroy its Registration without deadlocking.
    for (auto& [id, callback] : callbacks) {
        if (callback) {
            callback();
        }
    }
}

bool CancellationSource::isCancelled() const noexcept
{
    if (!m_state) {
        return false;
    }
    std::lock_guard lock{m_state->mutex};
    return m_state->cancelled;
}

CancellationToken CancellationSource::token() const noexcept
{
    return CancellationToken{m_state};
}

// --- CancellationToken ----------------------------------------------------

bool CancellationToken::isCancelled() const noexcept
{
    if (!m_state) {
        return false;
    }
    std::lock_guard lock{m_state->mutex};
    return m_state->cancelled;
}

bool CancellationToken::waitFor(Milliseconds timeout) const
{
    if (!m_state) {
        // A default token never cancels; honour the caller's sleep intent.
        std::this_thread::sleep_for(timeout);
        return false;
    }
    std::unique_lock lock{m_state->mutex};
    return m_state->cv.wait_for(lock, timeout, [this] { return m_state->cancelled; });
}

CancellationToken::Registration CancellationToken::onCancelled(
    std::function<void()> callback) const
{
    if (!m_state || !callback) {
        return Registration{};
    }

    u64 id = 0;
    {
        std::lock_guard lock{m_state->mutex};
        if (!m_state->cancelled) {
            id = m_state->nextId++;
            m_state->callbacks.emplace_back(id, std::move(callback));
            return Registration{m_state, id};
        }
    }

    // Already cancelled - run immediately, outside the lock.
    callback();
    return Registration{};
}

// --- Registration ---------------------------------------------------------

CancellationToken::Registration::Registration(std::shared_ptr<CancellationSource::State> state,
                                              u64 id) noexcept
    : m_state(std::move(state)), m_id(id)
{
}

CancellationToken::Registration::Registration(Registration&& other) noexcept
    : m_state(std::move(other.m_state)), m_id(std::exchange(other.m_id, 0))
{
}

CancellationToken::Registration& CancellationToken::Registration::operator=(
    Registration&& other) noexcept
{
    if (this != &other) {
        reset();
        m_state = std::move(other.m_state);
        m_id    = std::exchange(other.m_id, 0);
    }
    return *this;
}

CancellationToken::Registration::~Registration()
{
    reset();
}

void CancellationToken::Registration::reset() noexcept
{
    if (m_id == 0) {
        return;
    }
    if (auto state = m_state.lock()) {
        std::lock_guard lock{state->mutex};
        auto it = std::find_if(state->callbacks.begin(), state->callbacks.end(),
                               [this](const auto& entry) { return entry.first == m_id; });
        if (it != state->callbacks.end()) {
            state->callbacks.erase(it);
        }
    }
    m_state.reset();
    m_id = 0;
}

} // namespace nova
