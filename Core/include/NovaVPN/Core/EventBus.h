// NovaVPN - Core/EventBus.h
// In-process typed publish/subscribe. Used by the service to broadcast state
// changes (tunnel state, statistics ticks, leak alerts) to the IPC layer, the
// logger and the telemetry sink without those modules knowing each other.
//
// Contract:
//   * publish() invokes handlers synchronously on the calling thread;
//     handlers must be short and must not block on tunnel I/O.
//   * a Subscription unsubscribes on destruction, so a handler can never
//     outlive the object whose members it captured.
//   * subscribing or unsubscribing from inside a handler is safe.
#pragma once

#include <NovaVPN/Core/Types.h>

#include <functional>
#include <memory>
#include <mutex>
#include <typeindex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace nova {

class EventBus final : public std::enable_shared_from_this<EventBus> {
public:
    /// RAII handle returned by subscribe().
    class Subscription final {
    public:
        Subscription() noexcept = default;
        ~Subscription() { reset(); }

        Subscription(Subscription&& other) noexcept
            : m_bus(std::move(other.m_bus)),
              m_type(other.m_type),
              m_id(std::exchange(other.m_id, 0))
        {
        }

        Subscription& operator=(Subscription&& other) noexcept
        {
            if (this != &other) {
                reset();
                m_bus  = std::move(other.m_bus);
                m_type = other.m_type;
                m_id   = std::exchange(other.m_id, 0);
            }
            return *this;
        }

        Subscription(const Subscription&) = delete;
        Subscription& operator=(const Subscription&) = delete;

        [[nodiscard]] bool isActive() const noexcept { return m_id != 0; }

        void reset() noexcept
        {
            if (m_id == 0) {
                return;
            }
            if (auto bus = m_bus.lock()) {
                bus->unsubscribe(m_type, m_id);
            }
            m_bus.reset();
            m_id = 0;
        }

    private:
        friend class EventBus;
        Subscription(std::weak_ptr<EventBus> bus, std::type_index type, u64 id) noexcept
            : m_bus(std::move(bus)), m_type(type), m_id(id)
        {
        }

        std::weak_ptr<EventBus> m_bus;
        std::type_index         m_type{typeid(void)};
        u64                     m_id = 0;
    };

    [[nodiscard]] static std::shared_ptr<EventBus> create()
    {
        return std::shared_ptr<EventBus>{new EventBus{}};
    }

    /// Registers `handler` for events of type `Event`.
    template <typename Event>
    [[nodiscard]] Subscription subscribe(std::function<void(const Event&)> handler)
    {
        if (!handler) {
            return Subscription{};
        }

        const std::type_index type{typeid(Event)};
        auto erased = std::make_shared<std::function<void(const void*)>>(
            [handler = std::move(handler)](const void* payload) {
                handler(*static_cast<const Event*>(payload));
            });

        std::lock_guard lock{m_mutex};
        const u64 id = m_nextId++;
        m_handlers[type].push_back(Entry{id, std::move(erased)});
        return Subscription{weak_from_this(), type, id};
    }

    /// Delivers `event` to every current subscriber of that type.
    /// Handlers are copied under the lock and invoked outside it.
    template <typename Event>
    void publish(const Event& event)
    {
        std::vector<Entry> snapshot;
        {
            std::lock_guard lock{m_mutex};
            const auto it = m_handlers.find(std::type_index{typeid(Event)});
            if (it == m_handlers.end() || it->second.empty()) {
                return;
            }
            snapshot = it->second;
        }

        for (const auto& entry : snapshot) {
            (*entry.handler)(static_cast<const void*>(&event));
        }
    }

    /// Number of live subscribers for an event type (diagnostics/tests).
    template <typename Event>
    [[nodiscard]] std::size_t subscriberCount() const
    {
        std::lock_guard lock{m_mutex};
        const auto it = m_handlers.find(std::type_index{typeid(Event)});
        return it == m_handlers.end() ? 0 : it->second.size();
    }

private:
    EventBus() = default;

    struct Entry {
        u64 id = 0;
        std::shared_ptr<std::function<void(const void*)>> handler;
    };

    void unsubscribe(std::type_index type, u64 id)
    {
        std::lock_guard lock{m_mutex};
        const auto it = m_handlers.find(type);
        if (it == m_handlers.end()) {
            return;
        }
        auto& entries = it->second;
        for (auto entry = entries.begin(); entry != entries.end(); ++entry) {
            if (entry->id == id) {
                entries.erase(entry);
                break;
            }
        }
        if (entries.empty()) {
            m_handlers.erase(it);
        }
    }

    mutable std::mutex m_mutex;
    std::unordered_map<std::type_index, std::vector<Entry>> m_handlers;
    u64 m_nextId = 1;
};

} // namespace nova
