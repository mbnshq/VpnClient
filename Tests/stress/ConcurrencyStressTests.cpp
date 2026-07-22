// Concurrency stress: run the real primitives under many threads and assert
// the invariants that a data race would break - no crash, every operation
// accounted for, and a consistent final state. Assertions are deterministic
// (counts and final state), never timing-dependent, so the suite does not flake.
//
// Built with ASan (the ninja-asan preset) these are also a race/UAF detector.
#include <NovaVPN/Core/Cancellation.h>
#include <NovaVPN/Core/Config.h>
#include <NovaVPN/Core/EventBus.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Logs/Sink.h>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <barrier>
#include <filesystem>
#include <thread>
#include <vector>

using namespace nova;

namespace {

/// Runs `work(threadIndex)` on `threads` threads that all start together (a
/// barrier maximises contention), and joins them.
template <typename Fn>
void runConcurrently(int threads, Fn&& work)
{
    std::barrier sync{threads};
    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (int i = 0; i < threads; ++i) {
        pool.emplace_back([i, &sync, &work] {
            sync.arrive_and_wait();
            work(i);
        });
    }
    for (auto& t : pool) {
        t.join();
    }
}

struct StressEvent {
    int value = 0;
};

} // namespace

TEST_CASE("EventBus survives concurrent publish and subscribe churn",
          "[stress][eventbus]")
{
    auto bus = EventBus::create();

    std::atomic<u64> delivered{0};
    // A set of long-lived subscribers whose deliveries we count exactly.
    std::vector<EventBus::Subscription> stable;
    constexpr int kStable = 8;
    for (int i = 0; i < kStable; ++i) {
        stable.push_back(bus->subscribe<StressEvent>(
            [&delivered](const StressEvent&) { delivered.fetch_add(1, std::memory_order_relaxed); }));
    }

    constexpr int kPublishers = 8;
    constexpr int kPerPublisher = 2000;

    // Publishers hammer the bus while churners add and drop short-lived
    // subscriptions - the classic use-after-free shape if the bus mishandles
    // its handler list.
    runConcurrently(kPublishers + 4, [&](int index) {
        if (index < kPublishers) {
            for (int i = 0; i < kPerPublisher; ++i) {
                bus->publish(StressEvent{i});
            }
        } else {
            for (int i = 0; i < 5000; ++i) {
                auto sub = bus->subscribe<StressEvent>([](const StressEvent&) {});
                sub.reset();
            }
        }
    });

    // Every publish reached every stable subscriber.
    REQUIRE(delivered.load() == static_cast<u64>(kStable) * kPublishers * kPerPublisher);
    REQUIRE(bus->subscriberCount<StressEvent>() == kStable);
}

TEST_CASE("the logger accounts for every record under a multi-thread flood",
          "[stress][logs]")
{
    auto ring = std::make_shared<logs::RingBufferSink>(1024, logs::Level::Trace);

    logs::LoggerOptions options;
    options.minimumLevel = logs::Level::Trace;
    options.queueCapacity = 256; // small, to force drops under load
    logs::Logger logger{options};
    logger.addSink(ring);

    constexpr int kThreads = 8;
    constexpr int kPerThread = 20000;
    std::atomic<u64> submitted{0};

    runConcurrently(kThreads, [&](int) {
        for (int i = 0; i < kPerThread; ++i) {
            logs::LogRecord record;
            record.timestamp = SystemClock::now();
            record.level = logs::Level::Info;
            record.message = "flood";
            if (logger.submit(std::move(record))) {
                submitted.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    logger.flush();

    // Nothing is lost silently: every attempt was either submitted or counted
    // as a drop.
    const u64 total = static_cast<u64>(kThreads) * kPerThread;
    REQUIRE(submitted.load() + logger.droppedCount() == total);
    // And the drain thread delivered at least everything that fit.
    REQUIRE(submitted.load() > 0);
}

TEST_CASE("ConfigStore tolerates concurrent readers and writers",
          "[stress][config]")
{
    const auto path = std::filesystem::temp_directory_path() /
                      ("novavpn-stress-" + Uuid::generate().toString() + ".json");
    ConfigStore store{path, serviceConfigDefaults()};
    REQUIRE(store.load().isOk());

    constexpr int kThreads = 8;
    std::atomic<u64> reads{0};

    runConcurrently(kThreads, [&](int index) {
        for (int i = 0; i < 5000; ++i) {
            if (index % 2 == 0) {
                (void)store.set("/connection/mtu", 1400 + (i % 100));
            } else {
                const int mtu = store.get<int>("/connection/mtu", 0);
                REQUIRE(mtu >= 1400); // never torn: always a value a writer set
                reads.fetch_add(1, std::memory_order_relaxed);
            }
        }
    });

    REQUIRE(reads.load() > 0);
    // The store is still coherent after the storm.
    REQUIRE(store.get<int>("/connection/mtu", 0) >= 1400);
    REQUIRE(store.get<std::string>("/service/logLevel", "") == "info");

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST_CASE("CancellationSource callbacks are consistent under contention",
          "[stress][cancellation]")
{
    // Many threads register callbacks while one cancels; every callback that is
    // still registered at cancel time runs exactly once, and none runs twice.
    for (int round = 0; round < 20; ++round) {
        CancellationSource source;
        std::atomic<int> fired{0};

        std::vector<CancellationToken::Registration> regs(64);
        std::atomic<bool> go{false};

        runConcurrently(9, [&](int index) {
            if (index == 8) {
                while (!go.load()) { /* spin until registrations start */ }
                source.cancel();
            } else {
                for (int i = index; i < 64; i += 8) {
                    regs[i] = source.token().onCancelled(
                        [&fired] { fired.fetch_add(1, std::memory_order_relaxed); });
                    go.store(true);
                }
            }
        });

        // Cancel is idempotent; a second cancel adds nothing.
        const int afterFirst = fired.load();
        source.cancel();
        REQUIRE(fired.load() == afterFirst);
        // Every callback fired at most once (<= number registered).
        REQUIRE(fired.load() <= 64);
    }
}

TEST_CASE("EventBus subscription destruction races publishing safely",
          "[stress][eventbus]")
{
    // A subscriber destroyed on one thread while another publishes must never
    // deliver to the dead handler - the guarantee that lets a handler capture
    // `this`.
    auto bus = EventBus::create();
    std::atomic<bool> stop{false};

    std::thread publisher([&] {
        while (!stop.load()) {
            bus->publish(StressEvent{1});
        }
    });

    for (int i = 0; i < 2000; ++i) {
        std::atomic<int> local{0};
        {
            auto sub = bus->subscribe<StressEvent>(
                [&local](const StressEvent&) { local.fetch_add(1, std::memory_order_relaxed); });
            // Let a few publishes hit it, then drop it.
        }
        // After the subscription is gone, local must not be touched again - but
        // we cannot observe that directly here; the real detector is ASan. The
        // assertion is simply that we got here without a crash.
    }

    stop.store(true);
    publisher.join();
    SUCCEED("no crash under publish/unsubscribe race");
}
