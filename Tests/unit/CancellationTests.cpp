#include <NovaVPN/Core/Cancellation.h>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <thread>

using namespace nova;

TEST_CASE("a token reflects its source", "[cancellation]")
{
    CancellationSource source;
    const CancellationToken token = source.token();

    REQUIRE_FALSE(token.isCancelled());
    REQUIRE_FALSE(source.isCancelled());

    source.cancel();

    REQUIRE(token.isCancelled());
    REQUIRE(source.isCancelled());

    source.cancel(); // idempotent
    REQUIRE(token.isCancelled());
}

TEST_CASE("a default token never cancels", "[cancellation]")
{
    const CancellationToken token;
    REQUIRE_FALSE(token.isCancelled());
    REQUIRE_FALSE(token.waitFor(Milliseconds{1}));
}

TEST_CASE("waitFor returns early on cancellation", "[cancellation]")
{
    CancellationSource source;
    const CancellationToken token = source.token();

    std::thread canceller{[&source] {
        std::this_thread::sleep_for(Milliseconds{20});
        source.cancel();
    }};

    const auto started = SteadyClock::now();
    const bool cancelled = token.waitFor(Milliseconds{5000});
    const auto elapsed = SteadyClock::now() - started;

    canceller.join();

    REQUIRE(cancelled);
    // It must not have waited out the full timeout.
    REQUIRE(std::chrono::duration_cast<Milliseconds>(elapsed) < Milliseconds{4000});
}

TEST_CASE("waitFor reports a timeout when nothing cancels", "[cancellation]")
{
    CancellationSource source;
    REQUIRE_FALSE(source.token().waitFor(Milliseconds{5}));
}

TEST_CASE("callbacks run exactly once on cancellation", "[cancellation]")
{
    CancellationSource source;
    std::atomic<int> calls{0};

    auto registration = source.token().onCancelled([&calls] { ++calls; });
    REQUIRE(calls.load() == 0);

    source.cancel();
    REQUIRE(calls.load() == 1);

    source.cancel();
    REQUIRE(calls.load() == 1);
}

TEST_CASE("registering on an already-cancelled token runs immediately",
          "[cancellation]")
{
    CancellationSource source;
    source.cancel();

    std::atomic<int> calls{0};
    auto registration = source.token().onCancelled([&calls] { ++calls; });

    REQUIRE(calls.load() == 1);
    REQUIRE_FALSE(registration.isActive());
}

TEST_CASE("a destroyed registration does not fire", "[cancellation]")
{
    CancellationSource source;
    std::atomic<int> calls{0};

    {
        auto registration = source.token().onCancelled([&calls] { ++calls; });
        REQUIRE(registration.isActive());
    }

    source.cancel();
    // This is the guarantee that lets a handler capture `this` safely.
    REQUIRE(calls.load() == 0);
}

TEST_CASE("tokens are safe to share across threads", "[cancellation]")
{
    CancellationSource source;
    std::atomic<int> completed{0};

    std::vector<std::thread> workers;
    for (int i = 0; i < 8; ++i) {
        workers.emplace_back([token = source.token(), &completed] {
            while (!token.isCancelled()) {
                std::this_thread::sleep_for(Milliseconds{1});
            }
            ++completed;
        });
    }

    std::this_thread::sleep_for(Milliseconds{10});
    source.cancel();

    for (auto& worker : workers) {
        worker.join();
    }
    REQUIRE(completed.load() == 8);
}
