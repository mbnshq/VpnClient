#include <NovaVPN/Networking/Statistics.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::net;

TEST_CASE("rates are derived from a counter delta", "[net][stats]")
{
    TrafficCounters previous;
    previous.bytesSent       = 1000;
    previous.bytesReceived   = 2000;
    previous.packetsSent     = 10;
    previous.packetsReceived = 20;

    TrafficCounters current;
    current.bytesSent       = 2000;   // +1000 bytes
    current.bytesReceived   = 6000;   // +4000 bytes
    current.packetsSent     = 20;
    current.packetsReceived = 60;

    const TrafficRates rates = computeRates(previous, current, Milliseconds{1000});

    REQUIRE(rates.bitsPerSecondUp == 8000.0);
    REQUIRE(rates.bitsPerSecondDown == 32000.0);
    REQUIRE(rates.packetsPerSecondUp == 10.0);
    REQUIRE(rates.packetsPerSecondDown == 40.0);
}

TEST_CASE("a half-second interval doubles the rate", "[net][stats]")
{
    TrafficCounters previous;
    TrafficCounters current;
    current.bytesReceived = 1000;

    const TrafficRates rates = computeRates(previous, current, Milliseconds{500});
    REQUIRE(rates.bitsPerSecondDown == 16000.0);
}

TEST_CASE("a counter reset reports zero rather than a wrapped delta",
          "[net][stats]")
{
    // Counters restart at zero after a reconnect. Subtracting naively would
    // produce an astronomically large rate on the dashboard.
    TrafficCounters previous;
    previous.bytesSent     = 1'000'000;
    previous.bytesReceived = 1'000'000;

    TrafficCounters current; // all zero

    const TrafficRates rates = computeRates(previous, current, Milliseconds{1000});
    REQUIRE(rates.bitsPerSecondUp == 0.0);
    REQUIRE(rates.bitsPerSecondDown == 0.0);
}

TEST_CASE("a non-positive interval yields zero rates", "[net][stats]")
{
    TrafficCounters previous;
    TrafficCounters current;
    current.bytesSent = 5000;

    REQUIRE(computeRates(previous, current, Milliseconds{0}).bitsPerSecondUp == 0.0);
    REQUIRE(computeRates(previous, current, Milliseconds{-100}).bitsPerSecondUp == 0.0);
}

TEST_CASE("the sample window keeps the newest samples", "[net][stats]")
{
    SampleWindow window{3};
    REQUIRE(window.empty());
    REQUIRE(window.capacity() == 3);

    for (int i = 1; i <= 5; ++i) {
        StatisticsSample sample;
        sample.rates.bitsPerSecondDown = static_cast<double>(i) * 100.0;
        window.push(sample);
    }

    REQUIRE(window.samples().size() == 3);
    REQUIRE(window.samples().front().rates.bitsPerSecondDown == 300.0);
    REQUIRE(window.samples().back().rates.bitsPerSecondDown == 500.0);
    REQUIRE(window.peakDownBitsPerSecond() == 500.0);

    window.clear();
    REQUIRE(window.empty());
    REQUIRE(window.peakDownBitsPerSecond() == 0.0);
}

TEST_CASE("peaks scale the graph axes", "[net][stats]")
{
    SampleWindow window{10};

    for (const double value : {100.0, 900.0, 400.0}) {
        StatisticsSample sample;
        sample.rates.bitsPerSecondUp   = value;
        sample.rates.bitsPerSecondDown = value / 2.0;
        window.push(sample);
    }

    REQUIRE(window.peakUpBitsPerSecond() == 900.0);
    REQUIRE(window.peakDownBitsPerSecond() == 450.0);
}

TEST_CASE("a zero-capacity window degrades to one slot", "[net][stats]")
{
    SampleWindow window{0};
    REQUIRE(window.capacity() == 1);

    window.push(StatisticsSample{});
    window.push(StatisticsSample{});
    REQUIRE(window.samples().size() == 1);
}
