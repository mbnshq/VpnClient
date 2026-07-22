// NovaVPN - Networking/Statistics.h
// Counters and quality metrics surfaced on the dashboard.
//
// The service samples these once per second per tunnel and publishes a
// StatisticsTick on the EventBus; the UI does no polling of its own.
#pragma once

#include <NovaVPN/Core/Types.h>

#include <deque>
#include <string>
#include <vector>

namespace nova::net {

/// Monotonic byte/packet counters for one tunnel since it came up.
struct TrafficCounters {
    ByteCount bytesSent = 0;
    ByteCount bytesReceived = 0;
    u64       packetsSent = 0;
    u64       packetsReceived = 0;
    u64       packetsDropped = 0;
    /// Compressed and encrypted byte totals differ from the payload totals;
    /// tracking both is what makes an overhead figure honest.
    ByteCount wireBytesSent = 0;
    ByteCount wireBytesReceived = 0;
};

/// Instantaneous rates derived from two consecutive counter samples.
struct TrafficRates {
    double bitsPerSecondUp = 0.0;
    double bitsPerSecondDown = 0.0;
    double packetsPerSecondUp = 0.0;
    double packetsPerSecondDown = 0.0;
};

/// Link quality, measured by the keepalive/ping probe.
struct LinkQuality {
    /// Round-trip time of the most recent probe.
    Milliseconds latency{0};
    /// Exponentially weighted mean and the jitter around it.
    Milliseconds latencyAverage{0};
    Milliseconds jitter{0};
    /// Fraction in [0, 1] over the trailing probe window.
    double       packetLoss = 0.0;
    /// Number of probes in the trailing window.
    u32          probeCount = 0;
    /// Time since the last successful probe. Growing past the keepalive
    /// interval is what triggers a reconnect.
    Seconds      sinceLastResponse{0};
};

/// One dashboard sample.
struct StatisticsSample {
    SystemTime      timestamp{};
    TrafficCounters counters;
    TrafficRates    rates;
    LinkQuality     quality;
};

/// Published once per second per active tunnel.
struct StatisticsTick {
    Id               tunnelId;
    StatisticsSample sample;
};

/// Fixed-capacity time series backing the latency and throughput graphs.
/// Sized by dashboard.graphWindowSeconds (default 120 samples).
class SampleWindow final {
public:
    explicit SampleWindow(std::size_t capacity = 120) : m_capacity(capacity == 0 ? 1 : capacity) {}

    void push(StatisticsSample sample)
    {
        m_samples.push_back(std::move(sample));
        while (m_samples.size() > m_capacity) {
            m_samples.pop_front();
        }
    }

    [[nodiscard]] const std::deque<StatisticsSample>& samples() const noexcept
    {
        return m_samples;
    }
    [[nodiscard]] std::size_t capacity() const noexcept { return m_capacity; }
    [[nodiscard]] bool empty() const noexcept { return m_samples.empty(); }
    void clear() { m_samples.clear(); }

    /// Peak downstream rate in the window - used to scale the graph's y axis.
    [[nodiscard]] double peakDownBitsPerSecond() const noexcept
    {
        double peak = 0.0;
        for (const auto& sample : m_samples) {
            peak = sample.rates.bitsPerSecondDown > peak ? sample.rates.bitsPerSecondDown : peak;
        }
        return peak;
    }

    [[nodiscard]] double peakUpBitsPerSecond() const noexcept
    {
        double peak = 0.0;
        for (const auto& sample : m_samples) {
            peak = sample.rates.bitsPerSecondUp > peak ? sample.rates.bitsPerSecondUp : peak;
        }
        return peak;
    }

private:
    std::size_t                  m_capacity;
    std::deque<StatisticsSample> m_samples;
};

/// Computes rates from two counter samples taken `interval` apart.
/// Handles counter resets (reconnect) by reporting zero rather than a negative
/// or absurd rate.
[[nodiscard]] TrafficRates computeRates(const TrafficCounters& previous,
                                        const TrafficCounters& current, Milliseconds interval);

} // namespace nova::net
