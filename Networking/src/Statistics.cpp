#include <NovaVPN/Networking/Statistics.h>

namespace nova::net {
namespace {

/// Difference that treats a decrease as a counter reset (0) rather than
/// wrapping into an enormous positive delta.
constexpr u64 delta(u64 previous, u64 current) noexcept
{
    return current >= previous ? current - previous : 0;
}

} // namespace

TrafficRates computeRates(const TrafficCounters& previous, const TrafficCounters& current,
                          Milliseconds interval)
{
    TrafficRates rates;
    if (interval.count() <= 0) {
        return rates;
    }

    const double seconds = static_cast<double>(interval.count()) / 1000.0;

    rates.bitsPerSecondUp =
        static_cast<double>(delta(previous.bytesSent, current.bytesSent)) * 8.0 / seconds;
    rates.bitsPerSecondDown =
        static_cast<double>(delta(previous.bytesReceived, current.bytesReceived)) * 8.0 / seconds;
    rates.packetsPerSecondUp =
        static_cast<double>(delta(previous.packetsSent, current.packetsSent)) / seconds;
    rates.packetsPerSecondDown =
        static_cast<double>(delta(previous.packetsReceived, current.packetsReceived)) / seconds;

    return rates;
}

} // namespace nova::net
