// NovaVPN - Driver/WintunAdapter.h
// Wintun virtual adapter ownership.
//
// Wintun is loaded dynamically from wintun.dll shipped beside the service
// binary. Loading it dynamically (rather than importing) means the service can
// start, report a precise DriverMissing error and let the updater repair the
// install, instead of failing to launch with a loader error the user cannot
// act on.
//
// Security note: the DLL is loaded with LOAD_LIBRARY_SEARCH_APPLICATION_DIR only
// and its Authenticode signature is verified before the first call, so a
// wintun.dll planted in the working directory cannot be used to run code as
// SYSTEM.
//
// Implemented in Phase 3.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Networking/IpAddress.h>

#include <memory>
#include <span>
#include <string>

namespace nova::driver {

struct AdapterInfo {
    std::string name;
    std::string tunnelType;
    u64         luid = 0;
    u32         interfaceIndex = 0;
    /// Wintun driver version, e.g. 0x00000100 for 1.0.
    u32         driverVersion = 0;
};

/// A received or outgoing IP packet. The span points into the ring buffer and
/// is valid only until the next receive/release call.
using PacketView = std::span<const u8>;

class IWintunSession;

/// One Wintun adapter instance.
class IWintunAdapter {
public:
    virtual ~IWintunAdapter() = default;

    [[nodiscard]] virtual const AdapterInfo& info() const noexcept = 0;

    /// Starts the packet session. `ringCapacity` must be a power of two between
    /// 128 KiB and 64 MiB; 4 MiB is the default and is enough to absorb a
    /// scheduling hiccup at gigabit rates.
    [[nodiscard]] virtual Result<std::shared_ptr<IWintunSession>> startSession(
        u32 ringCapacity = 4 * 1024 * 1024) = 0;

    /// Assigns the tunnel address and, on Windows, the interface metric.
    [[nodiscard]] virtual Status configureAddress(const net::IpRange& address,
                                                  u32 metric) = 0;

    /// Applies the DNS servers pushed by the server (or configured locally) to
    /// this interface only.
    [[nodiscard]] virtual Status configureDns(const std::vector<net::IpAddress>& servers,
                                              const std::vector<std::string>& searchDomains) = 0;

    [[nodiscard]] virtual Status setMtu(u32 mtu) = 0;
};

/// The packet ring. read()/write() are lock-free against the driver but each is
/// single-consumer/single-producer: the tunnel runs exactly one reader thread
/// and one writer thread per adapter.
class IWintunSession {
public:
    virtual ~IWintunSession() = default;

    /// Blocks until a packet is available, the token is cancelled or `timeout`
    /// elapses. The returned view is valid until releasePacket().
    [[nodiscard]] virtual Result<PacketView> receive(Milliseconds timeout) = 0;
    virtual void releasePacket(PacketView packet) = 0;

    /// Allocates, fills and commits an outbound packet in one call.
    [[nodiscard]] virtual Status send(std::span<const u8> packet) = 0;

    /// Wakes a blocked receive() so the reader thread can exit.
    virtual void cancelPendingReads() = 0;
};

/// Driver-level operations that need the installer's privileges.
class IWintunDriver {
public:
    virtual ~IWintunDriver() = default;

    /// Loads and verifies wintun.dll. Must be called before anything else.
    [[nodiscard]] virtual Status load() = 0;

    /// Creates (or opens, when it already exists) an adapter with a stable GUID
    /// derived from `name`, so reboots and reinstalls reuse the same interface
    /// and the user's firewall rules keep applying.
    [[nodiscard]] virtual Result<std::shared_ptr<IWintunAdapter>> createAdapter(
        const std::string& name, const std::string& tunnelType) = 0;

    [[nodiscard]] virtual Status deleteAdapter(const std::string& name) = 0;

    /// Removes adapters left behind by a crashed run.
    [[nodiscard]] virtual Status removeOrphanedAdapters() = 0;

    [[nodiscard]] virtual Result<u32> driverVersion() const = 0;
};

using WintunDriverPtr = std::shared_ptr<IWintunDriver>;

} // namespace nova::driver
