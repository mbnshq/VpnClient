#include "WintunLibrary.h"

#include <NovaVPN/Core/Cancellation.h>
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Driver/WintunAdapter.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Networking/SockAddr.h>

#include <Windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <atomic>
#include <cstring>

#pragma comment(lib, "iphlpapi.lib")

using nova::logs::Channel;

namespace nova::driver {
namespace {

/// Derives a stable adapter GUID from the tunnel name, so reboots and
/// reinstalls reuse the same interface and the user's firewall rules keep
/// applying. The mapping is a deterministic hash of the name into the RFC 4122
/// layout - not a v4 random UUID, on purpose.
GUID stableGuidFromName(const std::string& name)
{
    // FNV-1a over the name, expanded to 16 bytes by hashing with two seeds.
    auto fnv = [](std::string_view text, u64 seed) {
        u64 hash = seed;
        for (const char c : text) {
            hash ^= static_cast<u8>(c);
            hash *= 0x00000100000001B3ull;
        }
        return hash;
    };
    const u64 hi = fnv(name, 0xcbf29ce484222325ull);
    const u64 lo = fnv(name, 0x9e3779b97f4a7c15ull);

    GUID guid{};
    std::memcpy(&guid, &hi, sizeof(hi));
    std::memcpy(reinterpret_cast<u8*>(&guid) + 8, &lo, sizeof(lo));
    // Stamp the version (5, name-based) and variant bits.
    reinterpret_cast<u8*>(&guid)[6] = static_cast<u8>((reinterpret_cast<u8*>(&guid)[6] & 0x0F) | 0x50);
    reinterpret_cast<u8*>(&guid)[8] = static_cast<u8>((reinterpret_cast<u8*>(&guid)[8] & 0x3F) | 0x80);
    return guid;
}

// -------------------------------------------------------------------------
// Session
// -------------------------------------------------------------------------
class WintunSession final : public IWintunSession {
public:
    WintunSession(const WintunApi* api, WINTUN_SESSION_HANDLE session)
        : m_api(api), m_session(session), m_readEvent(api->getReadWaitEvent(session))
    {
    }

    ~WintunSession() override
    {
        if (m_session != nullptr) {
            m_api->endSession(m_session);
        }
    }

    Result<PacketView> receive(Milliseconds timeout) override
    {
        // Wintun's receive is a spin-then-wait: pull packets while they are
        // ready, and only block on the read event when the ring drains.
        const SteadyTime deadline = SteadyClock::now() + timeout;
        while (true) {
            DWORD size = 0;
            BYTE* packet = m_api->receivePacket(m_session, &size);
            if (packet != nullptr) {
                return PacketView{packet, size};
            }

            const DWORD error = ::GetLastError();
            if (error != ERROR_NO_MORE_ITEMS) {
                return win::fromWin32(error, "WintunReceivePacket");
            }

            const auto remaining = std::chrono::duration_cast<Milliseconds>(
                deadline - SteadyClock::now());
            if (remaining.count() <= 0) {
                return err::timeout("no packet within the receive window");
            }

            const DWORD waitMs = static_cast<DWORD>(
                std::min<i64>(remaining.count(), 1000));
            if (::WaitForSingleObject(m_readEvent, waitMs) == WAIT_FAILED) {
                return win::lastError("WaitForSingleObject(wintun read event)");
            }
        }
    }

    void releasePacket(PacketView packet) override
    {
        if (!packet.empty()) {
            m_api->releaseReceivePacket(m_session, packet.data());
        }
    }

    Status send(std::span<const u8> packet) override
    {
        if (packet.empty() || packet.size() > WINTUN_MAX_IP_PACKET_SIZE) {
            return err::invalidArgument("outbound packet size out of range");
        }

        BYTE* buffer = m_api->allocateSendPacket(m_session, static_cast<DWORD>(packet.size()));
        if (buffer == nullptr) {
            const DWORD error = ::GetLastError();
            if (error == ERROR_BUFFER_OVERFLOW) {
                // The ring is full - the peer is not draining fast enough.
                // Drop rather than block the tunnel writer thread.
                return Status{ErrorCode::Unavailable, "wintun send ring is full"};
            }
            return win::fromWin32(error, "WintunAllocateSendPacket");
        }

        std::memcpy(buffer, packet.data(), packet.size());
        m_api->sendPacket(m_session, buffer);
        return Status::ok();
    }

    void cancelPendingReads() override
    {
        // Signalling the read event unblocks a receive() waiting on it, so the
        // reader thread can observe cancellation and exit.
        ::SetEvent(m_readEvent);
    }

private:
    const WintunApi*      m_api;
    WINTUN_SESSION_HANDLE m_session;
    HANDLE                m_readEvent;
};

// -------------------------------------------------------------------------
// Adapter
// -------------------------------------------------------------------------
class WintunAdapter final : public IWintunAdapter {
public:
    WintunAdapter(const WintunApi* api, WINTUN_ADAPTER_HANDLE adapter, AdapterInfo info)
        : m_api(api), m_adapter(adapter), m_info(std::move(info))
    {
    }

    ~WintunAdapter() override
    {
        if (m_adapter != nullptr) {
            m_api->closeAdapter(m_adapter);
        }
    }

    const AdapterInfo& info() const noexcept override { return m_info; }

    Result<std::shared_ptr<IWintunSession>> startSession(u32 ringCapacity) override
    {
        if (ringCapacity < WINTUN_MIN_RING_CAPACITY ||
            ringCapacity > WINTUN_MAX_RING_CAPACITY ||
            (ringCapacity & (ringCapacity - 1)) != 0) {
            return err::invalidArgument("ring capacity must be a power of two within Wintun's "
                                        "supported range");
        }

        WINTUN_SESSION_HANDLE session = m_api->startSession(m_adapter, ringCapacity);
        if (session == nullptr) {
            return win::lastError("WintunStartSession");
        }
        return std::shared_ptr<IWintunSession>{
            std::make_shared<WintunSession>(m_api, session)};
    }

    Status configureAddress(const net::IpRange& address, u32 metric) override
    {
        MIB_UNICASTIPADDRESS_ROW row{};
        ::InitializeUnicastIpAddressEntry(&row);
        row.InterfaceLuid          = luid();
        row.Address                = net::toSockAddr(address.network());
        row.OnLinkPrefixLength     = address.prefixLength();
        row.DadState               = IpDadStatePreferred;

        const NETIO_STATUS status = ::CreateUnicastIpAddressEntry(&row);
        if (status != NO_ERROR && status != ERROR_OBJECT_ALREADY_EXISTS) {
            return win::fromWin32(status, "CreateUnicastIpAddressEntry");
        }

        // Interface metric: a low value makes the tunnel preferred when a
        // default route is present on it.
        MIB_IPINTERFACE_ROW iface{};
        ::InitializeIpInterfaceEntry(&iface);
        iface.Family        = address.family() == AddressFamily::IPv4 ? AF_INET : AF_INET6;
        iface.InterfaceLuid = luid();
        if (::GetIpInterfaceEntry(&iface) == NO_ERROR) {
            iface.UseAutomaticMetric = FALSE;
            iface.Metric             = metric;
            if (address.family() == AddressFamily::IPv4) {
                iface.SitePrefixLength = 0; // required or SetIpInterfaceEntry rejects it
            }
            ::SetIpInterfaceEntry(&iface);
        }
        return Status::ok();
    }

    Status configureDns(const std::vector<net::IpAddress>& servers,
                        const std::vector<std::string>& searchDomains) override
    {
        // Program DNS on this interface only, via the documented netsh-free
        // path: SetInterfaceDnsSettings (Windows 10 2004+). Fall back is the
        // registry, but the modern API keeps it interface-scoped which is what
        // leak protection needs.
        std::wstring joinedServers;
        for (const auto& server : servers) {
            if (!joinedServers.empty()) {
                joinedServers.push_back(L',');
            }
            joinedServers.append(win::toWide(server.toString()));
        }

        std::wstring joinedDomains;
        for (const auto& domain : searchDomains) {
            if (!joinedDomains.empty()) {
                joinedDomains.push_back(L',');
            }
            joinedDomains.append(win::toWide(domain));
        }

        DNS_INTERFACE_SETTINGS settings{};
        settings.Version   = DNS_INTERFACE_SETTINGS_VERSION1;
        settings.Flags     = DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST;
        settings.NameServer = joinedServers.empty() ? nullptr : joinedServers.data();
        settings.SearchList = joinedDomains.empty() ? nullptr : joinedDomains.data();

        const NET_LUID interfaceLuid = luid();
        GUID interfaceGuid{};
        if (const NETIO_STATUS status =
                ::ConvertInterfaceLuidToGuid(&interfaceLuid, &interfaceGuid);
            status != NO_ERROR) {
            return win::fromWin32(status, "ConvertInterfaceLuidToGuid");
        }

        const DWORD result = ::SetInterfaceDnsSettings(interfaceGuid, &settings);
        if (result != NO_ERROR) {
            return win::fromWin32(result, "SetInterfaceDnsSettings");
        }
        return Status::ok();
    }

    Status setMtu(u32 mtu) override
    {
        for (const ADDRESS_FAMILY family :
             {static_cast<ADDRESS_FAMILY>(AF_INET), static_cast<ADDRESS_FAMILY>(AF_INET6)}) {
            MIB_IPINTERFACE_ROW iface{};
            ::InitializeIpInterfaceEntry(&iface);
            iface.Family        = family;
            iface.InterfaceLuid = luid();
            if (::GetIpInterfaceEntry(&iface) != NO_ERROR) {
                continue;
            }
            iface.NlMtu = mtu;
            if (family == AF_INET) {
                iface.SitePrefixLength = 0;
            }
            ::SetIpInterfaceEntry(&iface);
        }
        return Status::ok();
    }

private:
    NET_LUID luid() const noexcept
    {
        NET_LUID value{};
        value.Value = m_info.luid;
        return value;
    }

    const WintunApi*      m_api;
    WINTUN_ADAPTER_HANDLE m_adapter;
    AdapterInfo           m_info;
};

// -------------------------------------------------------------------------
// Driver
// -------------------------------------------------------------------------
class WintunDriver final : public IWintunDriver {
public:
    Status load() override
    {
        auto api = loadWintun();
        if (api.isError()) {
            return api.status();
        }
        m_api = api.value();
        return Status::ok();
    }

    Result<std::shared_ptr<IWintunAdapter>> createAdapter(const std::string& name,
                                                          const std::string& tunnelType) override
    {
        if (m_api == nullptr) {
            return err::invalidState("wintun driver not loaded");
        }

        const std::wstring wideName = win::toWide(name);
        const std::wstring wideType = win::toWide(tunnelType.empty() ? "NovaVPN" : tunnelType);
        const GUID guid = stableGuidFromName(name);

        WINTUN_ADAPTER_HANDLE handle =
            m_api->createAdapter(wideName.c_str(), wideType.c_str(), &guid);
        if (handle == nullptr) {
            // Fall back to opening an existing adapter of the same name - a
            // previous run may have left one, and reusing it preserves rules.
            handle = m_api->openAdapter(wideName.c_str());
            if (handle == nullptr) {
                return win::lastError("WintunCreateAdapter(" + name + ")");
            }
        }

        AdapterInfo info;
        info.name       = name;
        info.tunnelType = tunnelType;

        NET_LUID luid{};
        m_api->getAdapterLuid(handle, &luid);
        info.luid = luid.Value;

        NET_IFINDEX ifIndex = 0;
        if (::ConvertInterfaceLuidToIndex(&luid, &ifIndex) == NO_ERROR) {
            info.interfaceIndex = ifIndex;
        }
        info.driverVersion = m_api->getRunningDriverVersion();

        NOVA_LOG_INFO(Channel::Driver, "adapter ready")
            .field("name", name)
            .field("interface", info.interfaceIndex)
            .field("luid", info.luid);

        return std::shared_ptr<IWintunAdapter>{
            std::make_shared<WintunAdapter>(m_api, handle, std::move(info))};
    }

    Status deleteAdapter(const std::string& name) override
    {
        if (m_api == nullptr) {
            return err::invalidState("wintun driver not loaded");
        }
        WINTUN_ADAPTER_HANDLE handle = m_api->openAdapter(win::toWide(name).c_str());
        if (handle == nullptr) {
            return Status::ok(); // already gone
        }
        m_api->closeAdapter(handle); // closing a created adapter removes it
        return Status::ok();
    }

    Status removeOrphanedAdapters() override
    {
        // Wintun removes a created adapter when its handle closes, so a cleanly
        // exited run leaves nothing. A crashed run's adapter is reclaimed by
        // reopening it (createAdapter's fallback) rather than enumerated here.
        return Status::ok();
    }

    Result<u32> driverVersion() const override
    {
        if (m_api == nullptr) {
            return err::invalidState("wintun driver not loaded");
        }
        const DWORD version = m_api->getRunningDriverVersion();
        if (version == 0) {
            return win::lastError("WintunGetRunningDriverVersion");
        }
        return static_cast<u32>(version);
    }

private:
    const WintunApi* m_api = nullptr;
};

} // namespace

WintunDriverPtr makeWintunDriver()
{
    return std::make_shared<WintunDriver>();
}

} // namespace nova::driver
