#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Firewall/FirewallEngine.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Networking/SockAddr.h>

#include <Windows.h>
#include <fwpmu.h>
#include <rpc.h>

#include <mutex>
#include <vector>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")

using nova::logs::Channel;

namespace nova::firewall {
namespace {

// Fixed provider and sublayer GUIDs. Every filter NovaVPN adds is tagged with
// the provider, so the whole policy can be enumerated and removed in one sweep
// and a crashed run leaves a state the next start reconciles.
// {6E2A1F30-4B77-4E9C-9E21-6B0E0A9D31A1}
constexpr GUID kProviderGuid = {
    0x6e2a1f30, 0x4b77, 0x4e9c, {0x9e, 0x21, 0x6b, 0x0e, 0x0a, 0x9d, 0x31, 0xa1}};
// {6E2A1F31-4B77-4E9C-9E21-6B0E0A9D31A1}
constexpr GUID kSublayerGuid = {
    0x6e2a1f31, 0x4b77, 0x4e9c, {0x9e, 0x21, 0x6b, 0x0e, 0x0a, 0x9d, 0x31, 0xa1}};

/// Filter weights. Higher wins within the sublayer. The block-all filter sits
/// low; permits sit above it so they punch through.
enum Weight : u8 {
    kWeightBlockAll   = 1,
    kWeightPermitLoopback = 8,
    kWeightPermitDhcp = 9,
    kWeightPermitLan  = 10,
    kWeightPermitTunnel = 12,
    kWeightPermitEndpoint = 14,
    kWeightBlockDnsLeak = 13,
};

std::wstring providerName() { return L"NovaVPN"; }

/// RAII for a WFP engine handle.
struct EngineHandle {
    HANDLE handle = nullptr;
    ~EngineHandle()
    {
        if (handle != nullptr) {
            ::FwpmEngineClose0(handle);
        }
    }
};

Status wfpError(DWORD code, std::string_view context)
{
    return Status{code == FWP_E_ALREADY_EXISTS ? ErrorCode::AlreadyExists
                                                : ErrorCode::FirewallApplyFailed,
                  std::string{context} + " failed",
                  static_cast<u32>(code)};
}

class WfpEngine final : public IFirewallEngine {
public:
    ~WfpEngine() override { close(); }

    Status open() override
    {
        std::lock_guard lock{m_mutex};
        if (m_engine != nullptr) {
            return Status::ok();
        }

        FWPM_SESSION0 session{};
        session.displayData.name        = const_cast<wchar_t*>(L"NovaVPN");
        session.displayData.description = const_cast<wchar_t*>(L"NovaVPN firewall session");
        // Dynamic sessions auto-remove their non-persistent objects when the
        // engine handle closes, which is exactly the soft kill-switch lifetime.
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

        HANDLE engine = nullptr;
        const DWORD result = ::FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session,
                                               &engine);
        if (result != ERROR_SUCCESS) {
            return wfpError(result, "FwpmEngineOpen");
        }
        m_engine  = engine;
        m_dynamic = true;

        if (const Status status = ensureProviderAndSublayer(); status.isError()) {
            ::FwpmEngineClose0(m_engine);
            m_engine = nullptr;
            return status;
        }

        NOVA_LOG_INFO(Channel::Firewall, "WFP engine opened");
        return Status::ok();
    }

    void close() override
    {
        std::lock_guard lock{m_mutex};
        if (m_engine != nullptr) {
            ::FwpmEngineClose0(m_engine);
            m_engine = nullptr;
        }
    }

    Status apply(const FirewallPolicy& policy) override
    {
        std::lock_guard lock{m_mutex};
        if (m_engine == nullptr) {
            return err::invalidState("firewall engine not open");
        }

        if (policy.mode == KillSwitchMode::Off) {
            NOVA_RETURN_IF_ERROR(clearFiltersLocked());
            m_engaged = false;
            m_policy.reset();
            return Status::ok();
        }

        // Everything goes into one transaction: either the whole policy lands
        // or none of it does, so there is never a half-applied leak.
        NOVA_RETURN_IF_ERROR(beginTransaction());
        Status status = applyPolicyLocked(policy);
        if (status.isError()) {
            ::FwpmTransactionAbort0(m_engine);
            return status;
        }
        const DWORD commit = ::FwpmTransactionCommit0(m_engine);
        if (commit != ERROR_SUCCESS) {
            return wfpError(commit, "FwpmTransactionCommit");
        }

        m_engaged = true;
        m_policy  = policy;
        NOVA_LOG_INFO(Channel::Firewall, "firewall policy applied")
            .field("mode", std::string{toString(policy.mode)})
            .field("interfaces", static_cast<u64>(policy.permittedInterfaceLuids.size()))
            .field("endpoints", static_cast<u64>(policy.vpnEndpoints.size()));
        return Status::ok();
    }

    Status clear() override
    {
        std::lock_guard lock{m_mutex};
        if (m_engine == nullptr) {
            return err::invalidState("firewall engine not open");
        }
        NOVA_RETURN_IF_ERROR(clearFiltersLocked());
        m_engaged = false;
        m_policy.reset();
        return Status::ok();
    }

    Status reconcile() override
    {
        std::lock_guard lock{m_mutex};
        if (m_engine == nullptr) {
            return err::invalidState("firewall engine not open");
        }
        // Remove any filters a previous run left under our provider. With a
        // dynamic session this is mostly redundant, but a hard (persistent)
        // policy from a crashed run must be swept here.
        return clearFiltersLocked();
    }

    Result<std::vector<FilterInfo>> activeFilters() const override
    {
        std::lock_guard lock{m_mutex};
        if (m_engine == nullptr) {
            return err::invalidState("firewall engine not open");
        }

        HANDLE enumHandle = nullptr;
        DWORD result = ::FwpmFilterCreateEnumHandle0(m_engine, nullptr, &enumHandle);
        if (result != ERROR_SUCCESS) {
            return wfpError(result, "FwpmFilterCreateEnumHandle");
        }

        std::vector<FilterInfo> filters;
        FWPM_FILTER0** entries = nullptr;
        UINT32 count = 0;
        result = ::FwpmFilterEnum0(m_engine, enumHandle, 256, &entries, &count);
        if (result == ERROR_SUCCESS && entries != nullptr) {
            for (UINT32 i = 0; i < count; ++i) {
                if (entries[i]->providerKey == nullptr ||
                    !IsEqualGUID(*entries[i]->providerKey, kProviderGuid)) {
                    continue;
                }
                FilterInfo info;
                info.id     = entries[i]->filterId;
                info.weight = entries[i]->weight.type == FWP_UINT8
                                  ? entries[i]->weight.uint8
                                  : 0;
                info.persistent = (entries[i]->flags & FWPM_FILTER_FLAG_PERSISTENT) != 0;
                if (entries[i]->displayData.name != nullptr) {
                    info.name = win::toUtf8(entries[i]->displayData.name);
                }
                filters.push_back(std::move(info));
            }
            ::FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
        }
        ::FwpmFilterDestroyEnumHandle0(m_engine, enumHandle);
        return filters;
    }

    bool isEngaged() const override
    {
        std::lock_guard lock{m_mutex};
        return m_engaged;
    }

    std::optional<FirewallPolicy> currentPolicy() const override
    {
        std::lock_guard lock{m_mutex};
        return m_policy;
    }

private:
    Status ensureProviderAndSublayer()
    {
        FWPM_PROVIDER0 provider{};
        provider.providerKey         = kProviderGuid;
        provider.displayData.name    = const_cast<wchar_t*>(L"NovaVPN");
        provider.displayData.description = const_cast<wchar_t*>(L"NovaVPN VPN client");
        DWORD result = ::FwpmProviderAdd0(m_engine, &provider, nullptr);
        if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
            return wfpError(result, "FwpmProviderAdd");
        }

        FWPM_SUBLAYER0 sublayer{};
        sublayer.subLayerKey      = kSublayerGuid;
        sublayer.displayData.name = const_cast<wchar_t*>(L"NovaVPN");
        sublayer.providerKey      = const_cast<GUID*>(&kProviderGuid);
        sublayer.weight           = 0x8000; // above the default sublayer
        result = ::FwpmSubLayerAdd0(m_engine, &sublayer, nullptr);
        if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
            return wfpError(result, "FwpmSubLayerAdd");
        }
        return Status::ok();
    }

    Status beginTransaction()
    {
        const DWORD result = ::FwpmTransactionBegin0(m_engine, 0);
        if (result != ERROR_SUCCESS) {
            return wfpError(result, "FwpmTransactionBegin");
        }
        return Status::ok();
    }

    /// Caller holds m_mutex and an open transaction.
    Status applyPolicyLocked(const FirewallPolicy& policy)
    {
        NOVA_RETURN_IF_ERROR(clearFiltersInTransaction());

        // Block-all, at both IPv4 and IPv6 connect layers. This is the floor
        // the kill switch stands on.
        for (const GUID& layer : {FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                  FWPM_LAYER_ALE_AUTH_CONNECT_V6}) {
            NOVA_RETURN_IF_ERROR(addSimpleFilter(layer, FWP_ACTION_BLOCK, kWeightBlockAll,
                                                 L"NovaVPN block-all", policy.persistent));
        }

        // Permit traffic on the tunnel adapters - the whole point is that
        // tunnelled traffic still flows.
        for (const u64 luid : policy.permittedInterfaceLuids) {
            for (const GUID& layer : {FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                      FWPM_LAYER_ALE_AUTH_CONNECT_V6}) {
                NOVA_RETURN_IF_ERROR(addInterfaceFilter(layer, luid, kWeightPermitTunnel,
                                                        policy.persistent));
            }
        }

        // Permit the VPN server endpoints over the underlay, or the tunnel
        // could never (re)establish under a hard kill switch.
        for (const auto& endpoint : policy.vpnEndpoints) {
            NOVA_RETURN_IF_ERROR(addEndpointFilter(endpoint, kWeightPermitEndpoint,
                                                   policy.persistent));
        }

        // Exceptions, each a deliberate hole.
        if (policy.exceptions.allowLoopback) {
            NOVA_RETURN_IF_ERROR(addLoopbackFilters(policy.persistent));
        }
        if (policy.exceptions.allowDhcp) {
            NOVA_RETURN_IF_ERROR(addDhcpFilters(policy.persistent));
        }
        for (const auto& range : policy.exceptions.allowedDestinations) {
            NOVA_RETURN_IF_ERROR(addRangeFilter(range, kWeightPermitLan, policy.persistent));
        }
        return Status::ok();
    }

    Status clearFiltersLocked()
    {
        NOVA_RETURN_IF_ERROR(beginTransaction());
        Status status = clearFiltersInTransaction();
        if (status.isError()) {
            ::FwpmTransactionAbort0(m_engine);
            return status;
        }
        const DWORD commit = ::FwpmTransactionCommit0(m_engine);
        if (commit != ERROR_SUCCESS) {
            return wfpError(commit, "FwpmTransactionCommit(clear)");
        }
        return Status::ok();
    }

    /// Caller holds an open transaction. Deletes every filter under our provider.
    Status clearFiltersInTransaction()
    {
        HANDLE enumHandle = nullptr;
        DWORD result = ::FwpmFilterCreateEnumHandle0(m_engine, nullptr, &enumHandle);
        if (result != ERROR_SUCCESS) {
            return wfpError(result, "FwpmFilterCreateEnumHandle");
        }

        std::vector<UINT64> toDelete;
        FWPM_FILTER0** entries = nullptr;
        UINT32 count = 0;
        result = ::FwpmFilterEnum0(m_engine, enumHandle, 512, &entries, &count);
        if (result == ERROR_SUCCESS && entries != nullptr) {
            for (UINT32 i = 0; i < count; ++i) {
                if (entries[i]->providerKey != nullptr &&
                    IsEqualGUID(*entries[i]->providerKey, kProviderGuid)) {
                    toDelete.push_back(entries[i]->filterId);
                }
            }
            ::FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
        }
        ::FwpmFilterDestroyEnumHandle0(m_engine, enumHandle);

        for (const UINT64 id : toDelete) {
            ::FwpmFilterDeleteById0(m_engine, id);
        }
        return Status::ok();
    }

    // --- filter builders ---------------------------------------------------

    static void stampCommon(FWPM_FILTER0& filter, const GUID& layer, u8 weight, bool persistent,
                            const wchar_t* name)
    {
        filter.layerKey            = layer;
        filter.subLayerKey         = kSublayerGuid;
        filter.providerKey         = const_cast<GUID*>(&kProviderGuid);
        filter.displayData.name    = const_cast<wchar_t*>(name);
        filter.weight.type         = FWP_UINT8;
        filter.weight.uint8        = weight;
        if (persistent) {
            filter.flags |= FWPM_FILTER_FLAG_PERSISTENT;
        }
    }

    Status addFilter(FWPM_FILTER0& filter, std::string_view context)
    {
        UINT64 id = 0;
        const DWORD result = ::FwpmFilterAdd0(m_engine, &filter, nullptr, &id);
        if (result != ERROR_SUCCESS) {
            return wfpError(result, context);
        }
        return Status::ok();
    }

    Status addSimpleFilter(const GUID& layer, FWP_ACTION_TYPE action, u8 weight,
                           const wchar_t* name, bool persistent)
    {
        FWPM_FILTER0 filter{};
        stampCommon(filter, layer, weight, persistent, name);
        filter.action.type = action;
        return addFilter(filter, "FwpmFilterAdd(block-all)");
    }

    Status addInterfaceFilter(const GUID& layer, u64 luid, u8 weight, bool persistent)
    {
        FWPM_FILTER_CONDITION0 condition{};
        condition.fieldKey           = FWPM_CONDITION_IP_LOCAL_INTERFACE;
        condition.matchType          = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT64;
        UINT64 luidValue             = luid;
        condition.conditionValue.uint64 = &luidValue;

        FWPM_FILTER0 filter{};
        stampCommon(filter, layer, weight, persistent, L"NovaVPN permit tunnel interface");
        filter.action.type      = FWP_ACTION_PERMIT;
        filter.numFilterConditions = 1;
        filter.filterCondition   = &condition;
        return addFilter(filter, "FwpmFilterAdd(permit interface)");
    }

    Status addEndpointFilter(const net::Endpoint& endpoint, u8 weight, bool persistent)
    {
        const bool v4 = endpoint.address().isV4();
        const GUID layer = v4 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6;

        std::vector<FWPM_FILTER_CONDITION0> conditions;

        // Remote address == endpoint.
        FWPM_FILTER_CONDITION0 addrCond{};
        addrCond.fieldKey  = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        addrCond.matchType = FWP_MATCH_EQUAL;
        FWP_BYTE_ARRAY16 v6Bytes{};
        UINT32 v4Address = 0;
        if (v4) {
            const auto bytes = endpoint.address().bytes();
            v4Address = (static_cast<u32>(bytes[0]) << 24) | (static_cast<u32>(bytes[1]) << 16) |
                        (static_cast<u32>(bytes[2]) << 8) | static_cast<u32>(bytes[3]);
            addrCond.conditionValue.type   = FWP_UINT32;
            addrCond.conditionValue.uint32 = v4Address;
        } else {
            const auto bytes = endpoint.address().bytes();
            std::memcpy(v6Bytes.byteArray16, bytes.data(), 16);
            addrCond.conditionValue.type        = FWP_BYTE_ARRAY16_TYPE;
            addrCond.conditionValue.byteArray16 = &v6Bytes;
        }
        conditions.push_back(addrCond);

        FWPM_FILTER0 filter{};
        stampCommon(filter, layer, weight, persistent, L"NovaVPN permit VPN endpoint");
        filter.action.type         = FWP_ACTION_PERMIT;
        filter.numFilterConditions = static_cast<UINT32>(conditions.size());
        filter.filterCondition     = conditions.data();
        return addFilter(filter, "FwpmFilterAdd(permit endpoint)");
    }

    Status addRangeFilter(const net::IpRange& range, u8 weight, bool persistent)
    {
        const bool v4 = range.family() == AddressFamily::IPv4;
        const GUID layer = v4 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6;

        FWP_V4_ADDR_AND_MASK v4Mask{};
        FWP_V6_ADDR_AND_MASK v6Mask{};
        FWPM_FILTER_CONDITION0 condition{};
        condition.fieldKey  = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.matchType = FWP_MATCH_EQUAL;

        if (v4) {
            const auto net = range.network().bytes();
            v4Mask.addr = (static_cast<u32>(net[0]) << 24) | (static_cast<u32>(net[1]) << 16) |
                          (static_cast<u32>(net[2]) << 8) | static_cast<u32>(net[3]);
            v4Mask.mask = range.prefixLength() == 0
                              ? 0
                              : (0xFFFFFFFFu << (32 - range.prefixLength()));
            condition.conditionValue.type = FWP_V4_ADDR_MASK;
            condition.conditionValue.v4AddrMask = &v4Mask;
        } else {
            const auto net = range.network().bytes();
            std::memcpy(v6Mask.addr, net.data(), 16);
            v6Mask.prefixLength = range.prefixLength();
            condition.conditionValue.type = FWP_V6_ADDR_MASK;
            condition.conditionValue.v6AddrMask = &v6Mask;
        }

        FWPM_FILTER0 filter{};
        stampCommon(filter, layer, weight, persistent, L"NovaVPN permit destination");
        filter.action.type         = FWP_ACTION_PERMIT;
        filter.numFilterConditions = 1;
        filter.filterCondition     = &condition;
        return addFilter(filter, "FwpmFilterAdd(permit range)");
    }

    Status addLoopbackFilters(bool persistent)
    {
        // 127.0.0.0/8 and ::1/128.
        NOVA_RETURN_IF_ERROR(
            addRangeFilter(net::IpRange::parse("127.0.0.0/8").value(), kWeightPermitLoopback,
                           persistent));
        NOVA_RETURN_IF_ERROR(
            addRangeFilter(net::IpRange::parse("::1/128").value(), kWeightPermitLoopback,
                           persistent));
        return Status::ok();
    }

    Status addDhcpFilters(bool persistent)
    {
        // DHCP is UDP 67/68; permitting the broadcast/limited ranges keeps the
        // lease alive. Approximated here by permitting the link-local and
        // broadcast destinations at the connect layer.
        NOVA_RETURN_IF_ERROR(
            addRangeFilter(net::IpRange::parse("255.255.255.255/32").value(), kWeightPermitDhcp,
                           persistent));
        NOVA_RETURN_IF_ERROR(
            addRangeFilter(net::IpRange::parse("169.254.0.0/16").value(), kWeightPermitDhcp,
                           persistent));
        return Status::ok();
    }

    mutable std::mutex             m_mutex;
    HANDLE                         m_engine = nullptr;
    bool                           m_dynamic = false;
    bool                           m_engaged = false;
    std::optional<FirewallPolicy>  m_policy;
};

} // namespace

FirewallEnginePtr makeFirewallEngine()
{
    return std::make_shared<WfpEngine>();
}

} // namespace nova::firewall
