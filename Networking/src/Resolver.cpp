#include <NovaVPN/Core/Handle.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Networking/NetworkMonitor.h>
#include <NovaVPN/Networking/Resolver.h>
#include <NovaVPN/Networking/SockAddr.h>

#include <winsock2.h>
#include <windns.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <unordered_map>

#pragma comment(lib, "dnsapi.lib")

using nova::logs::Channel;

namespace nova::net {
namespace {

struct EventHandleTraits {
    using value_type = HANDLE;
    static value_type invalid() noexcept { return nullptr; }
    static void close(value_type handle) noexcept { ::CloseHandle(handle); }
};
using EventHandle = win::UniqueResource<EventHandleTraits>;

/// TTL applied to literal addresses and other answers that never expire in
/// practice. One day keeps the cache bounded without ever mattering.
constexpr Seconds kLiteralTtl{86400};

/// Completion context for one DnsQueryEx call. Heap-allocated and owned by the
/// waiting thread; the DNS callback only signals the event, so the object must
/// stay alive until the callback has fired - which the waiter guarantees by
/// always waiting for the event, even after a cancel.
struct QueryContext {
    EventHandle       done;
    DNS_QUERY_RESULT  result{};
    std::atomic<bool> completed{false};
};

VOID WINAPI queryCompletion(PVOID context, PDNS_QUERY_RESULT results)
{
    auto* query = static_cast<QueryContext*>(context);
    if (results != nullptr) {
        query->result = *results;
    }
    query->completed.store(true, std::memory_order_release);
    ::SetEvent(query->done.get());
}

/// Builds the DNS_ADDR_ARRAY blob for pinning specific servers. The array is
/// variable-length; the returned buffer owns the storage.
std::vector<u8> buildServerList(const std::vector<IpAddress>& servers)
{
    if (servers.empty()) {
        return {};
    }

    const std::size_t bytes =
        FIELD_OFFSET(DNS_ADDR_ARRAY, AddrArray) + servers.size() * sizeof(DNS_ADDR);
    std::vector<u8> blob(bytes, 0);

    auto* array = reinterpret_cast<DNS_ADDR_ARRAY*>(blob.data());
    array->MaxCount  = static_cast<DWORD>(servers.size());
    array->AddrCount = static_cast<DWORD>(servers.size());

    for (std::size_t i = 0; i < servers.size(); ++i) {
        const SOCKADDR_INET address = toSockAddr(servers[i], 53);
        static_assert(sizeof(SOCKADDR_INET) <= DNS_ADDR_MAX_SOCKADDR_LENGTH);
        std::memcpy(array->AddrArray[i].MaxSa, &address, sizeof(address));
    }
    return blob;
}

/// Extracts addresses of the requested record type; returns the smallest TTL
/// seen so the cache never outlives any record in the answer.
void collectRecords(const DNS_RECORDW* records, WORD type, std::vector<IpAddress>& out,
                    u32& minTtl)
{
    for (const auto* record = records; record != nullptr; record = record->pNext) {
        if (record->wType != type) {
            continue;
        }
        if (type == DNS_TYPE_A) {
            std::array<u8, 4> bytes{};
            std::memcpy(bytes.data(), &record->Data.A.IpAddress, 4);
            out.push_back(IpAddress::fromV4(bytes));
        } else if (type == DNS_TYPE_AAAA) {
            std::array<u8, 16> bytes{};
            std::memcpy(bytes.data(), &record->Data.AAAA.Ip6Address, 16);
            out.push_back(IpAddress::fromV6(bytes));
        }
        minTtl = std::min(minTtl, static_cast<u32>(record->dwTtl));
    }
}

ErrorCode classifyDnsStatus(DNS_STATUS status) noexcept
{
    switch (status) {
    case DNS_ERROR_RCODE_NAME_ERROR: // NXDOMAIN
    case DNS_INFO_NO_RECORDS:
        return ErrorCode::NotFound;
    case ERROR_TIMEOUT:
    case DNS_ERROR_RCODE_SERVER_FAILURE:
        return ErrorCode::DnsFailure;
    case ERROR_CANCELLED:
        return ErrorCode::Cancelled;
    default:
        return ErrorCode::DnsFailure;
    }
}

class WindowsResolver final : public IResolver {
public:
    explicit WindowsResolver(std::shared_ptr<INetworkMonitor> monitor)
        : m_monitor(std::move(monitor))
    {
    }

    Result<ResolvedHost> resolve(const std::string& host, const ResolveOptions& options,
                                 const CancellationToken& token) override
    {
        const SteadyTime started = SteadyClock::now();

        ResolvedHost resolved;
        resolved.host = host;

        // Literal fast path: "8.8.8.8" or "2001:db8::1" as a remote needs no
        // query, no cache and no scope decision.
        if (IpAddress literal; IpAddress::tryParse(host, literal)) {
            if (options.family.has_value() && literal.family() != *options.family) {
                return err::invalidArgument("literal address " + host +
                                            " does not match the requested family");
            }
            resolved.addresses.push_back(literal);
            resolved.ttl          = kLiteralTtl;
            resolved.resolverUsed = "literal";
            resolved.elapsed      = elapsedSince(started);
            return resolved;
        }

        if (!isValidHostName(host)) {
            return err::invalidArgument("not a resolvable host name: " + host);
        }

        // Cache lookup. The key includes scope and family because the correct
        // answer differs per path - that is the whole point of scoping.
        const std::string cacheKey = makeCacheKey(host, options);
        if (!options.noCache) {
            if (auto hit = cacheLookup(cacheKey); hit.has_value()) {
                hit->elapsed = elapsedSince(started);
                return *hit;
            }
        }

        NOVA_ASSIGN_OR_RETURN(const ScopeBinding binding, bindingFor(options.scope));

        std::vector<IpAddress> addresses;
        u32 minTtl = 0xFFFFFFFF;

        const bool wantV4 = !options.family.has_value() || *options.family == AddressFamily::IPv4;
        const bool wantV6 = !options.family.has_value() || *options.family == AddressFamily::IPv6;

        Status lastError = Status::ok();
        if (wantV4) {
            const Status status =
                queryOne(host, DNS_TYPE_A, binding, options, token, addresses, minTtl);
            if (status.isError()) {
                lastError = status;
            }
        }
        if (wantV6) {
            const Status status =
                queryOne(host, DNS_TYPE_AAAA, binding, options, token, addresses, minTtl);
            if (status.isError()) {
                lastError = status;
            }
        }

        if (addresses.empty()) {
            if (lastError.isOk()) {
                lastError = Status{ErrorCode::NotFound, "no address records for " + host};
            }
            return lastError.withContext("resolving " + host);
        }

        resolved.addresses    = std::move(addresses);
        resolved.ttl          = Seconds{minTtl == 0xFFFFFFFF ? 0 : minTtl};
        resolved.resolverUsed = describeBinding(options.scope, binding);
        resolved.elapsed      = elapsedSince(started);

        if (!options.noCache && resolved.ttl.count() > 0) {
            cacheStore(cacheKey, resolved);
        }

        NOVA_LOG_DEBUG(Channel::Dns, "resolved")
            .field("host", host)
            .field("addresses", static_cast<u64>(resolved.addresses.size()))
            .field("ttl", static_cast<u64>(resolved.ttl.count()))
            .field("via", resolved.resolverUsed);
        return resolved;
    }

    void setTunnelBinding(std::optional<ScopeBinding> binding) override
    {
        {
            std::lock_guard lock{m_mutex};
            m_tunnelBinding = std::move(binding);
        }
        // The right answer for every cached name just changed with the path.
        flushCache();
    }

    void flushCache() override
    {
        std::lock_guard lock{m_mutex};
        m_cache.clear();
    }

    Status flushSystemCache() override
    {
        // DnsFlushResolverCache is exported by dnsapi.dll but not declared in
        // the SDK headers; resolve it dynamically from the system copy.
        using FlushFn = BOOL(WINAPI*)();

        const HMODULE dnsapi = ::GetModuleHandleW(L"dnsapi.dll");
        if (dnsapi == nullptr) {
            return win::lastError("GetModuleHandle(dnsapi.dll)");
        }
        const auto flush =
            reinterpret_cast<FlushFn>(::GetProcAddress(dnsapi, "DnsFlushResolverCache"));
        if (flush == nullptr) {
            return err::notImplemented("DnsFlushResolverCache is unavailable on this system");
        }
        if (flush() == FALSE) {
            return Status{ErrorCode::DnsFailure, "DnsFlushResolverCache reported failure"};
        }
        return Status::ok();
    }

private:
    struct CacheEntry {
        ResolvedHost resolved;
        SteadyTime   expires;
    };

    static Milliseconds elapsedSince(SteadyTime started)
    {
        return std::chrono::duration_cast<Milliseconds>(SteadyClock::now() - started);
    }

    static std::string makeCacheKey(const std::string& host, const ResolveOptions& options)
    {
        std::string key = str::toLower(host);
        key.push_back('|');
        key.append(std::to_string(static_cast<int>(options.scope)));
        key.push_back('|');
        key.append(options.family.has_value()
                       ? std::string{nova::toString(*options.family)}
                       : std::string{"any"});
        return key;
    }

    Result<ScopeBinding> bindingFor(ResolutionScope scope)
    {
        switch (scope) {
        case ResolutionScope::System:
            return ScopeBinding{};

        case ResolutionScope::Tunnel: {
            std::lock_guard lock{m_mutex};
            if (!m_tunnelBinding.has_value()) {
                return err::invalidState(
                    "tunnel-scoped resolution requested but no tunnel is bound");
            }
            return *m_tunnelBinding;
        }

        case ResolutionScope::Underlay: {
            if (!m_monitor) {
                NOVA_LOG_WARN(Channel::Dns,
                              "underlay scope requested without a network monitor; "
                              "falling back to system resolution");
                return ScopeBinding{};
            }
            NOVA_ASSIGN_OR_RETURN(auto underlay,
                                  m_monitor->underlayAdapter(AddressFamily::IPv4));
            ScopeBinding binding;
            binding.interfaceIndex = underlay.interfaceIndex;
            binding.servers        = underlay.dnsServers;
            return binding;
        }
        }
        return err::invalidArgument("unknown resolution scope");
    }

    static std::string describeBinding(ResolutionScope scope, const ScopeBinding& binding)
    {
        std::string out;
        switch (scope) {
        case ResolutionScope::System:   out = "system"; break;
        case ResolutionScope::Tunnel:   out = "tunnel"; break;
        case ResolutionScope::Underlay: out = "underlay"; break;
        }
        if (binding.interfaceIndex != 0) {
            out += " if=" + std::to_string(binding.interfaceIndex);
        }
        if (!binding.servers.empty()) {
            out += " via " + binding.servers.front().toString();
            if (binding.servers.size() > 1) {
                out += "+" + std::to_string(binding.servers.size() - 1);
            }
        }
        return out;
    }

    std::optional<ResolvedHost> cacheLookup(const std::string& key)
    {
        std::lock_guard lock{m_mutex};
        const auto it = m_cache.find(key);
        if (it == m_cache.end()) {
            return std::nullopt;
        }
        if (SteadyClock::now() >= it->second.expires) {
            m_cache.erase(it);
            return std::nullopt;
        }
        ResolvedHost hit = it->second.resolved;
        hit.resolverUsed += " (cached)";
        return hit;
    }

    void cacheStore(const std::string& key, const ResolvedHost& resolved)
    {
        std::lock_guard lock{m_mutex};
        // Bound the cache; evicting everything on overflow is crude but the
        // working set (a handful of gateways and rule domains) never nears it.
        if (m_cache.size() >= 4096) {
            m_cache.clear();
        }
        m_cache[key] = CacheEntry{resolved, SteadyClock::now() + resolved.ttl};
    }

    /// One DnsQueryEx call for one record type, cancellable and time-bounded.
    Status queryOne(const std::string& host, WORD type, const ScopeBinding& binding,
                    const ResolveOptions& options, const CancellationToken& token,
                    std::vector<IpAddress>& out, u32& minTtl)
    {
        if (token.isCancelled()) {
            return err::cancelled("resolution cancelled");
        }

        auto context = std::make_unique<QueryContext>();
        context->done.reset(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!context->done) {
            return win::lastError("CreateEvent(dns)");
        }

        const std::wstring wideHost = win::toWide(host);
        std::vector<u8> serverBlob  = buildServerList(binding.servers);

        DNS_QUERY_REQUEST request{};
        request.Version                 = DNS_QUERY_REQUEST_VERSION1;
        request.QueryName               = wideHost.c_str();
        request.QueryType               = type;
        request.QueryOptions            = options.noCache ? DNS_QUERY_BYPASS_CACHE : 0;
        request.InterfaceIndex          = binding.interfaceIndex;
        request.pDnsServerList =
            serverBlob.empty() ? nullptr : reinterpret_cast<DNS_ADDR_ARRAY*>(serverBlob.data());
        request.pQueryCompletionCallback = &queryCompletion;
        request.pQueryContext            = context.get();

        DNS_QUERY_CANCEL cancelHandle{};
        DNS_QUERY_RESULT syncResult{};
        syncResult.Version = DNS_QUERY_REQUEST_VERSION1;

        const DNS_STATUS started = ::DnsQueryEx(&request, &syncResult, &cancelHandle);

        if (started != DNS_REQUEST_PENDING) {
            // Completed synchronously (cache hit or immediate failure); the
            // callback will not fire.
            if (started != ERROR_SUCCESS) {
                return Status{classifyDnsStatus(started),
                              "DnsQueryEx(" + host + ") failed",
                              static_cast<u32>(started)};
            }
            collectRecords(syncResult.pQueryRecords, type, out, minTtl);
            if (syncResult.pQueryRecords != nullptr) {
                ::DnsRecordListFree(syncResult.pQueryRecords, DnsFreeRecordList);
            }
            return Status::ok();
        }

        // Asynchronous path. Whatever happens next - timeout, cancellation or
        // completion - the callback WILL fire exactly once (cancel guarantees
        // it), so waiting on the event is always safe and always required.
        auto registration = token.onCancelled([&cancelHandle] {
            ::DnsCancelQuery(&cancelHandle);
        });

        const DWORD waitMs = static_cast<DWORD>(
            std::clamp<i64>(options.timeout.count(), 1, 60'000));
        if (::WaitForSingleObject(context->done.get(), waitMs) == WAIT_TIMEOUT) {
            ::DnsCancelQuery(&cancelHandle);
            ::WaitForSingleObject(context->done.get(), INFINITE);
        }
        registration.reset();

        const DNS_STATUS queryStatus = context->result.QueryStatus;
        if (token.isCancelled()) {
            if (context->result.pQueryRecords != nullptr) {
                ::DnsRecordListFree(context->result.pQueryRecords, DnsFreeRecordList);
            }
            return err::cancelled("resolution cancelled");
        }
        if (queryStatus != ERROR_SUCCESS) {
            if (context->result.pQueryRecords != nullptr) {
                ::DnsRecordListFree(context->result.pQueryRecords, DnsFreeRecordList);
            }
            if (queryStatus == ERROR_CANCELLED) {
                return err::timeout("DNS query for " + host + " timed out");
            }
            return Status{classifyDnsStatus(queryStatus),
                          "DnsQueryEx(" + host + ") failed", static_cast<u32>(queryStatus)};
        }

        collectRecords(context->result.pQueryRecords, type, out, minTtl);
        if (context->result.pQueryRecords != nullptr) {
            ::DnsRecordListFree(context->result.pQueryRecords, DnsFreeRecordList);
        }
        return Status::ok();
    }

    std::shared_ptr<INetworkMonitor> m_monitor;
    std::mutex                       m_mutex;
    std::optional<ScopeBinding>      m_tunnelBinding;
    std::unordered_map<std::string, CacheEntry> m_cache;
};

} // namespace

ResolverPtr makeResolver(std::shared_ptr<INetworkMonitor> monitor)
{
    return std::make_shared<WindowsResolver>(std::move(monitor));
}

} // namespace nova::net
