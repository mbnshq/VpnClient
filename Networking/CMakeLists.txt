# Networking - address vocabulary, the scope-pinned resolver and the network
# monitor (Phase 2), plus link-quality statistics.

nova_add_module(Networking
    SOURCES
        src/IpAddress.cpp
        src/SockAddr.cpp
        src/Statistics.cpp
        src/NetworkMonitor.cpp
        src/Resolver.cpp
    HEADERS
        include/NovaVPN/Networking/IpAddress.h
        include/NovaVPN/Networking/SockAddr.h
        include/NovaVPN/Networking/Resolver.h
        include/NovaVPN/Networking/NetworkMonitor.h
        include/NovaVPN/Networking/Statistics.h
    DEPENDS
        nova::core
        nova::logs
    SYSTEM
        ws2_32
        iphlpapi
        dnsapi)
