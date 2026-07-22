# Networking - address vocabulary, resolution and link-quality contracts.
# Phase 1 ships the value types (fully implemented and unit-tested); the
# resolver and network-monitor implementations land in Phase 2.

nova_add_module(Networking
    SOURCES
        src/IpAddress.cpp
        src/Statistics.cpp
    HEADERS
        include/NovaVPN/Networking/IpAddress.h
        include/NovaVPN/Networking/Resolver.h
        include/NovaVPN/Networking/NetworkMonitor.h
        include/NovaVPN/Networking/Statistics.h
    DEPENDS
        nova::core
        nova::logs
    SYSTEM
        ws2_32
        iphlpapi)
