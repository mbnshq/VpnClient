# Routing - policy vocabulary and evaluation, plus the Windows route-table
# manager with its crash-recovery ledger (Phase 2).

nova_add_module(Routing
    SOURCES
        src/RoutingRules.cpp
        src/RouteManager.cpp
    HEADERS
        include/NovaVPN/Routing/RoutingRules.h
        include/NovaVPN/Routing/RouteManager.h
    DEPENDS
        nova::core
        nova::logs
        nova::networking
    SYSTEM
        iphlpapi)
