# Routing - policy vocabulary and evaluation (implemented, unit-tested here)
# plus the Windows route-table management contract (Phase 2).

nova_add_module(Routing
    SOURCES
        src/RoutingRules.cpp
    HEADERS
        include/NovaVPN/Routing/RoutingRules.h
        include/NovaVPN/Routing/RouteManager.h
    DEPENDS
        nova::core
        nova::logs
        nova::networking
    SYSTEM
        iphlpapi)
