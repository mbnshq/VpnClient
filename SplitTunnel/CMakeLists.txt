# SplitTunnel - per-application routing. The WFP callout, the ETW process feed
# and the DNS interception land in Phase 4.

nova_add_module(SplitTunnel
    SOURCES
        src/SplitTunnelEngine.cpp
    HEADERS
        include/NovaVPN/SplitTunnel/ProcessRegistry.h
        include/NovaVPN/SplitTunnel/SplitTunnelEngine.h
    DEPENDS
        nova::core
        nova::logs
        nova::networking
        nova::routing
    SYSTEM
        fwpuclnt
        tdh
        version)
