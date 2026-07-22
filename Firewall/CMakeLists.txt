# Firewall - WFP policy: kill switch, leak protection, enforcement half of
# split tunnelling. The WFP implementation lands in Phase 6.

nova_add_module(Firewall
    SOURCES
        src/FirewallEngine.cpp
    HEADERS
        include/NovaVPN/Firewall/FirewallEngine.h
    DEPENDS
        nova::core
        nova::logs
        nova::networking
    SYSTEM
        fwpuclnt
        rpcrt4)
