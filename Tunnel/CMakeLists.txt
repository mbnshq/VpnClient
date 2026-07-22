# Tunnel - tunnel lifecycle and the protocol-engine plugin ABI.
# The OpenVPN engine and the tunnel implementation land in Phase 3.

nova_add_module(Tunnel
    HEADERS
        include/NovaVPN/Tunnel/Tunnel.h
        include/NovaVPN/Tunnel/Engine.h
    DEPENDS
        nova::core
        nova::logs
        nova::networking
        nova::profiles
        nova::driver)
