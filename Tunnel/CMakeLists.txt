# Tunnel - tunnel lifecycle and the protocol-engine plugin ABI. The engine
# registry and signed plugin loader ship here; the OpenVPN engine and the
# tunnel state machine land next.

nova_add_module(Tunnel
    SOURCES
        src/EngineRegistry.cpp
    HEADERS
        include/NovaVPN/Tunnel/Tunnel.h
        include/NovaVPN/Tunnel/Engine.h
    DEPENDS
        nova::core
        nova::logs
        nova::networking
        nova::profiles
        nova::driver
    SYSTEM
        wintrust
        crypt32)
