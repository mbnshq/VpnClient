# Profiles - connection profile model, validation and serialisation.
# The store and the .ovpn parser are implemented in Phase 3.

nova_add_module(Profiles
    SOURCES
        src/Profile.cpp
        src/OvpnParser.cpp
    HEADERS
        include/NovaVPN/Profiles/Profile.h
        include/NovaVPN/Profiles/ProfileStore.h
        include/NovaVPN/Profiles/OvpnParser.h
    DEPENDS
        nova::core
        nova::logs
        nova::networking)
