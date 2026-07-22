# Driver - Wintun adapter ownership. Compiles against wintun.h (fetched,
# header-only) and loads wintun.dll dynamically at runtime, so the module links
# no import library for it.

nova_add_module(Driver
    SOURCES
        src/WintunLibrary.cpp
        src/WintunAdapter.cpp
    HEADERS
        include/NovaVPN/Driver/WintunAdapter.h
    DEPENDS
        nova::core
        nova::logs
        nova::networking
    PRIVATE_DEPENDS
        nova::wintun_headers
    SYSTEM
        iphlpapi
        wintrust
        crypt32)
