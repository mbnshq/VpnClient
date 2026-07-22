# Updater - signed automatic updates with delta packages. Phase 7.

nova_add_module(Updater
    SOURCES
        src/Updater.cpp
        src/SignatureVerifier.cpp
        src/UpdaterImpl.cpp
        src/WinHttpFetcher.cpp
    HEADERS
        include/NovaVPN/Updater/Updater.h
    DEPENDS
        nova::core
        nova::logs
    SYSTEM
        winhttp
        wintrust
        crypt32
        bcrypt)
