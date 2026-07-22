# Services - the privileged host process and the UI <-> service IPC contract.

nova_add_module(Services
    SOURCES
        src/IpcProtocol.cpp
        src/IpcServer.cpp
        src/IpcClient.cpp
        src/ServiceHost.cpp
    HEADERS
        include/NovaVPN/Services/IpcProtocol.h
        include/NovaVPN/Services/IpcServer.h
        include/NovaVPN/Services/IpcClient.h
        include/NovaVPN/Services/ServiceHost.h
    DEPENDS
        nova::core
        nova::logs
        nova::networking
        nova::profiles
        nova::routing
        nova::firewall
        nova::splittunnel
        nova::tunnel
        nova::database
        nova::updater
    SYSTEM
        advapi32
        wtsapi32)

nova_add_executable(NovaVPNService
    SOURCES
        src/ServiceMain.cpp
    DEPENDS
        nova::services
    OUTPUT_NAME NovaVPNService
    FOLDER "Applications")
