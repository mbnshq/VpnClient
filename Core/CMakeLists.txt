# Core - foundation layer. Depends on nothing but the C++ standard library,
# nlohmann/json and the Win32 API. Every other module builds on it.

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/NovaVPN/Core/Version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/NovaVPN/Core/Version.h"
    @ONLY)

nova_add_module(Core
    SOURCES
        src/Types.cpp
        src/Status.cpp
        src/StringUtil.cpp
        src/SecureMemory.cpp
        src/WinError.cpp
        src/Uuid.cpp
        src/Paths.cpp
        src/FileUtil.cpp
        src/Json.cpp
        src/Config.cpp
        src/Cancellation.cpp
        src/DataProtection.cpp
    HEADERS
        include/NovaVPN/Core/Types.h
        include/NovaVPN/Core/Status.h
        include/NovaVPN/Core/Result.h
        include/NovaVPN/Core/StringUtil.h
        include/NovaVPN/Core/SecureMemory.h
        include/NovaVPN/Core/WinError.h
        include/NovaVPN/Core/Handle.h
        include/NovaVPN/Core/Uuid.h
        include/NovaVPN/Core/Paths.h
        include/NovaVPN/Core/FileUtil.h
        include/NovaVPN/Core/Json.h
        include/NovaVPN/Core/Config.h
        include/NovaVPN/Core/Cancellation.h
        include/NovaVPN/Core/DataProtection.h
        include/NovaVPN/Core/EventBus.h
    DEPENDS
        nlohmann_json::nlohmann_json
    SYSTEM
        bcrypt
        advapi32
        shell32
        ole32
        crypt32)

target_include_directories(novavpn_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>)
