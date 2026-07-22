#
# NovaVPN - commercial-grade Windows VPN client
# Root build script (superbuild entry point).
#
cmake_minimum_required(VERSION 3.24)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(NovaVpnVersion)

project(NovaVPN
    VERSION     ${NOVAVPN_VERSION}
    DESCRIPTION "NovaVPN - modern Windows VPN client"
    HOMEPAGE_URL "https://github.com/mbnshq/VpnClient"
    LANGUAGES   CXX C)   # C for the vendored SQLite amalgamation

if(NOT WIN32)
    message(FATAL_ERROR "NovaVPN targets Windows 10/11 (x64) only.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "NovaVPN must be built for x64. Configure with a 64-bit toolchain.")
endif()

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
    # Static CRT keeps the service and the elevated helpers free of redistributable
    # dependencies, which matters for a driver-installing product.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

include(NovaVpnOptions)
include(CompilerWarnings)
include(NovaVpnModule)
include(Dependencies)

# Vendored third-party libraries built from source.
add_subdirectory(ThirdParty/sqlite)

# ---------------------------------------------------------------------------
# Modules (see docs/ARCHITECTURE.md for the layering rules)
# ---------------------------------------------------------------------------
add_subdirectory(Core)
add_subdirectory(Logs)
add_subdirectory(Database)
add_subdirectory(Profiles)
add_subdirectory(Networking)
add_subdirectory(Driver)
add_subdirectory(Tunnel)
add_subdirectory(Firewall)
add_subdirectory(Routing)
add_subdirectory(SplitTunnel)
add_subdirectory(Updater)
add_subdirectory(Services)

if(NOVAVPN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(Tests)
endif()

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "NovaVPN ${PROJECT_VERSION} (${NOVAVPN_VERSION_CHANNEL})")
message(STATUS "  Generator     : ${CMAKE_GENERATOR}")
message(STATUS "  Compiler      : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  CRT           : ${CMAKE_MSVC_RUNTIME_LIBRARY}")
message(STATUS "  Tests         : ${NOVAVPN_BUILD_TESTS}")
message(STATUS "  Warnings fatal: ${NOVAVPN_WARNINGS_AS_ERRORS}")
message(STATUS "")
