# Build-time switches. Defaults are tuned for developer machines; CI overrides
# NOVAVPN_WARNINGS_AS_ERRORS and NOVAVPN_ENABLE_ASAN explicitly.

include(CMakeDependentOption)

option(NOVAVPN_BUILD_TESTS        "Build unit/integration tests"            ON)
# The OpenVPN engine compiles OpenVPN3 Core (plus OpenSSL/asio/lz4/fmt via
# vcpkg) into a dedicated target. It is opt-in because it requires the vcpkg
# toolchain file and the fetched OpenVPN3 source; the rest of the product builds
# and tests without it. See docs/OPENVPN_ENGINE.md.
option(NOVAVPN_BUILD_OPENVPN_ENGINE "Build the OpenVPN3-backed engine"       OFF)
option(NOVAVPN_WARNINGS_AS_ERRORS "Treat compiler warnings as errors"       OFF)
option(NOVAVPN_ENABLE_ASAN        "Build with AddressSanitizer"             OFF)
option(NOVAVPN_ENABLE_LTO         "Enable link time code generation"        OFF)
option(NOVAVPN_OFFLINE            "Forbid network fetches of dependencies"  OFF)

# Minimum supported OS: Windows 10 21H2 (10.0.19044). WFP, Wintun and the
# split-tunnel callout paths all assume this baseline.
set(NOVAVPN_WIN32_WINNT 0x0A00 CACHE STRING "_WIN32_WINNT baseline")
mark_as_advanced(NOVAVPN_WIN32_WINNT)

if(NOVAVPN_ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT _nova_ipo_ok OUTPUT _nova_ipo_msg)
    if(_nova_ipo_ok)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
    else()
        message(WARNING "LTO requested but unavailable: ${_nova_ipo_msg}")
    endif()
endif()
