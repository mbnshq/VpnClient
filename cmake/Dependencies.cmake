# Third-party dependency acquisition.
#
# Policy (see docs/adr/0003-dependency-management.md):
#   * Vendored sources live in ThirdParty/ and are committed only when the
#     upstream project has no usable release archive (e.g. Wintun headers).
#   * Everything else is fetched by FetchContent at a pinned tag + hash so a
#     build is reproducible and auditable.
#   * NOVAVPN_OFFLINE=ON turns every fetch into a hard error, which is how the
#     release pipeline proves it only consumed the pre-populated cache.

include(FetchContent)

set(FETCHCONTENT_QUIET OFF)
if(NOVAVPN_OFFLINE)
    set(FETCHCONTENT_FULLY_DISCONNECTED ON)
endif()

# --- nlohmann/json --------------------------------------------------------
# Used for configuration files, profile metadata, the IPC wire format and the
# update manifest. Header-only, no transitive dependencies.
FetchContent_Declare(nlohmann_json
    URL      https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)

set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

if(TARGET nlohmann_json)
    set_target_properties(nlohmann_json PROPERTIES FOLDER "ThirdParty")
endif()

# --- Wintun (header only) -------------------------------------------------
# The Driver module compiles against wintun.h but loads wintun.dll dynamically
# at runtime (LoadLibraryEx + GetProcAddress), so only the header is a build
# input. The DLL itself is a packaging artifact fetched and signature-verified
# by the installer, never linked. wintun.h is released into the public domain.
FetchContent_Declare(wintun
    URL      https://www.wintun.net/builds/wintun-0.14.1.zip
    URL_HASH SHA256=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)

FetchContent_MakeAvailable(wintun)

# Expose the header directory as an interface target the Driver module consumes.
add_library(nova_wintun_headers INTERFACE)
add_library(nova::wintun_headers ALIAS nova_wintun_headers)
target_include_directories(nova_wintun_headers INTERFACE "${wintun_SOURCE_DIR}/include")

# Record where the redistributable DLL lives so the packaging step can copy and
# verify it. Not consumed by the build.
set(NOVAVPN_WINTUN_DLL "${wintun_SOURCE_DIR}/bin/amd64/wintun.dll"
    CACHE FILEPATH "Path to the fetched wintun.dll (packaging input)")

# --- Catch2 (tests only) --------------------------------------------------
if(NOVAVPN_BUILD_TESTS)
    FetchContent_Declare(Catch2
        URL      https://github.com/catchorg/Catch2/archive/refs/tags/v3.5.2.tar.gz
        URL_HASH SHA256=269543a49eb76f40b3f93ff231d4c24c27a7e16c90e47d2e45bcc564de470c6e
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)

    set(CATCH_INSTALL_DOCS OFF CACHE INTERNAL "")
    set(CATCH_INSTALL_EXTRAS OFF CACHE INTERNAL "")
    FetchContent_MakeAvailable(Catch2)

    # Catch.cmake / catch_discover_tests() live in the extras directory.
    list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")

    foreach(_t Catch2 Catch2WithMain)
        if(TARGET ${_t})
            set_target_properties(${_t} PROPERTIES FOLDER "ThirdParty")
        endif()
    endforeach()
endif()
