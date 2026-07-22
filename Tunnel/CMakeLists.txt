# Tunnel - tunnel lifecycle and the protocol-engine plugin ABI. The engine
# registry and signed plugin loader ship here; the OpenVPN engine and the
# tunnel state machine land next.

nova_add_module(Tunnel
    SOURCES
        src/EngineRegistry.cpp
    HEADERS
        include/NovaVPN/Tunnel/Tunnel.h
        include/NovaVPN/Tunnel/Engine.h
        include/NovaVPN/Tunnel/OpenVpnEngine.h
    DEPENDS
        nova::core
        nova::logs
        nova::networking
        nova::profiles
        nova::driver
    SYSTEM
        wintrust
        crypt32)

# --- OpenVPN engine -------------------------------------------------------
# When enabled, OpenVPN3 Core's ClientAPI is compiled into a dedicated engine
# library using OpenVPN3's build recipe (bigobj, its own defines, relaxed
# warnings - the OpenVPN3 headers do not build under our /W4 /WX). The strict
# first-party flags stop at this boundary; nothing here leaks OpenVPN3 types
# past IVpnEngine. When disabled, a stub keeps the factory symbols defined.
if(NOVAVPN_BUILD_OPENVPN_ENGINE)
    find_package(OpenSSL REQUIRED)
    find_package(asio CONFIG REQUIRED)
    find_package(lz4 REQUIRED)
    find_package(fmt CONFIG REQUIRED)

    if(NOT NOVAVPN_OPENVPN3_DIR)
        message(FATAL_ERROR "NOVAVPN_OPENVPN3_DIR is not set; the OpenVPN3 fetch failed.")
    endif()

    add_library(novavpn_openvpn_engine STATIC
        openvpn/OpenVpnEngine.cpp
        "${NOVAVPN_OPENVPN3_DIR}/client/ovpncli.cpp"
        "${NOVAVPN_OPENVPN3_DIR}/openvpn/crypto/data_epoch.cpp")

    # Pull the NovaVPN headers the adapter needs as include directories only -
    # NOT by linking nova::core, which would drag in nova::hardening's
    # _WIN32_WINNT=0x0A00 and break OpenVPN3's Windows tun code. As a static
    # library this target needs no nova symbols at build time; they resolve when
    # the final executable links nova::core through novavpn_tunnel.
    target_include_directories(novavpn_openvpn_engine PRIVATE
        "${NOVAVPN_OPENVPN3_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        $<TARGET_PROPERTY:novavpn_core,INTERFACE_INCLUDE_DIRECTORIES>
        $<TARGET_PROPERTY:novavpn_logs,INTERFACE_INCLUDE_DIRECTORIES>
        $<TARGET_PROPERTY:novavpn_networking,INTERFACE_INCLUDE_DIRECTORIES>
        $<TARGET_PROPERTY:novavpn_profiles,INTERFACE_INCLUDE_DIRECTORIES>)

    target_compile_definitions(novavpn_openvpn_engine PRIVATE
        ASIO_STANDALONE USE_ASIO HAVE_LZ4 USE_OPENSSL
        _WIN32_WINNT=0x0600 TAP_WIN_COMPONENT_ID=tap0901
        _CRT_SECURE_NO_WARNINGS ASIO_DISABLE_LOCAL_SOCKETS
        NOMINMAX WIN32_LEAN_AND_MEAN)

    if(MSVC)
        target_compile_options(novavpn_openvpn_engine PRIVATE
            /bigobj /W3 /wd4200 /wd4146 /EHsc /utf-8)
    endif()

    # Only the third-party engine dependencies are linked here. The nova
    # symbols resolve when the final executable links novavpn_tunnel (which
    # depends on nova::core et al.); see the include-directories note above.
    target_link_libraries(novavpn_openvpn_engine
        PRIVATE asio::asio lz4::lz4 fmt::fmt OpenSSL::SSL OpenSSL::Crypto
                fwpuclnt.lib iphlpapi.lib wininet.lib setupapi.lib rpcrt4.lib
                wtsapi32.lib ws2_32.lib crypt32.lib)

    set_target_properties(novavpn_openvpn_engine PROPERTIES FOLDER "Engines")

    # The Tunnel library exposes the engine to the rest of the product.
    target_link_libraries(novavpn_tunnel PUBLIC novavpn_openvpn_engine)
    target_compile_definitions(novavpn_tunnel PUBLIC NOVAVPN_HAS_OPENVPN_ENGINE=1)
else()
    target_sources(novavpn_tunnel PRIVATE openvpn/OpenVpnEngineStub.cpp)
endif()
