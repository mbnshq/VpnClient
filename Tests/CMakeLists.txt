# Tests - unit tests for everything implemented so far.
#
# Integration, stress and leak tests arrive with the subsystems they exercise
# (Phases 4, 6 and 9); they need an elevated runner and a real adapter, so they
# are kept in a separate target from these host-independent unit tests.

include(Catch)

nova_add_executable(novavpn_unit_tests
    SOURCES
        unit/StatusTests.cpp
        unit/StringUtilTests.cpp
        unit/SecureMemoryTests.cpp
        unit/UuidTests.cpp
        unit/ConfigTests.cpp
        unit/CancellationTests.cpp
        unit/DataProtectionTests.cpp
        unit/EventBusTests.cpp
        unit/LoggerTests.cpp
        unit/IpAddressTests.cpp
        unit/SockAddrTests.cpp
        unit/NetworkMonitorTests.cpp
        unit/ResolverTests.cpp
        unit/RouteManagerTests.cpp
        unit/DatabaseTests.cpp
        unit/StatisticsTests.cpp
        unit/RoutingRulesTests.cpp
        unit/ProfileTests.cpp
        unit/OvpnParserTests.cpp
        unit/CredentialStoreTests.cpp
        unit/ProfileStoreTests.cpp
        unit/WintunTests.cpp
        unit/EngineRegistryTests.cpp
        unit/TunnelManagerTests.cpp
        unit/OpenVpnEngineTests.cpp
        unit/IpcProtocolTests.cpp
        unit/IpcTransportTests.cpp
    DEPENDS
        nova::core
        nova::logs
        nova::networking
        nova::routing
        nova::profiles
        nova::services
        nova::database
        nova::driver
        nova::tunnel
        Catch2::Catch2WithMain
    FOLDER "Tests")

# Wintun loads by name from the executable's own directory, so the fetched DLL
# must sit beside the test binary for the load path to be exercisable. The
# signed DLL is a runtime input, never linked.
if(EXISTS "${NOVAVPN_WINTUN_DLL}")
    add_custom_command(TARGET novavpn_unit_tests POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${NOVAVPN_WINTUN_DLL}" "$<TARGET_FILE_DIR:novavpn_unit_tests>"
        VERBATIM)
endif()

catch_discover_tests(novavpn_unit_tests
    TEST_PREFIX "unit."
    REPORTER console)
