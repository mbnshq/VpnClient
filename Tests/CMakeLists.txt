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
        unit/IpcProtocolTests.cpp
    DEPENDS
        nova::core
        nova::logs
        nova::networking
        nova::routing
        nova::profiles
        nova::services
        nova::database
        Catch2::Catch2WithMain
    FOLDER "Tests")

catch_discover_tests(novavpn_unit_tests
    TEST_PREFIX "unit."
    REPORTER console)
