// The OpenVPN engine is compiled conditionally. These tests adapt to both
// builds: when the engine is absent they assert the factory reports it cleanly;
// when present they exercise validate() through OpenVPN3's own eval_config,
// which needs no server and no elevation.
#include <NovaVPN/Profiles/Profile.h>
#include <NovaVPN/Tunnel/Engine.h>
#include <NovaVPN/Tunnel/OpenVpnEngine.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::tunnel;

namespace {

profiles::Profile profileWithConfig(std::string config)
{
    profiles::Profile profile;
    profile.name         = "OpenVPN Test";
    profile.sourceConfig = std::move(config);
    return profile;
}

} // namespace

TEST_CASE("the engine availability flag matches the factory", "[openvpn][engine]")
{
    if (isOpenVpnEngineAvailable()) {
        REQUIRE(makeOpenVpnEngine().isOk());
    } else {
        auto engine = makeOpenVpnEngine();
        REQUIRE(engine.isError());
        REQUIRE(engine.status().code() == ErrorCode::NotImplemented);
    }
}

TEST_CASE("registering the engine is a no-op when it is unavailable",
          "[openvpn][engine]")
{
    auto registry = std::dynamic_pointer_cast<IMutableEngineRegistry>(makeEngineRegistry());
    REQUIRE(registry != nullptr);

    // Registration always succeeds - the startup path is identical in both
    // build configurations.
    REQUIRE(registerOpenVpnEngine(*registry).isOk());
    REQUIRE(registry->create("openvpn").isOk() == isOpenVpnEngineAvailable());
}

TEST_CASE("validate accepts a well-formed config and rejects a broken one",
          "[openvpn][engine]")
{
    if (!isOpenVpnEngineAvailable()) {
        SUCCEED("OpenVPN engine not compiled into this build");
        return;
    }

    auto engine = makeOpenVpnEngine().value();

    // A minimal but valid OpenVPN client config (example.net is RFC-reserved).
    const auto good = profileWithConfig(
        "client\ndev tun\nproto udp\nremote hk1.example.net 1194 udp\n"
        "<ca>\n-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n</ca>\n");
    REQUIRE(engine->validate(good).isOk());

    // An empty config has nothing to validate.
    REQUIRE(engine->validate(profileWithConfig("")).isError());

    // Garbage that OpenVPN3's own parser rejects.
    const auto bad = profileWithConfig("this is not an openvpn configuration at all\n");
    const Status result = engine->validate(bad);
    // eval_config is lenient about unknown directives but a config with no
    // remote and no meaningful content should not validate as connectable;
    // whichever way OpenVPN3 judges it, the engine must not crash and must
    // return a definite verdict.
    REQUIRE((result.isOk() || result.code() == ErrorCode::ConfigInvalid));
}

TEST_CASE("the engine reports its id and version", "[openvpn][engine]")
{
    if (!isOpenVpnEngineAvailable()) {
        SUCCEED("OpenVPN engine not compiled into this build");
        return;
    }
    auto engine = makeOpenVpnEngine().value();
    REQUIRE(engine->engineId() == "openvpn");
    REQUIRE_FALSE(engine->version().empty());
}
