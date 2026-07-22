#include <NovaVPN/Tunnel/Engine.h>

#include <catch2/catch_test_macros.hpp>

#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <memory>

using namespace nova;
using namespace nova::tunnel;

namespace {

/// A minimal in-process engine so the registry can be exercised without a real
/// protocol implementation.
class FakeEngine final : public IVpnEngine {
public:
    explicit FakeEngine(std::string id) : m_id(std::move(id)) {}

    std::string_view engineId() const noexcept override { return m_id; }
    std::string version() const override { return "test"; }
    Status validate(const profiles::Profile&) const override { return Status::ok(); }
    Status start(EngineConfig, EngineHost, const CancellationToken&) override
    {
        return Status::ok();
    }
    Status stop() override { return Status::ok(); }
    Status sendPacket(std::span<const u8>) override { return Status::ok(); }
    Status provideCredential(ChallengeKind, SecureString) override { return Status::ok(); }
    Status renegotiate() override { return Status::ok(); }

private:
    std::string m_id;
};

std::shared_ptr<IMutableEngineRegistry> mutableRegistry(bool requireSigned = true)
{
    return std::dynamic_pointer_cast<IMutableEngineRegistry>(
        makeEngineRegistry(requireSigned));
}

} // namespace

TEST_CASE("a built-in engine can be registered and created", "[tunnel][registry]")
{
    auto registry = mutableRegistry();
    REQUIRE(registry != nullptr);

    REQUIRE(registry
                ->registerBuiltin("openvpn",
                                  [] { return std::make_shared<FakeEngine>("openvpn"); })
                .isOk());

    auto engine = registry->create("openvpn");
    REQUIRE(engine.isOk());
    REQUIRE(engine.value()->engineId() == "openvpn");
}

TEST_CASE("engine ids are matched case-insensitively", "[tunnel][registry]")
{
    auto registry = mutableRegistry();
    REQUIRE(registry
                ->registerBuiltin("OpenVPN",
                                  [] { return std::make_shared<FakeEngine>("openvpn"); })
                .isOk());

    REQUIRE(registry->create("openvpn").isOk());
    REQUIRE(registry->create("OPENVPN").isOk());
}

TEST_CASE("registering the same engine twice is refused", "[tunnel][registry]")
{
    auto registry = mutableRegistry();
    REQUIRE(registry->registerBuiltin("openvpn", [] {
                return std::make_shared<FakeEngine>("openvpn");
            }).isOk());

    const Status second = registry->registerBuiltin("openvpn", [] {
        return std::make_shared<FakeEngine>("openvpn");
    });
    REQUIRE(second.code() == ErrorCode::AlreadyExists);
}

TEST_CASE("an unknown engine is NotFound", "[tunnel][registry]")
{
    auto registry = makeEngineRegistry();
    auto engine = registry->create("wireguard");
    REQUIRE(engine.isError());
    REQUIRE(engine.status().code() == ErrorCode::NotFound);
}

TEST_CASE("availableEngines lists what is registered", "[tunnel][registry]")
{
    auto registry = mutableRegistry();
    REQUIRE(registry->availableEngines().empty());

    REQUIRE(registry->registerBuiltin("openvpn", [] {
                return std::make_shared<FakeEngine>("openvpn");
            }).isOk());
    REQUIRE(registry->registerBuiltin("wireguard", [] {
                return std::make_shared<FakeEngine>("wireguard");
            }).isOk());

    const auto engines = registry->availableEngines();
    REQUIRE(engines.size() == 2);
}

TEST_CASE("registering rejects empty ids and null factories", "[tunnel][registry]")
{
    auto registry = mutableRegistry();
    REQUIRE(registry->registerBuiltin("", [] { return nullptr; }).isError());
    REQUIRE(registry->registerBuiltin("x", nullptr).isError());
}

TEST_CASE("loading plugins from a missing directory is not an error",
          "[tunnel][registry]")
{
    auto registry = makeEngineRegistry();
    const auto missing = std::filesystem::temp_directory_path() / "novavpn-no-such-plugins";
    REQUIRE(registry->loadPlugins(missing).isOk());
}

TEST_CASE("loading plugins from an empty directory finds nothing",
          "[tunnel][registry]")
{
    auto registry = makeEngineRegistry();
    const auto dir = std::filesystem::temp_directory_path() /
                     ("novavpn-plugins-" + std::to_string(::GetCurrentProcessId()));
    std::filesystem::create_directories(dir);

    REQUIRE(registry->loadPlugins(dir).isOk());
    REQUIRE(registry->availableEngines().empty());

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST_CASE("an unsigned DLL in the plugin directory is refused when signing is required",
          "[tunnel][registry][security]")
{
    auto registry = makeEngineRegistry(/*requireSignedPlugins=*/true);
    const auto dir = std::filesystem::temp_directory_path() /
                     ("novavpn-plugins-unsigned-" + std::to_string(::GetCurrentProcessId()));
    std::filesystem::create_directories(dir);

    // A file that is not a validly-signed DLL: loadPlugins must skip it (the
    // whole call still succeeds - one bad plugin never stops the rest) and
    // register nothing from it.
    const auto fake = dir / "evil.dll";
    { std::ofstream out{fake}; out << "not a real dll"; }

    REQUIRE(registry->loadPlugins(dir).isOk());
    REQUIRE(registry->availableEngines().empty());

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}
