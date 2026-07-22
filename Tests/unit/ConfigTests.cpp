#include <NovaVPN/Core/Config.h>
#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/Uuid.h>

#include <catch2/catch_test_macros.hpp>

#include <filesystem>

using namespace nova;

namespace {

/// Temporary directory removed when the test finishes, whatever the outcome.
class ScratchDirectory {
public:
    ScratchDirectory()
        : m_path(std::filesystem::temp_directory_path() /
                 ("novavpn-test-" + Uuid::generate().toString()))
    {
        std::filesystem::create_directories(m_path);
    }

    ~ScratchDirectory()
    {
        std::error_code ec;
        std::filesystem::remove_all(m_path, ec);
    }

    ScratchDirectory(const ScratchDirectory&) = delete;
    ScratchDirectory& operator=(const ScratchDirectory&) = delete;

    [[nodiscard]] std::filesystem::path file(std::string_view name) const
    {
        return m_path / name;
    }

private:
    std::filesystem::path m_path;
};

} // namespace

TEST_CASE("a missing config file yields the defaults", "[config]")
{
    const ScratchDirectory scratch;
    ConfigStore store{scratch.file("config.json"), serviceConfigDefaults()};

    REQUIRE(store.load().isOk());
    REQUIRE(store.get<std::string>("/service/logLevel", "") == "info");
    REQUIRE(store.get<bool>("/connection/autoReconnect", false));
    REQUIRE(store.get<int>("/connection/mtu", 0) == 1500);
    REQUIRE(store.get<std::string>("/firewall/killSwitch", "") == "soft");
}

TEST_CASE("only the delta against the defaults is persisted", "[config]")
{
    const ScratchDirectory scratch;
    const auto path = scratch.file("config.json");

    ConfigStore store{path, serviceConfigDefaults()};
    REQUIRE(store.load().isOk());
    REQUIRE(store.set("/service/logLevel", "debug").isOk());
    REQUIRE(store.save().isOk());

    const Json delta = store.delta();
    REQUIRE(delta.contains("service"));
    REQUIRE(delta["service"]["logLevel"] == "debug");
    // Untouched keys must not be written, so future default changes reach the
    // user instead of being frozen by a stale file.
    REQUIRE_FALSE(delta["service"].contains("logRetentionDays"));
    REQUIRE_FALSE(delta.contains("firewall"));

    ConfigStore reloaded{path, serviceConfigDefaults()};
    REQUIRE(reloaded.load().isOk());
    REQUIRE(reloaded.get<std::string>("/service/logLevel", "") == "debug");
    REQUIRE(reloaded.get<int>("/service/logRetentionDays", 0) == 14);
}

TEST_CASE("a corrupt config file falls back to defaults and reports why", "[config]")
{
    const ScratchDirectory scratch;
    const auto path = scratch.file("config.json");

    REQUIRE(file::writeAtomicText(path, "{ this is not json").isOk());

    ConfigStore store{path, serviceConfigDefaults()};
    const Status status = store.load();

    REQUIRE(status.isError());
    REQUIRE(status.code() == ErrorCode::ParseError);
    // The service must still be able to run, so the store is usable afterwards.
    REQUIRE(store.get<std::string>("/service/logLevel", "") == "info");
}

TEST_CASE("apply merges an overlay and notifies once per changed key", "[config]")
{
    const ScratchDirectory scratch;
    ConfigStore store{scratch.file("config.json"), serviceConfigDefaults()};
    REQUIRE(store.load().isOk());

    std::vector<std::string> changed;
    store.onChanged([&changed](std::string_view pointer) {
        changed.emplace_back(pointer);
    });

    Json overlay;
    overlay["firewall"] = Json{{"killSwitch", "hard"}};
    overlay["dns"]      = Json{{"leakProtection", true}}; // unchanged value

    REQUIRE(store.apply(overlay).isOk());

    REQUIRE(store.get<std::string>("/firewall/killSwitch", "") == "hard");
    // Nested keys the overlay did not mention survive the merge.
    REQUIRE(store.get<bool>("/firewall/blockIpv6", false));

    REQUIRE(changed.size() == 1);
    REQUIRE(changed[0] == "/firewall");

    REQUIRE(store.apply(Json::array()).isError());
}

TEST_CASE("reset restores a single default", "[config]")
{
    const ScratchDirectory scratch;
    ConfigStore store{scratch.file("config.json"), serviceConfigDefaults()};
    REQUIRE(store.load().isOk());

    REQUIRE(store.set("/connection/mtu", 1400).isOk());
    REQUIRE(store.get<int>("/connection/mtu", 0) == 1400);

    REQUIRE(store.reset("/connection/mtu").isOk());
    REQUIRE(store.get<int>("/connection/mtu", 0) == 1500);

    REQUIRE(store.reset("/nonexistent/key").isError());
}

TEST_CASE("user settings defaults cover the UI surface", "[config]")
{
    const Json& defaults = userSettingsDefaults();

    REQUIRE(defaults["appearance"]["theme"] == "system");
    REQUIRE(defaults["language"] == "system");
    REQUIRE(defaults["notifications"]["onLeakDetected"] == true);
    REQUIRE(defaults["dashboard"]["graphWindowSeconds"] == 120);
}

TEST_CASE("writeAtomicText replaces content without corruption", "[config][io]")
{
    const ScratchDirectory scratch;
    const auto path = scratch.file("atomic.txt");

    REQUIRE(file::writeAtomicText(path, "first").isOk());
    REQUIRE(file::readText(path).value() == "first");

    REQUIRE(file::writeAtomicText(path, "second, longer contents").isOk());
    REQUIRE(file::readText(path).value() == "second, longer contents");

    REQUIRE(file::sizeOf(path).value() == 23);
    REQUIRE(file::exists(path));

    REQUIRE(file::secureDelete(path).isOk());
    REQUIRE_FALSE(file::exists(path));
    REQUIRE(file::secureDelete(path).isOk()); // idempotent
}

TEST_CASE("readText strips a BOM and normalises line endings", "[config][io]")
{
    const ScratchDirectory scratch;
    const auto path = scratch.file("bom.txt");

    const std::string withBom = "\xEF\xBB\xBFremote host\r\nport 1194\r\n";
    REQUIRE(file::writeAtomicText(path, withBom).isOk());

    const auto text = file::readText(path);
    REQUIRE(text.isOk());
    REQUIRE(text.value() == "remote host\nport 1194\n");
}
