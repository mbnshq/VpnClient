// The process registry runs against the live machine, so these assert only what
// every Windows session guarantees: this process is enumerable with its own
// image path, the parent chain resolves, and installed-app discovery returns a
// coherent (possibly empty) list without faulting.
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/SplitTunnel/ProcessRegistry.h>

#include <catch2/catch_test_macros.hpp>

#include <Windows.h>

#include <algorithm>

using namespace nova;
using namespace nova::splittunnel;

TEST_CASE("the registry starts and stops cleanly", "[splittunnel][process]")
{
    auto registry = makeProcessRegistry();
    REQUIRE(registry->start().isOk());
    registry->stop();
}

TEST_CASE("the current process resolves to its own image path",
          "[splittunnel][process]")
{
    auto registry = makeProcessRegistry();
    REQUIRE(registry->start().isOk());

    const ProcessId self = ::GetCurrentProcessId();
    auto path = registry->imagePathFor(self);
    REQUIRE(path.has_value());
    // We are the unit test binary.
    REQUIRE(path->find("novavpn_unit_tests") != std::string::npos);
}

TEST_CASE("a non-existent PID resolves to nothing", "[splittunnel][process]")
{
    auto registry = makeProcessRegistry();
    REQUIRE(registry->start().isOk());
    // PID 0xFFFFFFF0 is not a real process.
    REQUIRE_FALSE(registry->imagePathFor(0xFFFFFFF0).has_value());
}

TEST_CASE("effectiveRuleTargetFor resolves the process or a parent",
          "[splittunnel][process]")
{
    auto registry = makeProcessRegistry();
    REQUIRE(registry->start().isOk());

    auto target = registry->effectiveRuleTargetFor(::GetCurrentProcessId());
    REQUIRE(target.has_value());
    REQUIRE_FALSE(target->empty());
}

TEST_CASE("running processes include this one", "[splittunnel][process]")
{
    auto registry = makeProcessRegistry();
    REQUIRE(registry->start().isOk());

    auto processes = registry->runningProcesses();
    REQUIRE(processes.isOk());
    REQUIRE(processes.value().size() > 1); // at least us and System

    const ProcessId self = ::GetCurrentProcessId();
    const bool foundSelf =
        std::any_of(processes.value().begin(), processes.value().end(),
                    [self](const ProcessInfo& p) { return p.pid == self; });
    REQUIRE(foundSelf);

    // Every entry has a display name. (PID 0 is the legitimate System Idle
    // Process, so pid is not required to be non-zero.)
    for (const auto& process : processes.value()) {
        REQUIRE_FALSE(process.displayName.empty());
    }
}

TEST_CASE("installed applications is a coherent, sorted list",
          "[splittunnel][process]")
{
    auto registry = makeProcessRegistry();
    auto apps = registry->installedApplications();
    REQUIRE(apps.isOk());

    // Whatever is installed, every returned entry is a named .exe and the list
    // is de-duplicated and sorted by name (case-insensitive).
    std::string previous;
    for (const auto& app : apps.value()) {
        REQUIRE_FALSE(app.displayName.empty());
        // The image path is an .exe (case-insensitively - DisplayIcon casing
        // varies).
        REQUIRE(str::endsWith(str::toLower(app.imagePath), ".exe"));
        const std::string lowered = str::toLower(app.displayName);
        // Non-decreasing order.
        REQUIRE(previous <= lowered);
        previous = lowered;
    }
}

TEST_CASE("icon extraction is deferred to the UI", "[splittunnel][process]")
{
    auto registry = makeProcessRegistry();
    auto icon = registry->iconFor("C:\\Windows\\explorer.exe");
    REQUIRE(icon.isError());
    REQUIRE(icon.status().code() == ErrorCode::NotImplemented);
}
