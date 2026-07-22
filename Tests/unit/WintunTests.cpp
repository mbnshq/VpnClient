// Wintun adapter creation requires an elevated token and the signed DLL beside
// the binary, so the live path is guarded: when the driver cannot load (no DLL,
// not elevated, or signature failure) the test asserts the error is reported
// cleanly rather than crashing, which is the contract that matters most.
#include <NovaVPN/Driver/WintunAdapter.h>
#include <NovaVPN/Services/ServiceHost.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::driver;

TEST_CASE("the driver reports a precise error when it cannot load", "[driver][wintun]")
{
    auto driver = makeWintunDriver();
    const Status loaded = driver->load();

    if (loaded.isError()) {
        // Missing or unsigned DLL must surface as an actionable driver error,
        // never a loader crash or a generic failure.
        REQUIRE((loaded.code() == ErrorCode::DriverMissing ||
                 loaded.code() == ErrorCode::DriverVersion ||
                 loaded.code() == ErrorCode::SignatureInvalid ||
                 loaded.code() == ErrorCode::PermissionDenied));
        // Operations on an unloaded driver are InvalidState, not undefined.
        REQUIRE(driver->driverVersion().status().code() == ErrorCode::InvalidState);
        return;
    }

    // The DLL loaded and its signature verified. The *running driver* version
    // is only available once an adapter has started the kernel driver, so
    // before that driverVersion() may legitimately report an error - what
    // matters is that it does so cleanly rather than faulting, and that a
    // successful query returns a non-zero version.
    auto version = driver->driverVersion();
    if (version.isOk()) {
        REQUIRE(version.value() != 0);
    } else {
        REQUIRE(version.status().code() != ErrorCode::InvalidState); // it did load
    }
}

TEST_CASE("creating an adapter requires a loaded driver", "[driver][wintun]")
{
    auto driver = makeWintunDriver();
    // Without load(), createAdapter must refuse rather than dereference a null
    // function table.
    auto adapter = driver->createAdapter("NovaVPN-Test", "NovaVPN");
    REQUIRE(adapter.isError());
    REQUIRE(adapter.status().code() == ErrorCode::InvalidState);
}

TEST_CASE("a real adapter can be created and torn down", "[driver][wintun][.integration]")
{
    // Tagged hidden ([.]) so it runs only when explicitly selected, since it
    // needs elevation and mutates the machine's adapter list.
    if (!service::isProcessElevated()) {
        SUCCEED("skipped: adapter creation requires elevation");
        return;
    }

    auto driver = makeWintunDriver();
    if (driver->load().isError()) {
        SUCCEED("skipped: wintun.dll not available");
        return;
    }

    auto adapter = driver->createAdapter("NovaVPN-Test", "NovaVPN");
    REQUIRE(adapter.isOk());
    REQUIRE(adapter.value()->info().interfaceIndex != 0);
    REQUIRE(adapter.value()->info().luid != 0);

    // A session over the adapter can be started with a valid ring size.
    auto session = adapter.value()->startSession(4 * 1024 * 1024);
    REQUIRE(session.isOk());

    // An invalid ring capacity is rejected.
    REQUIRE(adapter.value()->startSession(1234).isError());

    session.value().reset();
    adapter.value().reset();
    REQUIRE(driver->deleteAdapter("NovaVPN-Test").isOk());
}
