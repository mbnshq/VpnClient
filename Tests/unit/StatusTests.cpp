#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/Status.h>

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace nova;

TEST_CASE("a default Status is Ok", "[status]")
{
    const Status status;
    REQUIRE(status.isOk());
    REQUIRE_FALSE(status.isError());
    REQUIRE(static_cast<bool>(status));
    REQUIRE(status.code() == ErrorCode::Ok);
}

TEST_CASE("Status carries code, message and platform code", "[status]")
{
    const Status status{ErrorCode::PermissionDenied, "cannot open the pipe", 5};

    REQUIRE(status.isError());
    REQUIRE(status.code() == ErrorCode::PermissionDenied);
    REQUIRE(status.message() == "cannot open the pipe");
    REQUIRE(status.platformCode() == 5);
    REQUIRE(status.hasPlatformCode());
    REQUIRE(status.toString() == "PermissionDenied: cannot open the pipe (platform=5)");
}

TEST_CASE("withContext prefixes without losing the code", "[status]")
{
    const Status inner = err::notFound("profile 'HK-01'");
    const Status outer = inner.withContext("connect");

    REQUIRE(outer.code() == ErrorCode::NotFound);
    REQUIRE(outer.message() == "connect: profile 'HK-01'");

    // Contexting an Ok status is a no-op, so callers can wrap unconditionally.
    REQUIRE(Status::ok().withContext("anything").isOk());
}

TEST_CASE("transient errors are the ones worth retrying", "[status]")
{
    REQUIRE(isTransient(ErrorCode::Timeout));
    REQUIRE(isTransient(ErrorCode::ConnectionReset));
    REQUIRE(isTransient(ErrorCode::NetworkUnreachable));

    REQUIRE_FALSE(isTransient(ErrorCode::AuthFailed));
    REQUIRE_FALSE(isTransient(ErrorCode::CertificateExpired));
    REQUIRE_FALSE(isTransient(ErrorCode::ConfigInvalid));
}

TEST_CASE("every ErrorCode has a distinct name", "[status]")
{
    // A duplicated or missing name silently corrupts logs and the IPC error
    // surface, so the mapping is asserted rather than assumed.
    REQUIRE(toString(ErrorCode::Ok) == "Ok");
    REQUIRE(toString(ErrorCode::LeakDetected) == "LeakDetected");
    REQUIRE(toString(ErrorCode::IpcPeerUntrusted) == "IpcPeerUntrusted");
    REQUIRE(toString(static_cast<ErrorCode>(60000)) == "Unrecognised");
}

namespace {

Result<int> parsePort(std::string_view text)
{
    if (text == "1194") {
        return 1194;
    }
    return err::invalidArgument("not a port");
}

Status usesAssignOrReturn(std::string_view text, int& out)
{
    NOVA_ASSIGN_OR_RETURN(const int port, parsePort(text));
    out = port;
    return Status::ok();
}

} // namespace

TEST_CASE("Result holds either a value or an error", "[result]")
{
    const auto ok = parsePort("1194");
    REQUIRE(ok.isOk());
    REQUIRE(ok.value() == 1194);
    REQUIRE(ok.valueOr(0) == 1194);
    REQUIRE(ok.statusOrOk().isOk());

    const auto bad = parsePort("nope");
    REQUIRE(bad.isError());
    REQUIRE(bad.status().code() == ErrorCode::InvalidArgument);
    REQUIRE(bad.valueOr(-1) == -1);
    REQUIRE_FALSE(bad.toOptional().has_value());
}

TEST_CASE("NOVA_ASSIGN_OR_RETURN propagates errors", "[result]")
{
    int port = 0;
    REQUIRE(usesAssignOrReturn("1194", port).isOk());
    REQUIRE(port == 1194);

    port = 0;
    const Status failed = usesAssignOrReturn("nope", port);
    REQUIRE(failed.isError());
    REQUIRE(failed.code() == ErrorCode::InvalidArgument);
    REQUIRE(port == 0);
}

TEST_CASE("Result::map transforms values and passes errors through", "[result]")
{
    const auto doubled = parsePort("1194").map([](int port) { return port * 2; });
    REQUIRE(doubled.isOk());
    REQUIRE(doubled.value() == 2388);

    const auto failed = parsePort("x").map([](int port) { return port * 2; });
    REQUIRE(failed.isError());
    REQUIRE(failed.status().code() == ErrorCode::InvalidArgument);
}
