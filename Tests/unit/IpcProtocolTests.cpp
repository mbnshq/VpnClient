#include <NovaVPN/Core/Version.h>
#include <NovaVPN/Services/IpcProtocol.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::ipc;

TEST_CASE("requests round-trip", "[ipc]")
{
    Request request;
    request.id     = 17;
    request.method = Method::Connect;
    request.params = Json{{"profileId", "hk-01"}};

    const auto decoded = decodeRequest(encode(request));

    REQUIRE(decoded.isOk());
    REQUIRE(decoded.value().id == 17);
    REQUIRE(decoded.value().method == Method::Connect);
    REQUIRE(decoded.value().params["profileId"] == "hk-01");
}

TEST_CASE("responses round-trip in both directions", "[ipc]")
{
    const Response success = makeSuccess(9, Json{{"tunnelId", "t-1"}});
    const auto decodedSuccess = decodeResponse(encode(success));

    REQUIRE(decodedSuccess.isOk());
    REQUIRE(decodedSuccess.value().success);
    REQUIRE(decodedSuccess.value().id == 9);
    REQUIRE(decodedSuccess.value().result["tunnelId"] == "t-1");

    const Response failure =
        makeError(10, Status{ErrorCode::AuthFailed, "bad password", 1326});
    const auto decodedFailure = decodeResponse(encode(failure));

    REQUIRE(decodedFailure.isOk());
    REQUIRE_FALSE(decodedFailure.value().success);
    REQUIRE(decodedFailure.value().errorCode == ErrorCode::AuthFailed);
    REQUIRE(decodedFailure.value().errorMessage == "bad password");
    REQUIRE(decodedFailure.value().platformCode == 1326);
}

TEST_CASE("events round-trip", "[ipc]")
{
    Event event;
    event.kind    = EventKind::TunnelStateChanged;
    event.payload = Json{{"tunnelId", "t-1"}, {"state", "Connected"}};

    const auto decoded = decodeEvent(encode(event));

    REQUIRE(decoded.isOk());
    REQUIRE(decoded.value().kind == EventKind::TunnelStateChanged);
    REQUIRE(decoded.value().payload["state"] == "Connected");
}

TEST_CASE("a protocol mismatch is reported as ServiceVersion", "[ipc][compat]")
{
    Json frame = encode(Request{1, Method::Hello, Json::object()});
    frame["protocol"] = version::kIpcProtocol + 1;

    const auto decoded = decodeRequest(frame);
    REQUIRE(decoded.isError());
    REQUIRE(decoded.status().code() == ErrorCode::ServiceVersion);
}

TEST_CASE("malformed frames are rejected precisely", "[ipc][security]")
{
    REQUIRE(decodeRequest(Json::array()).status().code() == ErrorCode::IpcProtocol);

    Json wrongType = encode(Event{});
    REQUIRE(decodeRequest(wrongType).isError());

    Json noId = encode(Request{0, Method::Hello, Json::object()});
    REQUIRE(decodeRequest(noId).isError());

    // An unknown method must not be cast into the enum: that would be UB and,
    // worse, could land on a privileged handler.
    Json unknownMethod = encode(Request{1, Method::Hello, Json::object()});
    unknownMethod["method"] = 60000;
    REQUIRE(decodeRequest(unknownMethod).status().code() == ErrorCode::IpcProtocol);

    Json badParams = encode(Request{1, Method::Hello, Json::object()});
    badParams["params"] = "not an object";
    REQUIRE(decodeRequest(badParams).isError());

    Json unknownEvent = encode(Event{});
    unknownEvent["event"] = 60000;
    REQUIRE(decodeEvent(unknownEvent).isError());
}

TEST_CASE("framing prefixes a little-endian length", "[ipc][framing]")
{
    const Json value{{"a", 1}};
    const auto framed = frame(value);

    REQUIRE(framed.isOk());
    REQUIRE(framed.value().size() > 4);

    const auto length = readFrameLength(framed.value());
    REQUIRE(length.isOk());
    REQUIRE(length.value() == framed.value().size() - 4);

    const auto parsed = parseFrame(
        std::span{framed.value()}.subspan(4));
    REQUIRE(parsed.isOk());
    REQUIRE(parsed.value()["a"] == 1);
}

TEST_CASE("oversized and empty frames are refused before allocation",
          "[ipc][framing][security]")
{
    // A hostile client announcing a huge frame must be rejected on the prefix
    // alone, without the service reserving the buffer.
    const std::array<u8, 4> huge{0xFF, 0xFF, 0xFF, 0x7F};
    REQUIRE(readFrameLength(huge).isError());

    const std::array<u8, 4> empty{0, 0, 0, 0};
    REQUIRE(readFrameLength(empty).isError());

    const std::array<u8, 2> truncated{0, 0};
    REQUIRE(readFrameLength(truncated).isError());
}

TEST_CASE("a frame at the limit is accepted", "[ipc][framing]")
{
    const std::array<u8, 4> atLimit{
        static_cast<u8>(kMaxFrameBytes & 0xFF),
        static_cast<u8>((kMaxFrameBytes >> 8) & 0xFF),
        static_cast<u8>((kMaxFrameBytes >> 16) & 0xFF),
        static_cast<u8>((kMaxFrameBytes >> 24) & 0xFF)};

    const auto length = readFrameLength(atLimit);
    REQUIRE(length.isOk());
    REQUIRE(length.value() == kMaxFrameBytes);
}

TEST_CASE("hello negotiation round-trips", "[ipc][handshake]")
{
    HelloParams params;
    params.protocolVersion = version::kIpcProtocol;
    params.clientVersion   = std::string{version::kString};
    params.clientName      = "NovaVPN.App";

    const auto decodedParams = decodeHelloParams(encode(params));
    REQUIRE(decodedParams.isOk());
    REQUIRE(decodedParams.value().protocolVersion == version::kIpcProtocol);
    REQUIRE(decodedParams.value().clientName == "NovaVPN.App");

    HelloResult result;
    result.protocolVersion       = version::kIpcProtocol;
    result.serviceVersion        = std::string{version::kString};
    result.callerIsAdministrator = true;
    result.uptime                = Seconds{3600};

    const auto decodedResult = decodeHelloResult(encode(result));
    REQUIRE(decodedResult.isOk());
    REQUIRE(decodedResult.value().callerIsAdministrator);
    REQUIRE(decodedResult.value().uptime == Seconds{3600});

    REQUIRE(decodeHelloParams(Json::object()).isError());
}

TEST_CASE("privileged methods are enumerated deliberately",
          "[ipc][security]")
{
    // Anything that changes where the machine's traffic goes requires an
    // elevated caller; read-only methods must not.
    REQUIRE(requiresAdministrator(Method::SetFirewallPolicy));
    REQUIRE(requiresAdministrator(Method::SetRoutingPolicy));
    REQUIRE(requiresAdministrator(Method::SetSplitTunnelConfig));
    REQUIRE(requiresAdministrator(Method::ImportOvpn));
    REQUIRE(requiresAdministrator(Method::DeleteProfile));
    REQUIRE(requiresAdministrator(Method::InstallUpdate));

    REQUIRE_FALSE(requiresAdministrator(Method::Hello));
    REQUIRE_FALSE(requiresAdministrator(Method::ListProfiles));
    REQUIRE_FALSE(requiresAdministrator(Method::Connect));
    REQUIRE_FALSE(requiresAdministrator(Method::Disconnect));
    REQUIRE_FALSE(requiresAdministrator(Method::GetStatistics));
    REQUIRE_FALSE(requiresAdministrator(Method::GetLogs));
}

TEST_CASE("method and event names are stable", "[ipc]")
{
    REQUIRE(toString(Method::Connect) == "Connect");
    REQUIRE(toString(Method::ExportSupportBundle) == "ExportSupportBundle");
    REQUIRE(toString(EventKind::StatisticsTick) == "StatisticsTick");
    REQUIRE(toString(static_cast<Method>(60000)) == "Unknown");
}
