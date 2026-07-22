// Micro-benchmarks for the hot paths - the code that runs per packet, per
// route decision, per IPC frame. Run them with:
//   novavpn_unit_tests.exe "[!benchmark]" --benchmark-samples 50
// They are tagged [!benchmark] so they are skipped in a normal test run and
// only execute when explicitly selected.
#include <NovaVPN/Core/Json.h>
#include <NovaVPN/Networking/IpAddress.h>
#include <NovaVPN/Routing/RoutingRules.h>
#include <NovaVPN/Services/IpcProtocol.h>

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

using namespace nova;

TEST_CASE("benchmark: IPv4 address parsing", "[!benchmark]")
{
    BENCHMARK("parse 192.168.1.1")
    {
        return net::IpAddress::parse("192.168.1.1");
    };
    BENCHMARK("parse 2001:db8::1")
    {
        return net::IpAddress::parse("2001:db8::1");
    };
}

TEST_CASE("benchmark: routing decision", "[!benchmark]")
{
    // A policy of the size a real split-tunnel config reaches.
    routing::RoutingPolicy policy;
    policy.defaultDisposition = routing::Disposition::Tunnel;
    for (int i = 0; i < 64; ++i) {
        routing::IpRule rule;
        rule.id = "r" + std::to_string(i);
        rule.range = net::IpRange::parse("10." + std::to_string(i) + ".0.0/16").value();
        rule.disposition = routing::Disposition::Direct;
        policy.ipRules.push_back(rule);
    }
    for (int i = 0; i < 32; ++i) {
        routing::DomainRule rule;
        rule.id = "d" + std::to_string(i);
        rule.pattern = "*.site" + std::to_string(i) + ".com";
        rule.disposition = routing::Disposition::Direct;
        policy.domainRules.push_back(rule);
    }
    routing::PolicyEvaluator evaluator{policy};
    const auto address = net::IpAddress::parse("10.40.5.7").value();

    BENCHMARK("evaluate IP against 64 rules")
    {
        return evaluator.evaluateAddress(address);
    };
    BENCHMARK("evaluate domain against 32 rules")
    {
        return evaluator.evaluateDomain("www.site20.com");
    };
}

TEST_CASE("benchmark: IPC frame encode/decode", "[!benchmark]")
{
    ipc::Request request;
    request.id = 42;
    request.method = ipc::Method::Connect;
    request.params = Json{{"profileId", "hk-01"}, {"username", "user"}};

    BENCHMARK("encode + frame a request")
    {
        return ipc::frame(ipc::encode(request));
    };

    const auto framed = ipc::frame(ipc::encode(request)).value();
    BENCHMARK("parse + decode a request")
    {
        auto json = ipc::parseFrame(std::span{framed}.subspan(4));
        return ipc::decodeRequest(json.value());
    };
}

TEST_CASE("benchmark: JSON round-trip", "[!benchmark]")
{
    const std::string doc =
        R"({"name":"HK","remotes":[{"host":"hk1.example.net","port":1194}],"mtu":1420})";

    BENCHMARK("parse a small profile document")
    {
        return json::parse(doc);
    };
}
