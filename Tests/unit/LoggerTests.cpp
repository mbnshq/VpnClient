#include <NovaVPN/Core/Json.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Logs/Sink.h>

#include <catch2/catch_test_macros.hpp>

#include <memory>

using namespace nova;
using namespace nova::logs;

TEST_CASE("levels and channels round-trip through text", "[logs]")
{
    Level level = Level::Info;
    REQUIRE(parseLevel("debug", level));
    REQUIRE(level == Level::Debug);
    REQUIRE(parseLevel("WARNING", level));
    REQUIRE(level == Level::Warn);
    REQUIRE(parseLevel("verbose", level));
    REQUIRE(level == Level::Trace);
    REQUIRE_FALSE(parseLevel("chatty", level));

    REQUIRE(toString(Level::Fatal) == "fatal");

    Channel channel = Channel::Core;
    REQUIRE(parseChannel("splittunnel", channel));
    REQUIRE(channel == Channel::SplitTunnel);
    REQUIRE_FALSE(parseChannel("nope", channel));
    REQUIRE(toString(Channel::Firewall) == "firewall");
}

TEST_CASE("text formatting includes level, channel, message and fields", "[logs]")
{
    LogRecord record;
    record.level   = Level::Warn;
    record.channel = Channel::Tunnel;
    record.message = "reconnecting";
    record.fields.push_back({"attempt", "3"});
    record.fields.push_back({"profile", "HK-01"});

    const std::string text = formatText(record);

    REQUIRE(text.find("WARN") != std::string::npos);
    REQUIRE(text.find("[tunnel]") != std::string::npos);
    REQUIRE(text.find("reconnecting") != std::string::npos);
    REQUIRE(text.find("{attempt=3 profile=HK-01}") != std::string::npos);
}

TEST_CASE("JSON formatting emits one parseable object", "[logs]")
{
    LogRecord record;
    record.level     = Level::Error;
    record.channel   = Channel::Firewall;
    record.message   = "filter apply failed";
    record.sessionId = "session-1";
    record.fields.push_back({"layer", "ALE_AUTH_CONNECT_V4"});

    const auto parsed = json::parse(formatJsonLine(record));
    REQUIRE(parsed.isOk());

    const Json& value = parsed.value();
    REQUIRE(value["level"] == "error");
    REQUIRE(value["channel"] == "firewall");
    REQUIRE(value["msg"] == "filter apply failed");
    REQUIRE(value["session"] == "session-1");
    REQUIRE(value["fields"]["layer"] == "ALE_AUTH_CONNECT_V4");
}

TEST_CASE("timestamps are ISO-8601 UTC with milliseconds", "[logs]")
{
    const std::string text = formatTimestamp(SystemClock::now());

    REQUIRE(text.size() == 24);
    REQUIRE(text[4] == '-');
    REQUIRE(text[10] == 'T');
    REQUIRE(text[19] == '.');
    REQUIRE(text.back() == 'Z');
}

TEST_CASE("the ring buffer keeps the newest records in order", "[logs]")
{
    RingBufferSink sink{4};

    for (int i = 0; i < 6; ++i) {
        LogRecord record;
        record.message = std::to_string(i);
        sink.write(record);
    }

    const auto snapshot = sink.snapshot();
    REQUIRE(snapshot.size() == 4);
    REQUIRE(snapshot.front().message == "2");
    REQUIRE(snapshot.back().message == "5");

    sink.clear();
    REQUIRE(sink.snapshot().empty());
}

TEST_CASE("the ring buffer handles a partial fill", "[logs]")
{
    RingBufferSink sink{8};

    LogRecord record;
    record.message = "only one";
    sink.write(record);

    const auto snapshot = sink.snapshot();
    REQUIRE(snapshot.size() == 1);
    REQUIRE(snapshot.front().message == "only one");
}

TEST_CASE("the logger delivers records to its sinks", "[logs]")
{
    auto ring = std::make_shared<RingBufferSink>(64, Level::Trace);

    LoggerOptions options;
    options.minimumLevel = Level::Debug;
    Logger logger{options};
    logger.addSink(ring);

    LogRecord record;
    record.timestamp = SystemClock::now();
    record.level     = Level::Info;
    record.channel   = Channel::Service;
    record.message   = "hello";
    REQUIRE(logger.submit(std::move(record)));

    logger.flush();

    const auto snapshot = ring->snapshot();
    REQUIRE(snapshot.size() == 1);
    REQUIRE(snapshot.front().message == "hello");
    REQUIRE(logger.droppedCount() == 0);
}

TEST_CASE("level thresholds gate at the call site", "[logs]")
{
    Logger logger{LoggerOptions{Level::Warn}};

    REQUIRE_FALSE(logger.isEnabled(Level::Info, Channel::Core));
    REQUIRE(logger.isEnabled(Level::Error, Channel::Core));

    // A per-channel override silences one subsystem without touching the rest.
    logger.setChannelLevel(Channel::Tunnel, Level::Off);
    REQUIRE_FALSE(logger.isEnabled(Level::Fatal, Channel::Tunnel));
    REQUIRE(logger.isEnabled(Level::Error, Channel::Firewall));

    logger.setMinimumLevel(Level::Trace);
    logger.setChannelLevel(Channel::Tunnel, Level::Trace);
    REQUIRE(logger.isEnabled(Level::Trace, Channel::Tunnel));
}

TEST_CASE("the queue drops rather than blocking when full", "[logs]")
{
    // A tiny queue plus a sink that cannot drain instantly is the shape of the
    // back-pressure case the tunnel data path must survive.
    LoggerOptions options;
    options.minimumLevel  = Level::Trace;
    options.queueCapacity = 4;

    Logger logger{options};

    u64 submitted = 0;
    for (int i = 0; i < 4096; ++i) {
        LogRecord record;
        record.timestamp = SystemClock::now();
        record.message   = "flood";
        if (logger.submit(std::move(record))) {
            ++submitted;
        }
    }

    logger.flush();
    // Whatever the split, nothing may be lost silently: every non-submitted
    // record is counted.
    REQUIRE(submitted + logger.droppedCount() == 4096);
}

TEST_CASE("RecordBuilder attaches typed fields and statuses", "[logs]")
{
    auto ring = std::make_shared<RingBufferSink>(16, Level::Trace);

    LoggerOptions options;
    options.minimumLevel = Level::Trace;
    Logger logger{options};
    logger.addSink(ring);

    {
        RecordBuilder builder{logger, Level::Error, Channel::Dns, "resolve failed",
                              SourceLocation{__FILE__, __LINE__, __func__}};
        builder.field("host", "hk1.example.net")
            .field("attempts", 3)
            .field("cached", false)
            .field("elapsed", 12.5)
            .status(Status{ErrorCode::DnsFailure, "SERVFAIL", 9002})
            .secret("token", "abcdef123456");
    }

    logger.flush();

    const auto snapshot = ring->snapshot();
    REQUIRE(snapshot.size() == 1);

    const auto& record = snapshot.front();
    REQUIRE(record.message == "resolve failed");
    REQUIRE(record.channel == Channel::Dns);

    const auto fieldValue = [&record](std::string_view key) -> std::string {
        for (const auto& field : record.fields) {
            if (field.key == key) {
                return field.value;
            }
        }
        return {};
    };

    REQUIRE(fieldValue("host") == "hk1.example.net");
    REQUIRE(fieldValue("attempts") == "3");
    REQUIRE(fieldValue("cached") == "false");
    REQUIRE(fieldValue("error") == "DnsFailure");
    REQUIRE(fieldValue("detail") == "SERVFAIL");
    REQUIRE(fieldValue("platform") == "9002");

    // The secret must never appear in full.
    REQUIRE(fieldValue("token") == "ab********56");
}

TEST_CASE("a disabled record costs nothing and emits nothing", "[logs]")
{
    auto ring = std::make_shared<RingBufferSink>(16, Level::Trace);

    Logger logger{LoggerOptions{Level::Error}};
    logger.addSink(ring);

    {
        RecordBuilder builder{logger, Level::Debug, Channel::Core, "noise",
                              SourceLocation{__FILE__, __LINE__, __func__}};
        builder.field("key", "value");
    }

    logger.flush();
    REQUIRE(ring->snapshot().empty());
}

TEST_CASE("the thread session id tags records", "[logs]")
{
    Logger::setThreadSessionId("connect-42");
    REQUIRE(Logger::threadSessionId() == "connect-42");

    Logger::setThreadSessionId("");
    REQUIRE(Logger::threadSessionId().empty());
}
