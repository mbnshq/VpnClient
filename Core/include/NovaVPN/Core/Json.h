// NovaVPN - Core/Json.h
// The single place nlohmann/json enters the codebase. Modules use nova::Json
// and the helpers below rather than including the third-party header directly,
// so the dependency can be swapped without touching call sites.
#pragma once

#include <NovaVPN/Core/Result.h>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>
#include <string_view>

namespace nova {

using Json = nlohmann::json;

namespace json {

/// Parses UTF-8 text. Never throws: parse failures come back as ParseError with
/// the offending byte offset in the message.
[[nodiscard]] Result<Json> parse(std::string_view text);

/// Reads and parses a JSON file.
[[nodiscard]] Result<Json> readFile(const std::filesystem::path& path);

/// Serialises and writes atomically (see file::writeAtomicText).
[[nodiscard]] Status writeFile(const std::filesystem::path& path, const Json& value,
                               int indent = 2);

/// Reads `pointer` ("/dns/servers/0", RFC 6901) and returns `fallback` when the
/// path is missing or the value has the wrong type. Never throws.
template <typename T>
[[nodiscard]] T get(const Json& root, std::string_view pointer, T fallback)
{
    try {
        const Json::json_pointer jp{std::string{pointer}};
        if (!root.contains(jp)) {
            return fallback;
        }
        return root.at(jp).get<T>();
    } catch (const Json::exception&) {
        return fallback;
    }
}

/// Like get() but reports a missing or ill-typed value as an error, for fields
/// that have no sensible default.
template <typename T>
[[nodiscard]] Result<T> require(const Json& root, std::string_view pointer)
{
    try {
        const Json::json_pointer jp{std::string{pointer}};
        if (!root.contains(jp)) {
            return Status{ErrorCode::ConfigMissingField,
                          "missing required field " + std::string{pointer}};
        }
        return root.at(jp).get<T>();
    } catch (const Json::exception& ex) {
        return Status{ErrorCode::ConfigInvalid,
                      "field " + std::string{pointer} + " has the wrong type: " + ex.what()};
    }
}

/// Sets `pointer`, creating intermediate objects as needed.
Status set(Json& root, std::string_view pointer, Json value);

/// Deep-merges `overlay` into `base`: objects merge recursively, every other
/// type (including arrays) replaces wholesale. This is how user settings are
/// layered over shipped defaults.
void merge(Json& base, const Json& overlay);

} // namespace json
} // namespace nova
