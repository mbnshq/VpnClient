#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/Json.h>

namespace nova::json {

Result<Json> parse(std::string_view text)
{
    // nlohmann's non-throwing overload returns a discarded value on failure; we
    // use the throwing form to keep the diagnostic (byte offset + reason) and
    // convert it at this single boundary.
    try {
        return Json::parse(text, nullptr, /*allow_exceptions=*/true, /*ignore_comments=*/true);
    } catch (const Json::parse_error& ex) {
        return Status{ErrorCode::ParseError,
                      std::string{"JSON parse error at byte "} + std::to_string(ex.byte) + ": " +
                          ex.what()};
    } catch (const Json::exception& ex) {
        return Status{ErrorCode::ParseError, std::string{"JSON error: "} + ex.what()};
    }
}

Result<Json> readFile(const std::filesystem::path& path)
{
    NOVA_ASSIGN_OR_RETURN(auto text, file::readText(path));
    auto parsed = parse(text);
    if (parsed.isError()) {
        return std::move(parsed).status().withContext(path.string());
    }
    return std::move(parsed).value();
}

Status writeFile(const std::filesystem::path& path, const Json& value, int indent)
{
    try {
        const std::string text = value.dump(indent);
        return file::writeAtomicText(path, text);
    } catch (const Json::exception& ex) {
        return Status{ErrorCode::SerializationError,
                      std::string{"failed to serialise "} + path.string() + ": " + ex.what()};
    }
}

Status set(Json& root, std::string_view pointer, Json value)
{
    try {
        const Json::json_pointer jp{std::string{pointer}};
        root[jp] = std::move(value);
        return Status::ok();
    } catch (const Json::exception& ex) {
        return Status{ErrorCode::SerializationError,
                      "cannot set " + std::string{pointer} + ": " + ex.what()};
    }
}

void merge(Json& base, const Json& overlay)
{
    if (!base.is_object() || !overlay.is_object()) {
        base = overlay;
        return;
    }

    for (auto it = overlay.begin(); it != overlay.end(); ++it) {
        if (it->is_object() && base.contains(it.key()) && base[it.key()].is_object()) {
            merge(base[it.key()], *it);
        } else {
            base[it.key()] = *it;
        }
    }
}

} // namespace nova::json
