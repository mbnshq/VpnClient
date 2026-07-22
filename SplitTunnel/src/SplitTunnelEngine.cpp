#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/SplitTunnel/SplitTunnelEngine.h>

namespace nova::splittunnel {

std::string_view toString(SplitMode mode) noexcept
{
    switch (mode) {
    case SplitMode::Include: return "include";
    case SplitMode::Exclude: return "exclude";
    }
    return "unknown";
}

bool parseSplitMode(std::string_view text, SplitMode& out) noexcept
{
    if (str::equalsIgnoreCase(text, "include") || str::equalsIgnoreCase(text, "allowlist")) {
        out = SplitMode::Include;
        return true;
    }
    if (str::equalsIgnoreCase(text, "exclude") || str::equalsIgnoreCase(text, "blocklist")) {
        out = SplitMode::Exclude;
        return true;
    }
    return false;
}

} // namespace nova::splittunnel
