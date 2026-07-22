#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Updater/Updater.h>

namespace nova::updater {

std::string_view toString(Channel channel) noexcept
{
    switch (channel) {
    case Channel::Stable: return "stable";
    case Channel::Beta:   return "beta";
    case Channel::Dev:    return "dev";
    }
    return "unknown";
}

bool parseChannel(std::string_view text, Channel& out) noexcept
{
    if (str::equalsIgnoreCase(text, "stable")) {
        out = Channel::Stable;
        return true;
    }
    if (str::equalsIgnoreCase(text, "beta")) {
        out = Channel::Beta;
        return true;
    }
    if (str::equalsIgnoreCase(text, "dev") || str::equalsIgnoreCase(text, "nightly")) {
        out = Channel::Dev;
        return true;
    }
    return false;
}

} // namespace nova::updater
