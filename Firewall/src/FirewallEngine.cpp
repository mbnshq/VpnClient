#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Firewall/FirewallEngine.h>

namespace nova::firewall {

std::string_view toString(KillSwitchMode mode) noexcept
{
    switch (mode) {
    case KillSwitchMode::Off:  return "off";
    case KillSwitchMode::Soft: return "soft";
    case KillSwitchMode::Hard: return "hard";
    }
    return "unknown";
}

bool parseKillSwitchMode(std::string_view text, KillSwitchMode& out) noexcept
{
    if (str::equalsIgnoreCase(text, "off") || str::equalsIgnoreCase(text, "disabled")) {
        out = KillSwitchMode::Off;
        return true;
    }
    if (str::equalsIgnoreCase(text, "soft")) {
        out = KillSwitchMode::Soft;
        return true;
    }
    if (str::equalsIgnoreCase(text, "hard") || str::equalsIgnoreCase(text, "always")) {
        out = KillSwitchMode::Hard;
        return true;
    }
    return false;
}

} // namespace nova::firewall
