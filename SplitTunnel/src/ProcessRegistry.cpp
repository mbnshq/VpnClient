#include <NovaVPN/Core/Handle.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/SplitTunnel/ProcessRegistry.h>

#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <mutex>
#include <unordered_map>

#pragma comment(lib, "advapi32.lib")

using nova::logs::Channel;

namespace nova::splittunnel {
namespace {

struct SnapshotTraits {
    using value_type = HANDLE;
    static value_type invalid() noexcept { return INVALID_HANDLE_VALUE; }
    static void close(value_type handle) noexcept { ::CloseHandle(handle); }
};
using SnapshotHandle = win::UniqueResource<SnapshotTraits>;

struct ProcessTraits {
    using value_type = HANDLE;
    static value_type invalid() noexcept { return nullptr; }
    static void close(value_type handle) noexcept { ::CloseHandle(handle); }
};
using ProcessAccessHandle = win::UniqueResource<ProcessTraits>;

/// Resolves a PID to its full image path. Returns empty (not an error) when the
/// process is protected, gone, or owned by another user we cannot open - the
/// caller treats "unknown path" as "no matching rule".
std::string imagePathOf(ProcessId pid)
{
    if (pid == 0) {
        return {};
    }
    ProcessAccessHandle process{
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!process) {
        return {};
    }

    std::array<wchar_t, 32768> buffer{};
    DWORD size = static_cast<DWORD>(buffer.size());
    if (::QueryFullProcessImageNameW(process.get(), 0, buffer.data(), &size) == FALSE) {
        return {};
    }
    return win::toUtf8(std::wstring_view{buffer.data(), size});
}

class WindowsProcessRegistry final : public IProcessRegistry {
public:
    Status start() override
    {
        // A full ETW session is the eventual source of truth (it catches
        // short-lived processes); the toolhelp snapshot used here is enough for
        // the picker and the diagnostics view and needs no elevation. Seed the
        // cache so imagePathFor() has data immediately.
        refreshSnapshot();
        m_running = true;
        NOVA_LOG_INFO(Channel::SplitTunnel, "process registry started");
        return Status::ok();
    }

    void stop() override { m_running = false; }

    std::optional<std::string> imagePathFor(ProcessId pid) const override
    {
        {
            std::lock_guard lock{m_mutex};
            if (const auto it = m_pidToPath.find(pid); it != m_pidToPath.end()) {
                return it->second;
            }
        }
        // Not cached - resolve live and cache the answer.
        std::string path = imagePathOf(pid);
        if (path.empty()) {
            return std::nullopt;
        }
        std::lock_guard lock{m_mutex};
        m_pidToPath[pid] = path;
        return path;
    }

    std::optional<std::string> effectiveRuleTargetFor(ProcessId pid) const override
    {
        // Walk the parent chain so a rule with includeChildren covers helpers.
        std::unordered_map<ProcessId, ProcessId> parents;
        {
            std::lock_guard lock{m_mutex};
            parents = m_pidToParent;
        }

        ProcessId current = pid;
        for (int depth = 0; depth < 32 && current != 0; ++depth) {
            if (auto path = imagePathFor(current); path.has_value()) {
                return path;
            }
            const auto it = parents.find(current);
            if (it == parents.end() || it->second == current) {
                break;
            }
            current = it->second;
        }
        return std::nullopt;
    }

    Result<std::vector<ProcessInfo>> runningProcesses() const override
    {
        SnapshotHandle snapshot{::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
        if (!snapshot) {
            return win::lastError("CreateToolhelp32Snapshot");
        }

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (::Process32FirstW(snapshot.get(), &entry) == FALSE) {
            return win::lastError("Process32First");
        }

        std::vector<ProcessInfo> processes;
        do {
            ProcessInfo info;
            info.pid       = entry.th32ProcessID;
            info.parentPid = entry.th32ParentProcessID;
            info.imagePath = imagePathOf(entry.th32ProcessID);
            info.displayName =
                info.imagePath.empty()
                    ? win::toUtf8(entry.szExeFile)
                    : std::filesystem::path{info.imagePath}.filename().string();
            processes.push_back(std::move(info));
        } while (::Process32NextW(snapshot.get(), &entry) != FALSE);

        return processes;
    }

    Result<std::vector<InstalledApplication>> installedApplications() override
    {
        std::vector<InstalledApplication> apps;
        std::unordered_map<std::string, bool> seen; // dedupe by lowercased path

        // The uninstall keys are the canonical list of installed desktop
        // programs; DisplayIcon usually points at the main executable.
        for (const HKEY root : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
            for (const wchar_t* subkey :
                 {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                  L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"}) {
                readUninstallKey(root, subkey, apps, seen);
            }
        }

        std::sort(apps.begin(), apps.end(),
                  [](const InstalledApplication& a, const InstalledApplication& b) {
                      return str::toLower(a.displayName) < str::toLower(b.displayName);
                  });
        return apps;
    }

    Result<std::vector<u8>> iconFor(const std::string& imagePath) override
    {
        // Icon extraction is a UI concern handled by the app layer via the
        // shell; the service does not carry the imaging stack. Report it as not
        // implemented here rather than returning a bogus blob.
        (void)imagePath;
        return err::notImplemented("icon extraction is performed in the UI process");
    }

private:
    void refreshSnapshot()
    {
        SnapshotHandle snapshot{::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
        if (!snapshot) {
            return;
        }
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (::Process32FirstW(snapshot.get(), &entry) == FALSE) {
            return;
        }

        std::unordered_map<ProcessId, ProcessId> parents;
        do {
            parents[entry.th32ProcessID] = entry.th32ParentProcessID;
        } while (::Process32NextW(snapshot.get(), &entry) != FALSE);

        std::lock_guard lock{m_mutex};
        m_pidToParent = std::move(parents);
    }

    static std::string readRegString(HKEY key, const wchar_t* value)
    {
        wchar_t buffer[1024]{};
        DWORD size = sizeof(buffer);
        DWORD type = 0;
        if (::RegQueryValueExW(key, value, nullptr, &type,
                               reinterpret_cast<LPBYTE>(buffer), &size) != ERROR_SUCCESS) {
            return {};
        }
        if (type != REG_SZ && type != REG_EXPAND_SZ) {
            return {};
        }
        return win::toUtf8(buffer);
    }

    void readUninstallKey(HKEY root, const wchar_t* path,
                          std::vector<InstalledApplication>& apps,
                          std::unordered_map<std::string, bool>& seen)
    {
        HKEY uninstall = nullptr;
        if (::RegOpenKeyExW(root, path, 0, KEY_READ | KEY_WOW64_64KEY, &uninstall) !=
            ERROR_SUCCESS) {
            return;
        }

        DWORD index = 0;
        wchar_t nameBuffer[256]{};
        DWORD nameSize = static_cast<DWORD>(std::size(nameBuffer));
        while (::RegEnumKeyExW(uninstall, index, nameBuffer, &nameSize, nullptr, nullptr,
                               nullptr, nullptr) == ERROR_SUCCESS) {
            ++index;
            nameSize = static_cast<DWORD>(std::size(nameBuffer));

            HKEY entry = nullptr;
            if (::RegOpenKeyExW(uninstall, nameBuffer, 0, KEY_READ, &entry) != ERROR_SUCCESS) {
                continue;
            }

            const std::string displayName = readRegString(entry, L"DisplayName");
            const std::string systemComponent = readRegString(entry, L"SystemComponent");
            if (displayName.empty() || systemComponent == "1") {
                ::RegCloseKey(entry);
                continue;
            }

            InstalledApplication app;
            app.displayName = displayName;
            app.publisher   = readRegString(entry, L"Publisher");
            app.version     = readRegString(entry, L"DisplayVersion");

            // Prefer DisplayIcon (often the main exe), fall back to the install
            // location - both give the app picker a path to match rules against.
            std::string icon = readRegString(entry, L"DisplayIcon");
            const std::size_t comma = icon.find_last_of(',');
            if (comma != std::string::npos) {
                icon.resize(comma); // strip ",<icon index>"
            }
            app.imagePath = icon;

            ::RegCloseKey(entry);

            if (app.imagePath.empty() ||
                !str::endsWith(str::toLower(app.imagePath), ".exe")) {
                continue;
            }
            const std::string key = str::toLower(app.imagePath);
            if (seen.count(key) != 0) {
                continue;
            }
            seen[key] = true;
            apps.push_back(std::move(app));
        }
        ::RegCloseKey(uninstall);
    }

    mutable std::mutex m_mutex;
    bool               m_running = false;
    mutable std::unordered_map<ProcessId, std::string> m_pidToPath;
    std::unordered_map<ProcessId, ProcessId>           m_pidToParent;
};

} // namespace

ProcessRegistryPtr makeProcessRegistry()
{
    return std::make_shared<WindowsProcessRegistry>();
}

} // namespace nova::splittunnel
