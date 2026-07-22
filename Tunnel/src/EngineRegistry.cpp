#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Tunnel/Engine.h>

#include <Windows.h>
#include <wintrust.h>
#include <softpub.h>

#include <mutex>
#include <system_error>
#include <unordered_map>

#pragma comment(lib, "wintrust.lib")

using nova::logs::Channel;

namespace nova::tunnel {
namespace {

/// Verifies a plugin DLL's Authenticode signature - the same gate Wintun uses,
/// because a plugin runs inside the SYSTEM service with full engine privileges.
Status verifyPluginSignature(const std::filesystem::path& path)
{
    const std::wstring widePath = path.wstring();

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct      = sizeof(fileInfo);
    fileInfo.pcwszFilePath = widePath.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData{};
    trustData.cbStruct            = sizeof(trustData);
    trustData.dwUIChoice          = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice       = WTD_CHOICE_FILE;
    trustData.pFile               = &fileInfo;
    trustData.dwStateAction       = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags         = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_NONE;

    const LONG result = ::WinVerifyTrust(nullptr, &action, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(nullptr, &action, &trustData);

    if (result != ERROR_SUCCESS) {
        return Status{ErrorCode::SignatureInvalid,
                      "plugin signature verification failed: " + path.string(),
                      static_cast<u32>(result)};
    }
    return Status::ok();
}

/// A loaded plugin module and the engine ids it advertises. The module is held
/// for the registry's lifetime; engines created from it must not outlive it.
struct LoadedPlugin {
    HMODULE          module = nullptr;
    EngineFactoryFn  factory = nullptr;
    std::filesystem::path path;

    ~LoadedPlugin()
    {
        if (module != nullptr) {
            ::FreeLibrary(module);
        }
    }
};

class EngineRegistry final : public IMutableEngineRegistry {
public:
    explicit EngineRegistry(bool requireSignedPlugins)
        : m_requireSigned(requireSignedPlugins)
    {
    }

    Status registerBuiltin(std::string engineId, BuiltinEngineFactory factory) override
    {
        if (engineId.empty() || !factory) {
            return err::invalidArgument("built-in engine needs an id and a factory");
        }
        std::lock_guard lock{m_mutex};
        const std::string key = str::toLower(engineId);
        if (m_builtins.count(key) != 0) {
            return err::alreadyExists("engine '" + engineId + "' is already registered");
        }
        m_builtins.emplace(key, std::move(factory));
        NOVA_LOG_INFO(Channel::Plugin, "registered built-in engine").field("engine", engineId);
        return Status::ok();
    }

    Result<VpnEnginePtr> create(std::string_view engineId) override
    {
        const std::string key = str::toLower(std::string{engineId});

        std::lock_guard lock{m_mutex};

        // Built-ins win over plugins: a plugin can never shadow a shipped engine.
        if (const auto it = m_builtins.find(key); it != m_builtins.end()) {
            VpnEnginePtr engine = it->second();
            if (!engine) {
                return Status{ErrorCode::Unavailable,
                              "built-in engine '" + std::string{engineId} +
                                  "' factory returned null"};
            }
            return engine;
        }

        if (const auto it = m_pluginEngines.find(key); it != m_pluginEngines.end()) {
            auto plugin = it->second.lock();
            if (!plugin) {
                return Status{ErrorCode::Unavailable, "plugin for '" + std::string{engineId} +
                                                          "' is no longer loaded"};
            }
            IVpnEngine* raw = plugin->factory(key.c_str());
            if (raw == nullptr) {
                return Status{ErrorCode::Unavailable,
                              "plugin factory returned null for '" + std::string{engineId} + "'"};
            }
            // The host owns the pointer; tie its lifetime to the plugin module
            // so the code backing the vtable outlives the engine.
            return VpnEnginePtr{raw, [plugin](IVpnEngine* engine) { delete engine; }};
        }

        return err::notFound("no engine registered for '" + std::string{engineId} + "'");
    }

    std::vector<std::string> availableEngines() const override
    {
        std::lock_guard lock{m_mutex};
        std::vector<std::string> ids;
        ids.reserve(m_builtins.size() + m_pluginEngines.size());
        for (const auto& [id, factory] : m_builtins) {
            ids.push_back(id);
        }
        for (const auto& [id, plugin] : m_pluginEngines) {
            ids.push_back(id);
        }
        return ids;
    }

    Status loadPlugins(const std::filesystem::path& directory) override
    {
        std::error_code ec;
        if (!std::filesystem::is_directory(directory, ec)) {
            return Status::ok(); // no plugin directory is not an error
        }

        for (const auto& entry : std::filesystem::directory_iterator{directory, ec}) {
            if (ec || !entry.is_regular_file(ec)) {
                continue;
            }
            if (!str::equalsIgnoreCase(entry.path().extension().string(), ".dll")) {
                continue;
            }
            if (const Status status = loadOnePlugin(entry.path()); status.isError()) {
                // One bad plugin must not stop the others; log and continue.
                NOVA_LOG_WARN(Channel::Plugin, "skipping plugin")
                    .field("path", entry.path().string())
                    .status(status);
            }
        }
        return Status::ok();
    }

private:
    Status loadOnePlugin(const std::filesystem::path& path)
    {
        if (m_requireSigned) {
            NOVA_RETURN_IF_ERROR(verifyPluginSignature(path));
        }

        HMODULE module = ::LoadLibraryExW(path.wstring().c_str(), nullptr,
                                          LOAD_LIBRARY_SEARCH_DEFAULT_DIRS |
                                              LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
        if (module == nullptr) {
            return win::lastError("LoadLibraryEx(" + path.string() + ")");
        }

        auto guard = [&module] {
            if (module != nullptr) {
                ::FreeLibrary(module);
                module = nullptr;
            }
        };

        const auto abiFn = reinterpret_cast<EngineAbiVersionFn>(
            ::GetProcAddress(module, "NovaVpnEngineAbiVersion"));
        const auto factoryFn =
            reinterpret_cast<EngineFactoryFn>(::GetProcAddress(module, "NovaVpnCreateEngine"));
        const auto idsFn = reinterpret_cast<const char* (*)()>(
            ::GetProcAddress(module, "NovaVpnEngineIds"));

        if (abiFn == nullptr || factoryFn == nullptr || idsFn == nullptr) {
            guard();
            return Status{ErrorCode::ProtocolError,
                          "plugin is missing a required export: " + path.string()};
        }

        const u32 abi = abiFn();
        if (abi != kEngineAbiVersion) {
            guard();
            return Status{ErrorCode::ServiceVersion,
                          "plugin ABI " + std::to_string(abi) + " != host ABI " +
                              std::to_string(kEngineAbiVersion) + ": " + path.string()};
        }

        // NovaVpnEngineIds returns a comma-separated list of the engine ids the
        // plugin serves ("wireguard,shadowsocks").
        const char* rawIds = idsFn();
        const std::string idList = rawIds != nullptr ? rawIds : "";
        if (idList.empty()) {
            guard();
            return Status{ErrorCode::ProtocolError, "plugin advertises no engine ids"};
        }

        auto plugin = std::make_shared<LoadedPlugin>();
        plugin->module  = module;
        plugin->factory = factoryFn;
        plugin->path    = path;
        module          = nullptr; // ownership moved into the plugin

        std::lock_guard lock{m_mutex};
        m_pluginHold.push_back(plugin); // the registry owns the module's lifetime
        for (const auto id : str::split(idList, ',', /*skipEmpty=*/true)) {
            const std::string key = str::toLower(std::string{str::trim(id)});
            if (m_builtins.count(key) != 0) {
                NOVA_LOG_WARN(Channel::Plugin, "plugin engine id shadows a built-in; ignored")
                    .field("engine", key);
                continue;
            }
            m_pluginEngines[key] = plugin;
            NOVA_LOG_INFO(Channel::Plugin, "loaded plugin engine")
                .field("engine", key)
                .field("path", path.string());
        }
        return Status::ok();
    }

    mutable std::mutex                              m_mutex;
    bool                                            m_requireSigned;
    std::unordered_map<std::string, BuiltinEngineFactory>       m_builtins;
    std::unordered_map<std::string, std::weak_ptr<LoadedPlugin>> m_pluginEngines;
    std::vector<std::shared_ptr<LoadedPlugin>>      m_pluginHold; // keeps modules alive
};

} // namespace

EngineRegistryPtr makeEngineRegistry(bool requireSignedPlugins)
{
    return std::make_shared<EngineRegistry>(requireSignedPlugins);
}

} // namespace nova::tunnel
