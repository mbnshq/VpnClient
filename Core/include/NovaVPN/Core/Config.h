// NovaVPN - Core/Config.h
// Layered configuration store.
//
//   defaults (compiled in)  <-  file on disk  <-  runtime overrides
//
// Readers always see a fully-populated document, so a hand-edited or truncated
// config file degrades to defaults instead of failing the service start. Writes
// persist only the delta against the defaults, which keeps the file readable
// and makes upgrades to new default values automatic.
#pragma once

#include <NovaVPN/Core/Json.h>
#include <NovaVPN/Core/Result.h>

#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace nova {

/// Compiled-in default document for the service (machine scope).
[[nodiscard]] const Json& serviceConfigDefaults();

/// Compiled-in default document for the UI (user scope).
[[nodiscard]] const Json& userSettingsDefaults();

class ConfigStore final {
public:
    /// Invoked after a successful set()/apply(); receives the JSON pointer that
    /// changed. Handlers run on the caller's thread with the store unlocked.
    using ChangeHandler = std::function<void(std::string_view pointer)>;

    /// Creates a store over `path` with `defaults` as the base layer. The file
    /// is not read until load() is called.
    ConfigStore(std::filesystem::path path, Json defaults);

    ConfigStore(const ConfigStore&) = delete;
    ConfigStore& operator=(const ConfigStore&) = delete;

    /// Reads the file and merges it over the defaults. A missing file is not an
    /// error - it yields the pure default document. A corrupt file returns
    /// ParseError while leaving the store on defaults so the caller can decide
    /// whether to continue or abort.
    Status load();

    /// Persists the current delta against the defaults, atomically.
    Status save() const;

    /// Typed read; falls back to the default document, then to `fallback`.
    template <typename T>
    [[nodiscard]] T get(std::string_view pointer, T fallback = T{}) const
    {
        std::lock_guard lock{m_mutex};
        return json::get<T>(m_effective, pointer, std::move(fallback));
    }

    /// Typed write. Returns InvalidArgument for a malformed pointer.
    Status set(std::string_view pointer, Json value);

    /// Applies a whole overlay document in one transaction, firing one change
    /// notification per top-level pointer that actually changed.
    Status apply(const Json& overlay);

    /// Restores a single key to its default value.
    Status reset(std::string_view pointer);

    /// Snapshot of the effective document.
    [[nodiscard]] Json snapshot() const;

    /// The delta that would be written by save().
    [[nodiscard]] Json delta() const;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return m_path; }

    /// Registers a change handler. Handlers live for the lifetime of the store;
    /// the store outlives its subscribers by construction (it is owned by the
    /// service host).
    void onChanged(ChangeHandler handler);

private:
    void notify(std::string_view pointer) const;
    static Json computeDelta(const Json& defaults, const Json& effective);

    mutable std::mutex         m_mutex;
    std::filesystem::path      m_path;
    Json                       m_defaults;
    Json                       m_effective;
    std::vector<ChangeHandler> m_handlers;
};

} // namespace nova
