// NovaVPN - SplitTunnel/ProcessRegistry.h
// Knowing *which* process a packet belongs to.
//
// This is the hard half of app-based split tunnelling. The requirements:
//   * a decision must be available at connection-establishment time, not after
//     the first packet, otherwise the first SYN leaks;
//   * identity must survive process restarts and PID reuse;
//   * a process must not be able to escape its rule by renaming itself or by
//     launching a helper, hence image-path identity and child inheritance.
//
// The registry keeps a live map of PID -> image path, maintained from the ETW
// process-start/stop feed rather than by polling, so a short-lived process is
// classified correctly. The WFP callout consults it from the ALE
// (Application Layer Enforcement) layers, where Windows already hands us the
// process id of the socket owner.
//
// Implemented in Phase 4.
#pragma once

#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Core/Types.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nova::splittunnel {

/// A process as presented in the process manager UI.
struct ProcessInfo {
    ProcessId   pid = 0;
    ProcessId   parentPid = 0;
    std::string imagePath;    ///< Full NT path, normalised to a DOS path.
    std::string displayName;  ///< FileDescription from the version resource.
    std::string publisher;    ///< Authenticode subject, empty when unsigned.
    SystemTime  startedAt{};
    bool        isElevated = false;
    bool        isSystem = false;
    /// True when the process is a UWP/packaged app; those are identified by
    /// package family name rather than image path.
    bool        isPackaged = false;
    std::string packageFamilyName;
    /// Per-process traffic, attributed by the callout.
    ByteCount   bytesSent = 0;
    ByteCount   bytesReceived = 0;
    /// Tunnel currently carrying this process's traffic, empty for direct.
    Id          tunnelId;
};

/// An installed application, as offered in the split-tunnel app picker. This is
/// the *catalogue* view (one entry per program) rather than the live process
/// view (one entry per running instance).
struct InstalledApplication {
    std::string imagePath;
    std::string displayName;
    std::string publisher;
    std::string version;
    /// PNG bytes of the extracted icon, cached in the database.
    std::vector<u8> iconPng;
    bool        isPackaged = false;
    std::string packageFamilyName;
    /// True when at least one instance is running right now.
    bool        isRunning = false;
};

class IProcessRegistry {
public:
    virtual ~IProcessRegistry() = default;

    /// Starts the ETW session and seeds the map with the current process list.
    [[nodiscard]] virtual Status start() = 0;
    virtual void stop() = 0;

    /// Resolves a PID to its image path. Fast path for the callout: lock-free
    /// read of a copy-on-write map.
    [[nodiscard]] virtual std::optional<std::string> imagePathFor(ProcessId pid) const = 0;

    /// Walks up the parent chain until it finds a process matching a rule,
    /// implementing ApplicationRule::includeChildren.
    [[nodiscard]] virtual std::optional<std::string> effectiveRuleTargetFor(
        ProcessId pid) const = 0;

    [[nodiscard]] virtual Result<std::vector<ProcessInfo>> runningProcesses() const = 0;

    /// Enumerates installed programs (Start menu, registry uninstall keys and
    /// the packaged-app catalogue) for the picker.
    [[nodiscard]] virtual Result<std::vector<InstalledApplication>> installedApplications() = 0;

    /// Extracts and caches an application icon as PNG.
    [[nodiscard]] virtual Result<std::vector<u8>> iconFor(const std::string& imagePath) = 0;
};

using ProcessRegistryPtr = std::shared_ptr<IProcessRegistry>;

} // namespace nova::splittunnel
