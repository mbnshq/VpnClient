#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/Paths.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Logs/Logger.h>
#include <NovaVPN/Updater/Updater.h>

#include <mutex>



namespace nova::updater {
namespace {

/// Joins a base URL and a relative path with exactly one slash.
std::string joinUrl(std::string_view base, std::string_view path)
{
    std::string out{base};
    if (!out.empty() && out.back() == '/' && str::startsWith(path, "/")) {
        out.pop_back();
    } else if (!out.empty() && out.back() != '/' && !str::startsWith(path, "/")) {
        out.push_back('/');
    }
    out.append(path);
    return out;
}

class Updater final : public IUpdater {
public:
    Updater(HttpFetcherPtr fetcher, std::shared_ptr<ISignatureVerifier> verifier,
            UpdaterConfig config)
        : m_fetcher(std::move(fetcher)), m_verifier(std::move(verifier)),
          m_config(std::move(config))
    {
    }

    Result<ReleaseInfo> check(Channel channel, const CancellationToken& token) override
    {
        setStage(UpdateStage::CheckingManifest);

        // The manifest and its detached signature live at well-known paths on
        // the feed, per channel.
        const std::string channelName{toString(channel)};
        const std::string manifestUrl =
            joinUrl(m_config.feedBaseUrl, channelName + "/manifest.json");
        const std::string signatureUrl =
            joinUrl(m_config.feedBaseUrl, channelName + "/manifest.json.sig");

        auto manifestBytes = m_fetcher->get(manifestUrl, token);
        if (manifestBytes.isError()) {
            setStage(UpdateStage::Failed);
            return manifestBytes.status().withContext("fetching the manifest");
        }
        auto signatureBytes = m_fetcher->get(signatureUrl, token);
        if (signatureBytes.isError()) {
            setStage(UpdateStage::Failed);
            return signatureBytes.status().withContext("fetching the manifest signature");
        }

        // Verify BEFORE parsing for meaning - a manifest is trusted only if it
        // was signed by the release key.
        setStage(UpdateStage::VerifyingManifest);
        if (const Status status =
                m_verifier->verifyManifest(manifestBytes.value(), signatureBytes.value());
            status.isError()) {
            setStage(UpdateStage::Failed);
            return status.withContext("verifying the manifest signature");
        }

        auto release = parseManifest(
            std::string_view{reinterpret_cast<const char*>(manifestBytes.value().data()),
                             manifestBytes.value().size()},
            channel);
        if (release.isError()) {
            setStage(UpdateStage::Failed);
            return release.status();
        }

        // Newer? Otherwise there is nothing to do.
        const int cmp = compareVersions(release.value().version, m_config.currentVersion);
        if (cmp == 0 || (cmp < 0 && !m_config.allowDowngrade)) {
            setStage(UpdateStage::Idle);
            return Status{ErrorCode::UpdateUnavailable,
                          "already up to date (" + m_config.currentVersion + ")"};
        }
        // A minimum-upgrade-from gate the release may declare.
        if (!release.value().minimumUpgradeFrom.empty() &&
            compareVersions(m_config.currentVersion, release.value().minimumUpgradeFrom) < 0) {
            setStage(UpdateStage::Failed);
            return Status{ErrorCode::UpdateApply,
                          "this build is too old to upgrade directly to " +
                              release.value().version};
        }

        setStage(UpdateStage::Idle);
        NOVA_LOG_INFO(logs::Channel::Updater, "update available")
            .field("version", release.value().version)
            .field("security", release.value().isSecurityUpdate);
        return release.value();
    }

    Status download(const ReleaseInfo& release,
                    std::function<void(const UpdateProgress&)> onProgress,
                    const CancellationToken& token) override
    {
        NOVA_RETURN_IF_ERROR(paths::ensureDirectory(m_config.stagingDir));

        // Prefer the delta when it applies to this exact version; else full.
        const bool useDelta = !release.deltaPackageUrl.empty() &&
                              release.deltaFromVersion == m_config.currentVersion;
        const std::string url = useDelta ? release.deltaPackageUrl : release.fullPackageUrl;
        const std::string expectedHash =
            useDelta ? release.deltaPackageSha256 : release.fullPackageSha256;

        const std::filesystem::path staged =
            m_config.stagingDir / ("NovaVPN-" + release.version +
                                   (useDelta ? "-delta.pkg" : ".pkg"));

        setStage(UpdateStage::Downloading);
        const Status downloaded = m_fetcher->download(
            url, staged,
            [this, onProgress](u64 done, u64 total) {
                UpdateProgress progress;
                progress.stage           = UpdateStage::Downloading;
                progress.bytesDownloaded = done;
                progress.bytesTotal      = total;
                progress.fraction        = total > 0 ? static_cast<double>(done) / total : -1.0;
                {
                    std::lock_guard lock{m_mutex};
                    m_progress = progress;
                }
                if (onProgress) {
                    onProgress(progress);
                }
            },
            token);
        if (downloaded.isError()) {
            setStage(UpdateStage::Failed);
            return downloaded.withContext("downloading the package");
        }

        // Verify the hash from the SIGNED manifest, then the Authenticode
        // signature - both before the package is ever executed.
        setStage(UpdateStage::VerifyingPackage);
        if (const Status status = m_verifier->verifyHash(staged, expectedHash);
            status.isError()) {
            (void)file::secureDelete(staged);
            setStage(UpdateStage::Failed);
            return status.withContext("verifying the package hash");
        }
        if (const Status status = m_verifier->verifyAuthenticode(staged); status.isError()) {
            (void)file::secureDelete(staged);
            setStage(UpdateStage::Failed);
            return status.withContext("verifying the package signature");
        }

        {
            std::lock_guard lock{m_mutex};
            m_stagedPackage = staged;
            m_stagedVersion = release.version;
        }
        setStage(UpdateStage::ReadyToInstall);
        NOVA_LOG_INFO(logs::Channel::Updater, "update staged and verified")
            .field("version", release.version)
            .field("package", staged.string());
        return Status::ok();
    }

    Status installStaged() override
    {
        std::filesystem::path package;
        {
            std::lock_guard lock{m_mutex};
            package = m_stagedPackage;
        }
        if (package.empty() || !file::exists(package)) {
            return err::invalidState("no staged package to install");
        }
        // Re-verify at install time: the file has been on disk since download,
        // and a tampered package must not be executed even after staging.
        NOVA_RETURN_IF_ERROR(m_verifier->verifyAuthenticode(package)
                                 .withContext("re-verifying the staged package"));

        // Launching the installer is a Phase 8 concern (it hands off to the MSI
        // and restarts the service). Until the installer exists, staging +
        // verification is the deliverable; refuse to pretend it installed.
        setStage(UpdateStage::Installing);
        return err::notImplemented(
            "installer hand-off requires the MSI package (Phase 8); the update is "
            "downloaded and verified at " + package.string());
    }

    Status discardStaged() override
    {
        std::filesystem::path package;
        {
            std::lock_guard lock{m_mutex};
            package         = m_stagedPackage;
            m_stagedPackage.clear();
            m_stagedVersion.clear();
        }
        if (!package.empty()) {
            (void)file::secureDelete(package);
        }
        setStage(UpdateStage::Idle);
        return Status::ok();
    }

    UpdateProgress progress() const override
    {
        std::lock_guard lock{m_mutex};
        return m_progress;
    }

private:
    void setStage(UpdateStage stage)
    {
        std::lock_guard lock{m_mutex};
        m_progress.stage = stage;
    }

    HttpFetcherPtr                       m_fetcher;
    std::shared_ptr<ISignatureVerifier>  m_verifier;
    UpdaterConfig                        m_config;

    mutable std::mutex     m_mutex;
    UpdateProgress         m_progress;
    std::filesystem::path  m_stagedPackage;
    std::string            m_stagedVersion;
};

} // namespace

UpdaterPtr makeUpdater(HttpFetcherPtr fetcher, std::shared_ptr<ISignatureVerifier> verifier,
                       UpdaterConfig config)
{
    return std::make_shared<Updater>(std::move(fetcher), std::move(verifier), std::move(config));
}

} // namespace nova::updater
