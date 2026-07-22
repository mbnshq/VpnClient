#include <NovaVPN/Core/FileUtil.h>
#include <NovaVPN/Core/Handle.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/WinError.h>
#include <NovaVPN/Updater/Updater.h>

#include <Windows.h>
#include <wincrypt.h>
#include <winhttp.h>

#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace nova::updater {
namespace {

struct WinHttpTraits {
    using value_type = HINTERNET;
    static value_type invalid() noexcept { return nullptr; }
    static void close(value_type handle) noexcept { ::WinHttpCloseHandle(handle); }
};
using WinHttpHandle = win::UniqueResource<WinHttpTraits>;

/// Cracks an https URL into host / path / port. http is refused - updates must
/// be transport-secured.
struct ParsedUrl {
    std::wstring host;
    std::wstring path;
    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
};

Result<ParsedUrl> parseUrl(const std::string& url)
{
    const std::wstring wide = win::toWide(url);

    URL_COMPONENTS components{};
    components.dwStructSize     = sizeof(components);
    wchar_t hostBuffer[256]{};
    wchar_t pathBuffer[2048]{};
    components.lpszHostName     = hostBuffer;
    components.dwHostNameLength = static_cast<DWORD>(std::size(hostBuffer));
    components.lpszUrlPath      = pathBuffer;
    components.dwUrlPathLength  = static_cast<DWORD>(std::size(pathBuffer));

    if (::WinHttpCrackUrl(wide.c_str(), 0, 0, &components) == FALSE) {
        return win::lastError("WinHttpCrackUrl(" + url + ")");
    }
    if (components.nScheme != INTERNET_SCHEME_HTTPS) {
        return err::invalidArgument("update URLs must be https: " + url);
    }

    ParsedUrl parsed;
    parsed.host = std::wstring{hostBuffer, components.dwHostNameLength};
    parsed.path = std::wstring{pathBuffer, components.dwUrlPathLength};
    parsed.port = components.nPort;
    return parsed;
}

class WinHttpFetcher final : public IHttpFetcher {
public:
    explicit WinHttpFetcher(std::vector<std::string> pinnedKeys)
        : m_pinnedKeys(std::move(pinnedKeys))
    {
    }

    Result<std::vector<u8>> get(const std::string& url, const CancellationToken& token) override
    {
        std::vector<u8> body;
        NOVA_RETURN_IF_ERROR(request(url, token, [&body](const u8* data, DWORD size) {
            body.insert(body.end(), data, data + size);
            return true;
        }));
        return body;
    }

    Status download(const std::string& url, const std::filesystem::path& destination,
                    std::function<void(u64, u64)> onProgress,
                    const CancellationToken& token) override
    {
        std::vector<u8> buffer;
        u64 total = 0;
        u64 done = 0;

        // Buffer to a temp file's worth in memory then flush - packages are
        // tens of MB, acceptable; a streamed-to-disk variant is a later
        // optimisation.
        NOVA_RETURN_IF_ERROR(request(
            url, token,
            [&](const u8* data, DWORD size) {
                buffer.insert(buffer.end(), data, data + size);
                done += size;
                if (onProgress) {
                    onProgress(done, total);
                }
                return true;
            },
            &total));

        return file::writeAtomic(destination, buffer);
    }

private:
    template <typename Sink>
    Status request(const std::string& url, const CancellationToken& token, Sink&& sink,
                   u64* outTotal = nullptr)
    {
        NOVA_ASSIGN_OR_RETURN(auto parsed, parseUrl(url));

        WinHttpHandle session{::WinHttpOpen(L"NovaVPN-Updater/1.0",
                                            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
        if (!session) {
            return win::lastError("WinHttpOpen");
        }
        // Modern TLS only.
        DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        ::WinHttpSetOption(session.get(), WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols,
                           sizeof(protocols));

        WinHttpHandle connection{::WinHttpConnect(session.get(), parsed.host.c_str(),
                                                  parsed.port, 0)};
        if (!connection) {
            return win::lastError("WinHttpConnect");
        }

        WinHttpHandle req{::WinHttpOpenRequest(connection.get(), L"GET", parsed.path.c_str(),
                                               nullptr, WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               WINHTTP_FLAG_SECURE)};
        if (!req) {
            return win::lastError("WinHttpOpenRequest");
        }

        if (::WinHttpSendRequest(req.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE) {
            return win::lastError("WinHttpSendRequest");
        }
        if (::WinHttpReceiveResponse(req.get(), nullptr) == FALSE) {
            return win::lastError("WinHttpReceiveResponse");
        }

        NOVA_RETURN_IF_ERROR(checkPinnedCertificate(req.get()));

        DWORD statusCode = 0;
        DWORD size = sizeof(statusCode);
        ::WinHttpQueryHeaders(req.get(),
                              WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr,
                              &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
        if (statusCode != 200) {
            return Status{ErrorCode::UpdateDownload,
                          "server returned HTTP " + std::to_string(statusCode)};
        }

        if (outTotal != nullptr) {
            DWORD contentLength = 0;
            size = sizeof(contentLength);
            if (::WinHttpQueryHeaders(
                    req.get(), WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                    nullptr, &contentLength, &size, WINHTTP_NO_HEADER_INDEX) != FALSE) {
                *outTotal = contentLength;
            }
        }

        std::vector<u8> chunk(64 * 1024);
        while (true) {
            if (token.isCancelled()) {
                return err::cancelled("download cancelled");
            }
            DWORD available = 0;
            if (::WinHttpQueryDataAvailable(req.get(), &available) == FALSE) {
                return win::lastError("WinHttpQueryDataAvailable");
            }
            if (available == 0) {
                break;
            }
            const DWORD toRead = std::min<DWORD>(available, static_cast<DWORD>(chunk.size()));
            DWORD read = 0;
            if (::WinHttpReadData(req.get(), chunk.data(), toRead, &read) == FALSE) {
                return win::lastError("WinHttpReadData");
            }
            if (read == 0) {
                break;
            }
            if (!sink(chunk.data(), read)) {
                return err::io("download sink rejected data");
            }
        }
        return Status::ok();
    }

    /// Certificate pinning: compares the leaf certificate's public-key SHA-256
    /// against the pinned set. Empty set = pinning disabled (test servers).
    Status checkPinnedCertificate(HINTERNET request)
    {
        if (m_pinnedKeys.empty()) {
            return Status::ok();
        }

        PCCERT_CONTEXT cert = nullptr;
        DWORD size = sizeof(cert);
        if (::WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert, &size) ==
                FALSE ||
            cert == nullptr) {
            return win::lastError("WinHttpQueryOption(server cert)");
        }

        // Hash the SubjectPublicKeyInfo bytes.
        const auto& spki = cert->pCertInfo->SubjectPublicKeyInfo;
        std::vector<u8> spkiBytes(spki.PublicKey.pbData,
                                  spki.PublicKey.pbData + spki.PublicKey.cbData);
        auto digest = sha256(spkiBytes);
        ::CertFreeCertificateContext(cert);
        if (digest.isError()) {
            return digest.status();
        }

        const std::string actual = str::toHex(digest.value().data(), 32);
        for (const auto& pinned : m_pinnedKeys) {
            if (str::equalsIgnoreCase(pinned, actual)) {
                return Status::ok();
            }
        }
        return Status{ErrorCode::CertificateInvalid,
                      "server certificate public key is not pinned"};
    }

    std::vector<std::string> m_pinnedKeys;
};

} // namespace

HttpFetcherPtr makeWinHttpFetcher(std::vector<std::string> pinnedKeySha256)
{
    return std::make_shared<WinHttpFetcher>(std::move(pinnedKeySha256));
}

} // namespace nova::updater
