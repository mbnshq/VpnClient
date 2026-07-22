#include <NovaVPN/Core/Paths.h>
#include <NovaVPN/Core/StringUtil.h>
#include <NovaVPN/Core/WinError.h>

#include <Windows.h>
#include <AclAPI.h>
#include <ShlObj.h>
#include <sddl.h>

#include <array>
#include <system_error>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace nova::paths {
namespace {

constexpr const wchar_t* kProductFolder = L"NovaVPN";

Result<std::filesystem::path> knownFolder(REFKNOWNFOLDERID id, const char* name)
{
    PWSTR raw = nullptr;
    const HRESULT hr = ::SHGetKnownFolderPath(id, KF_FLAG_CREATE, nullptr, &raw);
    if (FAILED(hr) || raw == nullptr) {
        if (raw != nullptr) {
            ::CoTaskMemFree(raw);
        }
        return win::fromHresult(hr, std::string{"SHGetKnownFolderPath("} + name + ")");
    }
    std::filesystem::path path{raw};
    ::CoTaskMemFree(raw);
    return path;
}

Result<std::filesystem::path> rootedSubdirectory(const Result<std::filesystem::path>& root,
                                                 const wchar_t* child, bool protectedDir)
{
    if (root.isError()) {
        return root.status();
    }
    std::filesystem::path path = root.value() / child;
    NOVA_RETURN_IF_ERROR(protectedDir ? ensureProtectedDirectory(path) : ensureDirectory(path));
    return path;
}

} // namespace

Result<std::filesystem::path> machineRoot()
{
    NOVA_ASSIGN_OR_RETURN(auto base, knownFolder(FOLDERID_ProgramData, "ProgramData"));
    std::filesystem::path root = base / kProductFolder;
    NOVA_RETURN_IF_ERROR(ensureProtectedDirectory(root));
    return root;
}

Result<std::filesystem::path> userRoot()
{
    NOVA_ASSIGN_OR_RETURN(auto base, knownFolder(FOLDERID_LocalAppData, "LocalAppData"));
    std::filesystem::path root = base / kProductFolder;
    NOVA_RETURN_IF_ERROR(ensureDirectory(root));
    return root;
}

Result<std::filesystem::path> executablePath()
{
    std::array<wchar_t, 32768> buffer{};
    const DWORD length = ::GetModuleFileNameW(nullptr, buffer.data(),
                                              static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) {
        return win::lastError("GetModuleFileName");
    }
    return std::filesystem::path{std::wstring_view{buffer.data(), length}};
}

Result<std::filesystem::path> executableDirectory()
{
    NOVA_ASSIGN_OR_RETURN(auto exe, executablePath());
    return exe.parent_path();
}

Result<std::filesystem::path> machineLogDirectory()
{
    return rootedSubdirectory(machineRoot(), L"logs", true);
}

Result<std::filesystem::path> userLogDirectory()
{
    return rootedSubdirectory(userRoot(), L"logs", false);
}

Result<std::filesystem::path> profileDirectory()
{
    return rootedSubdirectory(machineRoot(), L"profiles", true);
}

Result<std::filesystem::path> updateStagingDirectory()
{
    return rootedSubdirectory(machineRoot(), L"updates", true);
}

Result<std::filesystem::path> databasePath()
{
    NOVA_ASSIGN_OR_RETURN(auto root, machineRoot());
    return root / L"novavpn.db";
}

Result<std::filesystem::path> machineConfigPath()
{
    NOVA_ASSIGN_OR_RETURN(auto root, machineRoot());
    return root / L"config.json";
}

Result<std::filesystem::path> userSettingsPath()
{
    NOVA_ASSIGN_OR_RETURN(auto root, userRoot());
    return root / L"settings.json";
}

Status ensureDirectory(const std::filesystem::path& directory)
{
    std::error_code ec;
    if (std::filesystem::exists(directory, ec)) {
        if (std::filesystem::is_directory(directory, ec)) {
            return Status::ok();
        }
        return err::alreadyExists("path exists and is not a directory: " +
                                  directory.string());
    }

    std::filesystem::create_directories(directory, ec);
    if (ec) {
        return Status{ErrorCode::IoError,
                      "failed to create directory " + directory.string() + ": " + ec.message(),
                      static_cast<u32>(ec.value())};
    }
    return Status::ok();
}

Status ensureProtectedDirectory(const std::filesystem::path& directory)
{
    NOVA_RETURN_IF_ERROR(ensureDirectory(directory));

    // SDDL: protected (no inheritance from the parent), SYSTEM and the local
    // Administrators group get full control, authenticated users get read and
    // execute only. This is what stops a standard user from swapping a profile
    // or a staged update out from under the SYSTEM service.
    static constexpr const wchar_t* kSddl =
        L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)";

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(kSddl, SDDL_REVISION_1,
                                                               &descriptor, nullptr) == FALSE) {
        return win::lastError("ConvertStringSecurityDescriptorToSecurityDescriptor");
    }

    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    PACL dacl = nullptr;
    Status status = Status::ok();

    if (::GetSecurityDescriptorDacl(descriptor, &daclPresent, &dacl, &daclDefaulted) == FALSE) {
        status = win::lastError("GetSecurityDescriptorDacl");
    } else {
        const std::wstring native = directory.wstring();
        const DWORD result = ::SetNamedSecurityInfoW(
            const_cast<LPWSTR>(native.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
            dacl, nullptr);
        if (result != ERROR_SUCCESS) {
            // A non-elevated caller (the UI) legitimately cannot re-ACL the
            // machine root. Treat access denial as "already owned by the
            // service" rather than a hard failure.
            if (result != ERROR_ACCESS_DENIED && result != ERROR_PRIVILEGE_NOT_HELD) {
                status = win::fromWin32(result, "SetNamedSecurityInfo(" + directory.string() + ")");
            }
        }
    }

    ::LocalFree(descriptor);
    return status;
}

bool isContainedIn(const std::filesystem::path& root, const std::filesystem::path& candidate)
{
    std::error_code ec;
    const std::filesystem::path normalRoot =
        std::filesystem::weakly_canonical(root, ec).lexically_normal();
    if (ec) {
        return false;
    }
    const std::filesystem::path normalCandidate =
        std::filesystem::weakly_canonical(candidate, ec).lexically_normal();
    if (ec) {
        return false;
    }

    auto rootIt = normalRoot.begin();
    auto candIt = normalCandidate.begin();
    for (; rootIt != normalRoot.end(); ++rootIt, ++candIt) {
        if (candIt == normalCandidate.end()) {
            return false;
        }
        if (!str::equalsIgnoreCase(rootIt->string(), candIt->string())) {
            return false;
        }
    }
    return true;
}

std::string sanitizeFileName(std::string_view name)
{
    static constexpr std::string_view kForbidden = R"(<>:"/\|?*)";

    std::string out;
    out.reserve(name.size());
    for (const char c : name) {
        const auto uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || kForbidden.find(c) != std::string_view::npos) {
            out.push_back('_');
        } else {
            out.push_back(c);
        }
    }

    // Trailing dots and spaces are silently stripped by the shell and make a
    // name unopenable; strip them ourselves so the stored name is honest.
    while (!out.empty() && (out.back() == '.' || out.back() == ' ')) {
        out.pop_back();
    }
    if (out.empty()) {
        out = "unnamed";
    }

    // Reserved DOS device names remain reserved regardless of extension.
    static constexpr std::array<std::string_view, 22> kReserved{
        "CON",  "PRN",  "AUX",  "NUL",  "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"};

    const std::string_view stem{out.data(), out.find('.') == std::string::npos
                                                ? out.size()
                                                : out.find('.')};
    for (const auto reserved : kReserved) {
        if (str::equalsIgnoreCase(stem, reserved)) {
            out.insert(out.begin(), '_');
            break;
        }
    }

    if (out.size() > 200) {
        out.resize(200);
    }
    return out;
}

} // namespace nova::paths
