# Building NovaVPN

## Prerequisites

| Requirement | Version | Notes |
| --- | --- | --- |
| Windows | 10 21H2 (19044) or later | 11 recommended for the Fluent UI phase |
| Visual Studio 2022 or Build Tools | 17.8+ with "Desktop development with C++" | MSVC 14.38+ |
| Windows SDK | 10.0.22621.0 or later | WFP and Wintun headers |
| CMake | 3.24+ | ships with Visual Studio |
| Git | any recent | |

Dependencies (`nlohmann/json`, `Catch2`) are fetched by CMake at configure time
from pinned URLs with SHA-256 verification. The first configure needs network
access; afterwards the CMake download cache is reused. Configure with
`-DNOVAVPN_OFFLINE=ON` to turn any fetch into a hard error, which is how the
release pipeline proves it consumed only the pre-populated cache.

## Quick start

From any PowerShell prompt — the script locates Visual Studio and imports the
x64 toolchain environment itself:

```powershell
.\scripts\build.ps1 -Preset ninja-debug -Test
```

Artifacts land in `build\ninja-debug\bin`.

## Presets

| Preset | Generator | Purpose |
| --- | --- | --- |
| `ninja-debug` | Ninja | fast iteration; tests on |
| `ninja-release` | Ninja | shipping build; LTO, warnings-as-errors |
| `ninja-asan` | Ninja | AddressSanitizer (uses the DLL CRT) |
| `vs2022` | Visual Studio 17 | IDE / debugging |

## Manual build

From a **x64 Native Tools Command Prompt for VS 2022**:

```bash
cmake --preset ninja-debug
cmake --build --preset ninja-debug
ctest --preset ninja-debug
```

## Build options

| Option | Default | Effect |
| --- | --- | --- |
| `NOVAVPN_BUILD_TESTS` | `ON` | build the unit test target |
| `NOVAVPN_WARNINGS_AS_ERRORS` | `OFF` | `/WX`; on in the release preset |
| `NOVAVPN_ENABLE_ASAN` | `OFF` | `/fsanitize=address` |
| `NOVAVPN_ENABLE_LTO` | `OFF` | link-time code generation |
| `NOVAVPN_OFFLINE` | `OFF` | forbid dependency downloads |
| `NOVAVPN_VERSION_CHANNEL` | `dev` | `dev` / `beta` / `stable` |

The CRT is linked **statically** by default (`/MT`, `/MTd`) so the service and
the elevated helpers carry no redistributable dependency. The ASan preset
overrides this because the sanitizer runtime requires the DLL CRT.

## Running the tests

```powershell
.\build\ninja-debug\bin\novavpn_unit_tests.exe            # all
.\build\ninja-debug\bin\novavpn_unit_tests.exe "[routing]" # one tag
.\build\ninja-debug\bin\novavpn_unit_tests.exe --list-tests
```

Or through CTest, which discovers each Catch2 case as a separate test:

```powershell
ctest --preset ninja-debug --output-on-failure
```

## Running the service during development

The service does not need to be installed to be exercised:

```powershell
.\build\ninja-debug\bin\NovaVPNService.exe --console
```

Install/uninstall require an elevated prompt:

```powershell
.\build\ninja-debug\bin\NovaVPNService.exe --install
.\build\ninja-debug\bin\NovaVPNService.exe --status
.\build\ninja-debug\bin\NovaVPNService.exe --uninstall
```

Logs go to `%ProgramData%\NovaVPN\logs\service.log`, to the Windows Event Log
(source `NovaVPNService`) for errors, and to the debugger output.

## Adding a module

1. Create `<Module>/include/NovaVPN/<Module>/…` and `<Module>/src/…`.
2. Add a `CMakeLists.txt`:

   ```cmake
   nova_add_module(MyModule
       SOURCES  src/Thing.cpp
       HEADERS  include/NovaVPN/MyModule/Thing.h
       DEPENDS  nova::core nova::logs
       SYSTEM   iphlpapi)
   ```

3. `add_subdirectory(MyModule)` in the root `CMakeLists.txt`, **below** every
   module it depends on.

A module with no `SOURCES` becomes an `INTERFACE` library — that is how
contract-only modules are declared before their implementation phase.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `cmake not found` | not in a VS developer prompt; use `scripts\build.ps1` |
| `must be built for x64` | 32-bit toolchain selected |
| FetchContent hash mismatch | corrupt download cache; delete `build/*/\_deps` |
| `error C2039: 'span'` | missing `#include <span>` |
| ASan link errors | ASan needs the DLL CRT — use the `ninja-asan` preset |
