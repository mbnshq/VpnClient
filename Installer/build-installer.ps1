<#
.SYNOPSIS
    Builds the NovaVPN MSI: stages the service, the self-contained client and
    the Wintun driver, then compiles the WiX authoring.

.DESCRIPTION
    Prerequisites (installed as user-local dotnet tools, no admin required):
        dotnet tool install --global wix --version 5.0.2
        wix extension add -g WixToolset.Firewall.wixext/5.0.2
        wix extension add -g WixToolset.Util.wixext/5.0.2

    The service must already be built in Release (scripts/build.ps1
    -Preset ninja-release), and wintun.dll must be available from that build's
    dependency fetch.

.EXAMPLE
    .\Installer\build-installer.ps1
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'ninja-release',
    [string]$OutputMsi = 'build/NovaVPN.msi'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

$serviceExe = Join-Path $repo "build/$Configuration/bin/NovaVPNService.exe"
$clientExe  = Join-Path $repo 'build/client/NovaVPN.exe'
$wintun     = Get-ChildItem -Path (Join-Path $repo 'build') -Recurse -Filter 'wintun.dll' `
                 -ErrorAction SilentlyContinue | Select-Object -First 1

foreach ($required in @($serviceExe, $clientExe)) {
    if (-not (Test-Path $required)) {
        throw "Missing build input: $required. Build the service (Release) and publish the client first."
    }
}
if (-not $wintun) { throw 'wintun.dll not found under build/. Configure with the engine or run a build that fetches it.' }

$staging = Join-Path $repo 'build/installer-staging'
New-Item -ItemType Directory -Force -Path $staging | Out-Null
Copy-Item $serviceExe (Join-Path $staging 'NovaVPNService.exe') -Force
Copy-Item $clientExe  (Join-Path $staging 'NovaVPN.exe') -Force
Copy-Item $wintun.FullName (Join-Path $staging 'wintun.dll') -Force

$wix = Join-Path $env:USERPROFILE '.dotnet/tools/wix.exe'
if (-not (Test-Path $wix)) { $wix = (Get-Command wix -ErrorAction SilentlyContinue).Source }
if (-not $wix) { throw 'wix.exe not found. Install it with: dotnet tool install --global wix --version 5.0.2' }

& $wix build (Join-Path $PSScriptRoot 'NovaVPN.wxs') `
    -arch x64 `
    -d "BinDir=$staging" `
    -ext WixToolset.Firewall.wixext `
    -ext WixToolset.Util.wixext `
    -o (Join-Path $repo $OutputMsi)

if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }
Write-Host "`nOK - $OutputMsi" -ForegroundColor Green
