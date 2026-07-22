<#
.SYNOPSIS
    Configures and builds NovaVPN from a plain PowerShell prompt.

.DESCRIPTION
    Locates Visual Studio with vswhere, imports the x64 native toolchain
    environment, then runs the requested CMake preset. Use this instead of
    hand-rolling a developer command prompt.

.EXAMPLE
    .\scripts\build.ps1 -Preset ninja-debug
    .\scripts\build.ps1 -Preset ninja-release -Test
#>
[CmdletBinding()]
param(
    [ValidateSet('ninja-debug', 'ninja-release', 'ninja-asan', 'vs2022')]
    [string]$Preset = 'ninja-debug',

    [switch]$Clean,
    [switch]$Test,
    [string]$Target
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Get-VisualStudioPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) {
        throw 'vswhere.exe not found. Install Visual Studio 2022 (or Build Tools) with the C++ workload.'
    }
    $path = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $path) {
        # Build Tools installs do not always report the component; fall back to any install.
        $path = & $vswhere -latest -products * -property installationPath
    }
    if (-not $path) { throw 'No Visual Studio installation found.' }
    return $path
}

function Import-VcVars {
    param([string]$VsPath)

    $vcvars = Join-Path $VsPath 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found at $vcvars" }

    # Run vcvars in cmd, then copy the resulting environment into this session.
    $output = & "$env:ComSpec" /c "`"$vcvars`" >nul 2>&1 && set"
    foreach ($line in $output) {
        if ($line -match '^([^=]+)=(.*)$') {
            Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] -ErrorAction SilentlyContinue
        }
    }
}

$vsPath = Get-VisualStudioPath
Write-Host "Visual Studio : $vsPath"
Import-VcVars -VsPath $vsPath

$cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source
if (-not $cmake) {
    $cmake = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
}
if (-not (Test-Path $cmake)) { throw 'cmake not found.' }

$ctest = Join-Path (Split-Path $cmake) 'ctest.exe'
$buildDir = Join-Path $repoRoot "build\$Preset"

if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "Cleaning $buildDir"
    Remove-Item -Recurse -Force $buildDir
}

Push-Location $repoRoot
try {
    & $cmake --preset $Preset
    if ($LASTEXITCODE -ne 0) { throw "configure failed ($LASTEXITCODE)" }

    $buildArgs = @('--build', '--preset', $Preset)
    if ($Target) { $buildArgs += @('--target', $Target) }
    & $cmake @buildArgs
    if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }

    if ($Test) {
        & $ctest --preset $Preset
        if ($LASTEXITCODE -ne 0) { throw "tests failed ($LASTEXITCODE)" }
    }

    Write-Host "`nOK - artifacts in $buildDir\bin" -ForegroundColor Green
}
finally {
    Pop-Location
}
