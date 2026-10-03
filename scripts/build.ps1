<#
ObsidianGuard build helper.
Builds the project with the local, in-workspace toolchain (tools\mingw64) and
the local OpenSSL installation (vcpkg, or a source build under
tools\openssl-install).

Usage:
    pwsh -ExecutionPolicy Bypass -File scripts/build.ps1 -Linkage shared
    pwsh -ExecutionPolicy Bypass -File scripts/build.ps1 -Linkage static -Clean
#>
param(
    [ValidateSet("shared", "static")] [string]$Linkage = "shared",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot   # .../ObsidianGuard
$toolsRoot   = Join-Path $projectRoot "..\tools"  # .../tools

if (-not (Test-Path $toolsRoot)) {
    throw "Toolchain not found: $toolsRoot"
}

# Local toolchain first, so no system-wide installation is ever needed.
$env:Path = @(
    (Join-Path $toolsRoot "mingw64\bin"),
    (Join-Path $toolsRoot "vcpkg"),
    $env:Path
) -join ";"

# Keep all temporary files inside the workspace as well.
$tmpDir = Join-Path $projectRoot "..\.tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$env:TMP = $tmpDir
$env:TEMP = $tmpDir

foreach ($tool in "g++", "cmake", "mingw32-make") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required tool not found on PATH: $tool"
    }
}

$buildDir = Join-Path $projectRoot "build-$Linkage"
if ($Clean -and (Test-Path $buildDir)) {
    Remove-Item -Recurse -Force $buildDir
}

$shared = if ($Linkage -eq "shared") { "ON" } else { "OFF" }

$vcpkgToolchain = Join-Path $toolsRoot "vcpkg\scripts\buildsystems\vcpkg.cmake"
$opensslInstall = Join-Path $toolsRoot "openssl-install"

$cmakeArgs = @(
    "-S", $projectRoot,
    "-B", $buildDir,
    "-G", "MinGW Makefiles",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DBUILD_SHARED_LIBS=$shared",
    # No try-compile executables need to run during configure.
    "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY"
)

if (Test-Path $opensslInstall) {
    # OpenSSL built from source (tools\openssl-install)
    $cmakeArgs += @("-DOPENSSL_ROOT_DIR=$opensslInstall")
} elseif (Test-Path $vcpkgToolchain) {
    # OpenSSL installed through vcpkg (tools\vcpkg\installed)
    $cmakeArgs += @(
        "-DCMAKE_TOOLCHAIN_FILE=$vcpkgToolchain",
        "-DVCPKG_TARGET_TRIPLET=x64-mingw-static",
        "-DVCPKG_INSTALLED_DIR=$(Join-Path $toolsRoot 'vcpkg\installed')"
    )
} else {
    throw "Neither a local OpenSSL installation nor the vcpkg toolchain was found under $toolsRoot"
}

& cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed (exit $LASTEXITCODE)" }

& cmake --build $buildDir
if ($LASTEXITCODE -ne 0) { throw "cmake build failed (exit $LASTEXITCODE)" }

Write-Host ""
Write-Host "Build finished: $(Join-Path $buildDir 'bin\usage_example.exe')"
