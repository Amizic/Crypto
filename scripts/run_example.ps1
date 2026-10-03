<#
Runs the compiled usage example.
Usage: pwsh -ExecutionPolicy Bypass -File scripts/run_example.ps1 [-Linkage shared|static]
#>
param(
    [ValidateSet("shared", "static")] [string]$Linkage = "shared"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $projectRoot "build-$Linkage\bin\usage_example.exe"
if (-not (Test-Path $exe)) {
    throw "Not found: $exe (run scripts/build.ps1 -Linkage $Linkage first)"
}
& $exe
exit $LASTEXITCODE
