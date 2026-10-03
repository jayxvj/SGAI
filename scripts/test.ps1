param(
    [ValidateSet("Debug", "Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$Config = "Debug",

    [ValidateSet("all", "unit", "integration", "security")]
    [string]$Suite = "all"
)

$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildDir = Join-Path $RootDir "build"

if (-not (Test-Path $BuildDir)) {
    Write-Error "Build directory '$BuildDir' not found. Please run .\scripts\build.ps1 first."
    exit 1
}

$CTestArgs = @("--test-dir", $BuildDir, "-C", $Config, "--output-on-failure")

if ($Suite -ne "all") {
    $CTestArgs += @("-L", $Suite)
}

Write-Host "==> Running CTest (Config: $Config, Suite: $Suite)" -ForegroundColor Cyan
ctest @CTestArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Tests failed with exit code $LASTEXITCODE."
    exit $LASTEXITCODE
}

Write-Host "==> All tests in suite '$Suite' passed successfully." -ForegroundColor Green
exit 0
