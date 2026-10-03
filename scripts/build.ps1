param(
    [ValidateSet("Debug", "Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$Config = "Debug"
)

$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildDir = Join-Path $RootDir "build"

Write-Host "==> Configuring SentinalAI ($Config) in $BuildDir" -ForegroundColor Cyan
cmake -B $BuildDir -S $RootDir -G "Visual Studio 18 2026" -A x64
if ($LASTEXITCODE -ne 0) {
    Write-Error "CMake configuration failed with exit code $LASTEXITCODE."
    exit $LASTEXITCODE
}

Write-Host "==> Building SentinalAI ($Config)" -ForegroundColor Cyan
cmake --build $BuildDir --config $Config
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed with exit code $LASTEXITCODE."
    exit $LASTEXITCODE
}

Write-Host "==> Build ($Config) completed successfully." -ForegroundColor Green
exit 0
