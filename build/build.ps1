# Builds the engine (bin\hi-waf.exe) and the manager (bin\manager.exe).
# Run from anywhere; needs Go 1.26+:
#   powershell -ExecutionPolicy Bypass -File build\build.ps1
# $ErrorActionPreference stays 'Continue': go writes progress to stderr, which
# PowerShell 5.1 would turn into a terminating error under 'Stop'. Failures are
# caught from $LASTEXITCODE instead.
$ErrorActionPreference = 'Continue'
function Invoke-Go {
    & go @args
    if ($LASTEXITCODE -ne 0) { throw "go $args failed with exit code $LASTEXITCODE" }
}
Push-Location (Join-Path $PSScriptRoot '..')
try {
    Invoke-Go mod tidy
    Invoke-Go build -o bin/hi-waf.exe ./cmd/hi-waf
    Invoke-Go build -o bin/manager.exe ./cmd/manager
    Write-Host 'built bin\hi-waf.exe and bin\manager.exe'
}
finally {
    Pop-Location
}
