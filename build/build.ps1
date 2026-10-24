# Builds the engine (bin\hi-waf.exe) and the manager (bin\manager.exe).
# Run from anywhere; needs Go 1.26+.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
function Invoke-Go {
    & go @args
    if ($LASTEXITCODE -ne 0) { throw "go $args failed with exit code $LASTEXITCODE" }
}
Invoke-Go mod tidy
Invoke-Go build -o bin/hi-waf.exe ./cmd/hi-waf
Invoke-Go build -o bin/manager.exe ./cmd/manager
Write-Host 'built bin\hi-waf.exe and bin\manager.exe'
