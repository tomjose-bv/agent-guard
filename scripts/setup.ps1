# One-command setup for Windows (PowerShell 5.1+):
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
# Creates .venv, installs agent-guard (editable) with dev extras, validates the
# demo config and runs the tests. Re-running is safe.
param([switch]$SkipTests)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$py = $null
foreach ($cand in @("py -3.12", "py -3", "python")) {
    $exe, $arg = $cand.Split(" ", 2)
    if (Get-Command $exe -ErrorAction SilentlyContinue) {
        $ver = & $exe $arg -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -eq 0 -and [version]$ver -ge [version]"3.10") { $py = $cand; break }
    }
}
if (-not $py) { throw "Python 3.10+ not found. Install it from https://www.python.org/downloads/" }
Write-Host "Using $py"

if (-not (Test-Path ".venv")) {
    $exe, $arg = $py.Split(" ", 2)
    & $exe $arg -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "could not create .venv" }
}
$vpy = ".\.venv\Scripts\python.exe"

function Install-Deps {
    & $vpy -m pip install --disable-pip-version-check -q -e ".[dev]"
    return $LASTEXITCODE
}

if ((Install-Deps) -ne 0) {
    # Corporate TLS inspection often breaks pip; use the OS trust store instead
    # (this keeps certificate verification ON).
    Write-Host "pip failed; retrying with the system trust store (truststore)..."
    & $vpy -m pip install --disable-pip-version-check -q truststore
    $env:PIP_USE_FEATURE = "truststore"
    if ((Install-Deps) -ne 0) { throw "pip install failed. See the error above." }
}

& .\.venv\Scripts\agent-guard.exe validate
if (-not $SkipTests) {
    & $vpy -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }
}

Write-Host ""
Write-Host "Done. Try the demo:"
Write-Host "  .\.venv\Scripts\python examples\demo_agent.py"
Write-Host "  .\.venv\Scripts\agent-guard ui"
