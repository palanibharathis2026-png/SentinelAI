# SentinelAI one-click launcher (Windows).
# First run: creates the Python environment, installs libraries and, if Node.js is missing,
# downloads a portable copy into .tools\. Then starts the API and dashboard and opens the browser.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"
$tools = Join-Path $root ".tools"
$nodeVersion = "v22.12.0"
$nodeDir = Join-Path $tools "node-$nodeVersion-win-x64"
$apiUrl = "http://127.0.0.1:8000/api/health"
$dashboardUrl = "http://localhost:5173"

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Fail($msg) {
    Write-Host "`n$msg" -ForegroundColor Red
    exit 1
}
function IsUp($url) {
    try { Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 2 | Out-Null; return $true } catch { return $false }
}

# ---- Backend setup ---------------------------------------------------------
Step "Checking Python"
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Fail "Python not found. Install Python 3.11+ from https://www.python.org/downloads/ (tick 'Add python.exe to PATH') and run start.bat again."
}
$venvPython = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Step "First run: creating Python environment and installing backend libraries (1-2 min)"
    & python -m venv (Join-Path $backend ".venv")
    & $venvPython -m pip install --quiet --upgrade pip
    & $venvPython -m pip install --quiet -r (Join-Path $backend "requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        Remove-Item -Recurse -Force (Join-Path $backend ".venv")
        Fail "Installing backend libraries failed. Check your internet connection and run start.bat again."
    }
}

# ---- Frontend setup --------------------------------------------------------
Step "Checking Node.js"
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
    if (-not (Test-Path (Join-Path $nodeDir "npm.cmd"))) {
        Step "Node.js is not installed: downloading a portable copy (35 MB, one time only)"
        New-Item -ItemType Directory -Force $tools | Out-Null
        $zip = Join-Path $tools "node.zip"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest "https://nodejs.org/dist/$nodeVersion/node-$nodeVersion-win-x64.zip" -OutFile $zip -UseBasicParsing
        tar -xf $zip -C $tools
        Remove-Item $zip
    }
    $env:PATH = "$nodeDir;$env:PATH"
}
if (-not (Test-Path (Join-Path $frontend "node_modules"))) {
    Step "First run: installing dashboard libraries (1-2 min)"
    Push-Location $frontend
    & npm.cmd install --no-audit --no-fund
    $code = $LASTEXITCODE
    Pop-Location
    if ($code -ne 0) { Fail "Installing dashboard libraries failed. Check your internet connection and run start.bat again." }
}

# ---- Start both servers in their own windows --------------------------------
if (IsUp $apiUrl) {
    Step "API already running on port 8000"
} else {
    Step "Starting SentinelAI API (window: 'SentinelAI API')"
    Start-Process cmd.exe -ArgumentList "/k title SentinelAI API && cd /d `"$backend`" && .venv\Scripts\python.exe -m uvicorn main:app --port 8000" -WorkingDirectory $backend
}
if (IsUp $dashboardUrl) {
    Step "Dashboard already running on port 5173"
} else {
    Step "Starting dashboard (window: 'SentinelAI Dashboard')"
    Start-Process cmd.exe -ArgumentList "/k title SentinelAI Dashboard && cd /d `"$frontend`" && npm.cmd run dev" -WorkingDirectory $frontend
}

Step "Waiting for SentinelAI to come online"
$deadline = (Get-Date).AddSeconds(120)
while (-not ((IsUp $apiUrl) -and (IsUp $dashboardUrl))) {
    if ((Get-Date) -gt $deadline) { Fail "Timed out. Look at the 'SentinelAI API' and 'SentinelAI Dashboard' windows for errors." }
    Start-Sleep -Seconds 2
}

Start-Process $dashboardUrl
Write-Host "`nSentinelAI is running!" -ForegroundColor Green
Write-Host "  Dashboard: $dashboardUrl   (admin login: TOBY / 5429)"
Write-Host "  API docs:  http://localhost:8000/docs"
$lan = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" -and $_.PrefixOrigin -ne "WellKnown" } |
    Select-Object -First 1 -ExpandProperty IPAddress
if ($lan) {
    Write-Host "  Staff portal for guests on the same Wi-Fi: http://${lan}:5173" -ForegroundColor Yellow
    Write-Host "  (If Windows Firewall asks about Node.js, click 'Allow'.)"
}
Write-Host "To stop, close the 'SentinelAI API' and 'SentinelAI Dashboard' windows."
