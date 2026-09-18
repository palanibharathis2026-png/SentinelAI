# Makes a temporary public HTTPS link to the running dashboard, so guests on ANY network
# (mobile data, other Wi-Fi) can open the staff portal. Uses a free Cloudflare quick tunnel:
# no account needed, and the link stops working as soon as this window is closed.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$root = Split-Path -Parent $PSScriptRoot
$tools = Join-Path $root ".tools"
$exe = Join-Path $tools "cloudflared.exe"
$log = Join-Path $tools "tunnel.log"

function IsUp($url) {
    try { Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 2 | Out-Null; return $true } catch { return $false }
}

if (-not (IsUp "http://localhost:5173")) {
    Write-Host "SentinelAI is not running. Double-click start.bat first, then run share.bat again." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $exe)) {
    Write-Host "Downloading Cloudflare tunnel tool (one time, ~60 MB)..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Force $tools | Out-Null
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe" -OutFile $exe -UseBasicParsing
}

Remove-Item $log -ErrorAction SilentlyContinue
Write-Host "Creating public link..." -ForegroundColor Cyan
$proc = Start-Process $exe -ArgumentList "tunnel --no-autoupdate --url http://localhost:5173 --logfile `"$log`"" -PassThru -WindowStyle Hidden

$url = $null
$deadline = (Get-Date).AddSeconds(60)
while (-not $url -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 1
    if (Test-Path $log) {
        $m = Select-String -Path $log -Pattern "https://[a-z0-9-]+\.trycloudflare\.com" | Select-Object -First 1
        if ($m) { $url = $m.Matches[0].Value }
    }
}
if (-not $url) {
    Stop-Process -Id $proc.Id -ErrorAction SilentlyContinue
    Write-Host "Could not create the link. Check the internet connection and try again." -ForegroundColor Red
    exit 1
}

Set-Clipboard $url
Write-Host ""
Write-Host "  Public link (copied to clipboard):" -ForegroundColor Green
Write-Host "  $url" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Send it to your friend. They choose 'Staff portal' and sign in (e.g. rahul / 1957)."
Write-Host "  Anyone with the link sees the login page, so keep it within your demo."
Write-Host "  Close this window to switch the link off." -ForegroundColor Cyan
try { Wait-Process -Id $proc.Id } finally { Stop-Process -Id $proc.Id -ErrorAction SilentlyContinue }
