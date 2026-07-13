<#
    E2E widoku view.php - sciezki NIE pokryte glowna suite (run.ps1):
    formularz hasla v3 (submit liczy KDF, POST auth_tag, sessionStorage), inline
    prompt (fallback gdy brak mastera - tryb prywatny), uszkodzony #fragment,
    link bez hasla. Steruje przegladarka od tworzenia linku po odszyfrowanie.

    Osobno od run.ps1 bo: wymaga routera /uuid->view.php (glowna suite go nie ma),
    liczy PBKDF2 przez pelny flow, dluzsze. Odpalaj recznie po zmianach w:
    view.php (formularz v3 / decryptV3 / inline prompt) albo crypto.js.

    Uruchomienie: X:\tests\e2e-view.ps1
    Wymaga: PHP CLI + przegladarka Chromium. Exit 0 = all PASS.
#>
param([int]$TimeoutSec = 120)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$php = $env:BB_PHP
if (-not $php) { $php = 'C:\programy\php-8.5.7-nts-Win32-vs17-x64\php.exe' }
if (-not (Test-Path $php)) { $c = Get-Command php -ErrorAction SilentlyContinue; if ($c) { $php = $c.Source } }
if (-not (Test-Path $php)) { Write-Error "Nie znaleziono PHP."; exit 2 }

$browsers = @()
if ($env:BB_BROWSER) { $browsers += $env:BB_BROWSER }
$browsers += @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
)
$browser = $browsers | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $browser) { Write-Error "Nie znaleziono przegladarki."; exit 2 }

$port = 0
foreach ($p in 8340..8360) {
    if (-not (Test-NetConnection 127.0.0.1 -Port $p -WarningAction SilentlyContinue).TcpTestSucceeded) { $port = $p; break }
}
if ($port -eq 0) { Write-Error "Brak wolnego portu."; exit 2 }
$base = "http://127.0.0.1:$port"

$testData = Join-Path $env:TEMP ("bb-e2e-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $testData | Out-Null
$env:BB_TEST_DATA_DIR = $testData
$prepend = Join-Path $PSScriptRoot 'bootstrap.php'
$router = Join-Path $PSScriptRoot 'e2e-router.php'
$prof = Join-Path $env:TEMP ("bb-e2eprof-" + [guid]::NewGuid().ToString('N'))

function Stop-BrowserTree([string]$dir) {
    Get-CimInstance Win32_Process -Filter "Name='chrome.exe' OR Name='msedge.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains($dir) } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

Write-Host "E2E widoku na $base (router /uuid -> view.php)..."
$srv = Start-Process -FilePath $php -ArgumentList '-d', 'display_errors=0', '-d', "auto_prepend_file=$prepend", '-S', "127.0.0.1:$port", '-t', $root, $router -WindowStyle Hidden -PassThru
for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 250; if ((Test-NetConnection 127.0.0.1 -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded) { break } }

$exit = 1
try {
    $cr = Start-Process -FilePath $browser -ArgumentList '--headless=new', '--disable-gpu', '--no-sandbox', "--user-data-dir=$prof", '--no-first-run', "$base/tests/e2e-view.html" -PassThru -WindowStyle Hidden
    $resultFile = Join-Path $testData '_result.txt'
    # Czekaj na FINALNY wynik. Przyrostowe meldunki maja prefiks RUNNING; finalny
    # zaczyna sie od PASS/FAIL - inaczej zlapalibysmy niepelny raport po 1. kroku.
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $resultFile) { $peek = Get-Content $resultFile -Raw; if ($peek -match '^(PASS|FAIL)') { break } }
        Start-Sleep -Milliseconds 300
    }
    Stop-Process -Id $cr.Id -Force -ErrorAction SilentlyContinue
    Stop-BrowserTree $prof

    Write-Host ""
    if (Test-Path $resultFile) {
        $txt = Get-Content $resultFile -Raw
        ($txt -split "`n") | Where-Object { $_ -match '^(PASS|FAIL) ' } | ForEach-Object {
            $c = if ($_ -match '^PASS') { 'Green' } else { 'Red' }; Write-Host $_ -ForegroundColor $c
        }
        $fails = @(($txt -split "`n") | Where-Object { $_ -match '^FAIL ' }).Count
        $passes = @(($txt -split "`n") | Where-Object { $_ -match '^PASS ' }).Count
        $exit = if ($fails -eq 0 -and $passes -gt 0) { 0 } else { 1 }
        Write-Host ""
        $c = if ($exit -eq 0) { 'Green' } else { 'Red' }
        Write-Host "E2E-VIEW: $passes PASS / $fails FAIL" -ForegroundColor $c
    } else {
        Write-Host "BRAK MELDUNKU po $TimeoutSec s (e2e-view.html nie ukonczyl?)" -ForegroundColor Red
    }
}
finally {
    Stop-BrowserTree $prof
    if ($srv) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item $prof, $testData -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\BB_TEST_DATA_DIR -ErrorAction SilentlyContinue
}
exit $exit
