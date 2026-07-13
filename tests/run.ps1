<#
    bitback.one - runner CALEJ suite testow (browser + endpoint).

    Co robi:
      1. Startuje WLASNY serwer PHP z display_errors=0 na wolnym porcie
         (deterministyczne kody HTTP - inaczej Warning wycieka i psuje status).
      2. Browser: renderuje tests/harness.html w headless Chromium. Harness laduje
         REALNY index.php w iframe i wola prawdziwe funkcje (bez kopii kodu -
         test nie dryfuje). Pokrywa FAZA 1-4 + crypto round-trip + galaz bulk.
      3. Endpoint: tests/test-endpoint.ps1 - walidacja api/create*.php + bramka view.php.
      4. Laczy wyniki, zwraca exit 0 (all PASS) / 1 (jakikolwiek FAIL).
         Zrzut browser suite -> tests/output/suite.png.

    Uruchomienie (PowerShell 5.1 lub 7):
      X:\tests\run.ps1

    Wymaga: PHP CLI + przegladarka Chromium (Chrome lub Edge).
    PHP nadpisywalny przez $env:BB_PHP, przegladarka przez $env:BB_BROWSER.

    Gotcha (dwa razy przepalone): momentu ukonczenia suite NIE da sie obstawic
    czasem. --dump-dom bywa martwy w danym wydaniu Chromium (Edge 150 zwraca
    0 bajtow, bez bledu), a --virtual-time-budget odmierza czas WIRTUALNY i wygasa
    w trakcie realnego PBKDF2, ucinajac suite w losowym miejscu. Dlatego harness
    sam melduje wynik do tests/collect.php, a runner czeka na ten plik.
    Zrzut PNG jest wylacznie diagnostyczny i moze byc niepelny.
#>

param([int]$BrowserTimeoutSec = 120)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot   # X:\
$outDir = Join-Path $PSScriptRoot 'output'
$shot = Join-Path $outDir 'suite.png'
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory $outDir | Out-Null }

# --- PHP ---
$php = $env:BB_PHP
if (-not $php) { $php = 'C:\programy\php-8.5.7-nts-Win32-vs17-x64\php.exe' }
if (-not (Test-Path $php)) { $c = Get-Command php -ErrorAction SilentlyContinue; if ($c) { $php = $c.Source } }
if (-not (Test-Path $php)) { Write-Error "Nie znaleziono PHP. Ustaw `$env:BB_PHP na sciezke php.exe."; exit 2 }

# --- przegladarka (pierwsza znaleziona; dowolny Chromium wystarczy) ---
$browsers = @()
if ($env:BB_BROWSER) { $browsers += $env:BB_BROWSER }
$browsers += @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
)
$browsers = @($browsers | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)
if ($browsers.Count -eq 0) { Write-Error "Nie znaleziono Chrome ani Edge. Ustaw `$env:BB_BROWSER."; exit 2 }

# --- wolny port (display_errors=0 serwer) ---
$port = 0
foreach ($p in 8199..8220) {
    if (-not (Test-NetConnection 127.0.0.1 -Port $p -WarningAction SilentlyContinue).TcpTestSucceeded) { $port = $p; break }
}
if ($port -eq 0) { Write-Error "Brak wolnego portu 8199-8220."; exit 2 }
$base = "http://127.0.0.1:$port"

# Storage testowy: repo data/ jest read-only i trzyma realne rekordy.
# tests/bootstrap.php przekierowuje DATA_DIR tutaj (szczegoly w tym pliku).
$testData = Join-Path $env:TEMP ("bb-data-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $testData | Out-Null
$env:BB_TEST_DATA_DIR = $testData
$prepend = Join-Path $PSScriptRoot 'bootstrap.php'

Write-Host "Startuje serwer PHP (display_errors=0) na $base (root $root)..."
$srv = Start-Process -FilePath $php -ArgumentList '-d', 'display_errors=0', '-d', "auto_prepend_file=$prepend", '-S', "127.0.0.1:$port", '-t', $root -WindowStyle Hidden -PassThru
$up = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    if ((Test-NetConnection 127.0.0.1 -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded) { $up = $true; break }
}
if (-not $up) { if ($srv) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }; Write-Error "Serwer PHP nie wstal."; exit 2 }

$prof = Join-Path $env:TEMP ("bb-test-" + [guid]::NewGuid().ToString('N'))

# Ubij CALE drzewo przegladarki po unikalnym katalogu profilu.
# Stop-Process na PID ze Start-Process nie wystarcza: Edge startuje wlasciwy
# proces glowny odczepiony od launchera, wiec launcher ginie, a renderery,
# gpu-process i crashpad zostaja w tle (Chrome akurat sprzata po sobie sam).
function Stop-BrowserTree([string]$profileDir) {
    Get-CimInstance Win32_Process -Filter "Name='chrome.exe' OR Name='msedge.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains($profileDir) } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

$browserVerdict = 'FAIL'; $browserPass = 0; $browserTotal = 0; $endpointExit = 1; $unitExit = 1; $cronExit = 1
try {
    # --- BROWSER SUITE (czekamy na meldunek harnessu, nie na zegar) ---
    $url = "$base/tests/harness.html"
    $resultFile = Join-Path $testData '_result.txt'
    $browser = $browsers[0]
    $chromeArgs = @('--headless=new', '--disable-gpu', '--no-sandbox', "--user-data-dir=$prof", '--no-first-run', $url)
    $cr = Start-Process -FilePath $browser -ArgumentList $chromeArgs -PassThru -WindowStyle Hidden
    $deadline = (Get-Date).AddSeconds($BrowserTimeoutSec)
    while ((Get-Date) -lt $deadline -and -not (Test-Path $resultFile)) { Start-Sleep -Milliseconds 250 }
    Stop-Process -Id $cr.Id -Force -ErrorAction SilentlyContinue
    Stop-BrowserTree $prof
    Remove-Item $prof -Recurse -Force -ErrorAction SilentlyContinue

    $m = $null
    $resultText = ''
    if (Test-Path $resultFile) {
        $resultText = Get-Content $resultFile -Raw
        $m = [regex]::Match($resultText, '^(PASS|FAIL) (\d+)/(\d+)')
    }
    # Zrzut PNG: osobny przebieg, best-effort (moze zlapac suite w polowie).
    & $browser --headless=new --disable-gpu --no-sandbox --user-data-dir=$prof --hide-scrollbars --virtual-time-budget=25000 --window-size=1100,1400 --screenshot="$shot" $url 2>$null | Out-Null

    if ($m -and $m.Success) { $browserVerdict = $m.Groups[1].Value; $browserPass = [int]$m.Groups[2].Value; $browserTotal = [int]$m.Groups[3].Value }

    Write-Host ""
    Write-Host "== BROWSER SUITE =="
    if ($m -and $m.Success) {
        $bc = if ($browserVerdict -eq 'PASS') { 'Green' } else { 'Red' }
        Write-Host "$browserVerdict ($browserPass/$browserTotal)  [$(Split-Path -Leaf $browser)]  zrzut: $shot" -ForegroundColor $bc
        if ($browserVerdict -eq 'FAIL') {
            ($resultText -split "`n") | Where-Object { $_ -match '^FAIL ' } | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        }
    } else {
        Write-Host "BRAK MELDUNKU z harnessu po $BrowserTimeoutSec s (przegladarka: $(Split-Path -Leaf $browser)). Zrzut: $shot" -ForegroundColor Red
    }

    # --- ENDPOINT SUITE ---
    Write-Host ""
    Write-Host "== ENDPOINT SUITE =="
    & (Join-Path $PSScriptRoot 'test-endpoint.ps1') -BaseUrl $base -DataDir $testData
    $endpointExit = $LASTEXITCODE

    # --- UNIT SUITE (czyste funkcje PHP, bez HTTP) ---
    # -d extension=openssl: ten PHP CLI startuje bez php.ini, wiec rozszerzenia
    # trzeba dolozyc jawnie. Bez tego testy legacy CBC same sie oznacza jako SKIP.
    Write-Host ""
    Write-Host "== UNIT SUITE (PHP) =="
    $ext = Join-Path (Split-Path -Parent $php) 'ext'
    & $php -d "extension_dir=$ext" -d extension=openssl (Join-Path $PSScriptRoot 'unit.php')
    $unitExit = $LASTEXITCODE

    # --- CRON SUITE (cleanup.php, CLI, wlasny izolowany DATA_DIR) ---
    Write-Host ""
    Write-Host "== CRON SUITE (cleanup.php) =="
    & (Join-Path $PSScriptRoot 'test-cron.ps1') -Php $php
    $cronExit = $LASTEXITCODE
}
finally {
    Stop-BrowserTree $prof   # takze gdy suite przerwana w polowie (Ctrl+C, timeout, blad)
    Remove-Item $prof -Recurse -Force -ErrorAction SilentlyContinue
    if ($srv) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item $testData -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\BB_TEST_DATA_DIR -ErrorAction SilentlyContinue
}

$ok = ($browserVerdict -eq 'PASS' -and $browserTotal -gt 0 -and $endpointExit -eq 0 -and $unitExit -eq 0 -and $cronExit -eq 0)
Write-Host ""
$fc = if ($ok) { 'Green' } else { 'Red' }
Write-Host ("OVERALL: " + $(if ($ok) { 'PASS' } else { 'FAIL' }) + "  (browser $browserPass/$browserTotal, endpoint exit $endpointExit, unit exit $unitExit, cron exit $cronExit)") -ForegroundColor $fc
if ($ok) { exit 0 } else { exit 1 }
