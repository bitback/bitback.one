<#
    bitback.one - weryfikacja renderu ANGIELSKIEGO (?lang=en) end-to-end.

    Renderuje KAZDA strone user-facing w wersji EN i sprawdza, ze nie wycieka
    zadna polska fraza:
      - slownikowe PL (inc/i18n.php przetlumaczone wartosci) - dociagane z PHP,
      - galezie ternary w view.php - z tests/en-blocklist.json.
    Dodatkowo raportuje (bez failowania) resztkowe polskie diakrytyki w widocznym
    tekscie - do wzrokowej kontroli (moga to byc tylko komentarze inline w JS).

    Zero polskich literalow w tym pliku CELOWO: PowerShell 5.1 czyta .ps1 bez BOM
    jako ANSI i psulby polskie znaki w skrypcie. Listy PL sa DANYMI (UTF-8 JSON /
    zrzut z PHP), nie kodem.

    Standalone (jak e2e-view.ps1): startuje wlasny serwer z temp DATA_DIR.
    Uruchomienie: X:\tests\verify-en.ps1
    Exit 0 = brak wyciekow, 1 = wyciek/blad renderu.
#>
param()

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$here = $PSScriptRoot
$root = Split-Path -Parent $here
$outDir = Join-Path $here 'output'
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory $outDir | Out-Null }

# --- PHP ---
$php = $env:BB_PHP
if (-not $php) { $php = 'C:\programy\php-8.5.7-nts-Win32-vs17-x64\php.exe' }
if (-not (Test-Path $php)) { $c = Get-Command php -ErrorAction SilentlyContinue; if ($c) { $php = $c.Source } }
if (-not (Test-Path $php)) { Write-Error "Nie znaleziono PHP. Ustaw `$env:BB_PHP."; exit 2 }

# --- PL blocklist: slownik (z PHP) + ternary (z JSON) ---
$diffFile = Join-Path $outDir 'i18n-pl-diff.json'
& $php (Join-Path $here 'dump-i18n-diff.php') $diffFile | Out-Null
if (-not (Test-Path $diffFile)) { Write-Error "Nie powstal zrzut i18n-pl-diff.json"; exit 2 }
$dict = Get-Content $diffFile -Raw -Encoding UTF8 | ConvertFrom-Json
$plStrings = @()
foreach ($p in $dict.PSObject.Properties) { $plStrings += [string]$p.Value }
$block = Get-Content (Join-Path $here 'en-blocklist.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$plStrings += @($block.phrases)
# Deduplikacja + odsiew krotkich (<5 znakow) - zbyt generyczne do bezpiecznego szukania podciagu.
$plStrings = @($plStrings | Where-Object { $_ -and $_.Length -ge 5 } | Select-Object -Unique)
Write-Host ("Blocklist PL: {0} fraz (slownik + ternary)" -f $plStrings.Count)

# --- wolny port ---
$port = 0
foreach ($p in 8221..8245) {
    if (-not (Test-NetConnection 127.0.0.1 -Port $p -WarningAction SilentlyContinue).TcpTestSucceeded) { $port = $p; break }
}
if ($port -eq 0) { Write-Error "Brak wolnego portu 8221-8245."; exit 2 }
$base = "http://127.0.0.1:$port"

# --- temp DATA_DIR (repo data/ read-only) ---
$testData = Join-Path $env:TEMP ("bb-en-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $testData | Out-Null
$env:BB_TEST_DATA_DIR = $testData
$prepend = Join-Path $here 'bootstrap.php'

Write-Host "Startuje serwer PHP (display_errors=0) na $base ..."
$srv = Start-Process -FilePath $php -ArgumentList '-d', 'display_errors=0', '-d', "auto_prepend_file=$prepend", '-S', "127.0.0.1:$port", '-t', $root -WindowStyle Hidden -PassThru
$up = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    if ((Test-NetConnection 127.0.0.1 -Port $port -WarningAction SilentlyContinue).TcpTestSucceeded) { $up = $true; break }
}
if (-not $up) { if ($srv) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }; Write-Error "Serwer PHP nie wstal."; exit 2 }

function GetPage($path) {
    $req = [System.Net.HttpWebRequest]::Create($base + $path); $req.Method = 'GET'
    $resp = $null
    try { $resp = $req.GetResponse() } catch [System.Net.WebException] { $resp = $_.Exception.Response }
    if (-not $resp) { return @{ code = -1; text = '' } }
    $code = [int]$resp.StatusCode
    $sr = New-Object IO.StreamReader($resp.GetResponseStream(), [Text.Encoding]::UTF8)
    $txt = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
    return @{ code = $code; text = $txt }
}
function PostJson($path, $obj) {
    $req = [System.Net.HttpWebRequest]::Create($base + $path)
    $req.Method = 'POST'; $req.ContentType = 'application/json'
    $json = ($obj | ConvertTo-Json -Depth 6 -Compress)
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $req.ContentLength = $bytes.Length
    $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
    $resp = $null
    try { $resp = $req.GetResponse() } catch [System.Net.WebException] { $resp = $_.Exception.Response }
    if ($resp) { $resp.Close() }
}
function b64($s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }

# Zapis rekordu wprost do DATA_DIR (omija antybot). $over nadpisuje pola.
function NewRecord([hashtable]$over) {
    $uuid = [guid]::NewGuid().ToString()
    $rec = @{
        id = $uuid; created = '2026-01-01T00:00:00Z'; expires_secrets = '2036-01-01T00:00:00Z'
        delete_after_days = 30; max_views = 15; current_views = 0; status = 'active'
        format = 3; kdf = $null; password_hash = $null; password_verifier = $null
        total_sections = 2; view_log = @()
        encrypted_text = (b64 'REC-TEXT'); encrypted_secrets = (b64 'REC-SECRET')
    }
    if ($over) { foreach ($k in $over.Keys) { $rec[$k] = $over[$k] } }
    $f = Join-Path $testData "$uuid.json"
    $rec | ConvertTo-Json -Depth 5 | Set-Content $f -Encoding UTF8
    return @{ uuid = $uuid; file = $f }
}

function Clean($html) {
    $s = [regex]::Replace($html, '<!--.*?-->', '', [Text.RegularExpressions.RegexOptions]::Singleline)
    $s = [regex]::Replace($s, '/\*.*?\*/', '', [Text.RegularExpressions.RegexOptions]::Singleline)
    $s = [regex]::Replace($s, '(?m)^\s*//.*$', '')
    return $s
}

$pass = 0; $fail = 0
$leaks = @()
$diacritics = [regex]'[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]'

# Sprawdza jedna wyrenderowana strone: brak PL-blocklist + obecnosc oczekiwanej frazy EN.
function CheckPage($label, $page, [string[]]$expectEn) {
    if ($page.code -lt 200 -or $page.code -ge 500) {
        Write-Host ("FAIL [{0}] kod HTTP {1}" -f $label, $page.code) -ForegroundColor Red
        $script:fail++; return
    }
    $clean = Clean $page.text
    $hits = @()
    foreach ($ph in $script:plStrings) {
        if ($clean.Contains([string]$ph)) { $hits += $ph }
    }
    if ($hits.Count -gt 0) {
        Write-Host ("FAIL [{0}] wyciek PL ({1}):" -f $label, $hits.Count) -ForegroundColor Red
        foreach ($h in ($hits | Select-Object -First 6)) { Write-Host ("       -> {0}" -f $h) -ForegroundColor Red }
        $script:fail++
        $script:leaks += [pscustomobject]@{ page = $label; hits = $hits }
    } else {
        Write-Host ("PASS [{0}] brak wyciekow PL" -f $label) -ForegroundColor Green
        $script:pass++
    }
    # Pozytyw: oczekiwana fraza EN musi byc na stronie (dowod, ze render poszedl w EN, nie blad).
    foreach ($e in $expectEn) {
        if ($page.text.Contains($e)) {
            Write-Host ("PASS [{0}] EN obecne: '{1}'" -f $label, $e) -ForegroundColor Green
            $script:pass++
        } else {
            Write-Host ("FAIL [{0}] brak oczekiwanego EN: '{1}'" -f $label, $e) -ForegroundColor Red
            $script:fail++
        }
    }
    # Info: resztkowe diakrytyki w oczyszczonym tekscie (nie failuje - zwykle komentarz inline).
    $dm = $diacritics.Matches($clean)
    if ($dm.Count -gt 0) {
        $ctx = @()
        foreach ($m in ($dm | Select-Object -First 3)) {
            $a = [Math]::Max(0, $m.Index - 30); $len = [Math]::Min(70, $clean.Length - $a)
            $ctx += ('...' + ($clean.Substring($a, $len) -replace '\s+', ' ') + '...')
        }
        Write-Host ("  info [{0}] resztkowe diakrytyki: {1} (kontekst do kontroli):" -f $label, $dm.Count) -ForegroundColor DarkYellow
        foreach ($c in $ctx) { Write-Host ("       {0}" -f $c) -ForegroundColor DarkGray }
    }
}

try {
    Write-Host ""; Write-Host "== RENDER EN =="

    # 1. index.php
    CheckPage 'index' (GetPage '/index.php?lang=en') @('Zero-trust encryption', 'secure links for sharing confidential data')

    # 2. 404.php (globalny)
    CheckPage '404.php' (GetPage '/404.php?lang=en') @('This link does not exist', 'Source code on')

    # 3. view.php -> wewnetrzny 404 (nieistniejacy slug)
    $randUuid = [guid]::NewGuid().ToString()
    CheckPage 'view/404' (GetPage "/view.php?slug=$randUuid&lang=en") @('This link does not exist', 'Source code on')

    # 4. formularz hasla v3
    $sha = '0000000000000000000000000000000000000000000000000000000000000000'
    $v3 = NewRecord @{ password_verifier = $sha; kdf = @{ alg = 'PBKDF2-SHA256'; iter = 600000 } }
    CheckPage 'pwd-form-v3' (GetPage "/view.php?slug=$($v3.uuid)&lang=en") @('This link is password protected', 'Source code on')
    Remove-Item $v3.file -Force -ErrorAction SilentlyContinue

    # 5. formularz hasla v2 (bcrypt, plaintext gate)
    $bcrypt = '$2y$12$RoAvDRjgJwqJyWAv73vWHuH2daBMn93D/Mukpgby2JRB08D2wRqy2'
    $v2 = NewRecord @{ format = 2; password_hash = $bcrypt; encrypted_secrets = $null }
    CheckPage 'pwd-form-v2' (GetPage "/view.php?slug=$($v2.uuid)&lang=en") @('This link is password protected', 'Source code on')
    Remove-Item $v2.file -Force -ErrorAction SilentlyContinue

    # 6. aktywny widok (bez hasla) - strona z blobem, zt-badge, przyciski wygaszenia
    $act = NewRecord @{}
    CheckPage 'active-view' (GetPage "/view.php?slug=$($act.uuid)&lang=en") @('decryption happened in your browser', 'expire secret data now', 'We secure email, servers and computers')
    Remove-Item $act.file -Force -ErrorAction SilentlyContinue

    # 7. widok po wygaszeniu sekretow (expires_secrets w przeszlosci)
    $exp = NewRecord @{ expires_secrets = '2020-01-01T00:00:00Z' }
    CheckPage 'secrets-expired' (GetPage "/view.php?slug=$($exp.uuid)&lang=en") @('We secure email, servers and computers')
    Remove-Item $exp.file -Force -ErrorAction SilentlyContinue

    # 8. link ubity (kill) -> show_expired z manualInfo
    $kill = NewRecord @{}
    PostJson '/api/expire.php' @{ uuid = $kill.uuid; action = 'kill' }
    CheckPage 'killed-expired' (GetPage "/view.php?slug=$($kill.uuid)&lang=en") @('This link has expired', 'Link was manually deleted on')
    Remove-Item $kill.file -Force -ErrorAction SilentlyContinue
}
finally {
    if ($srv) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item $testData -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\BB_TEST_DATA_DIR -ErrorAction SilentlyContinue
}

Write-Host ""
$col = if ($fail -eq 0) { 'Green' } else { 'Red' }
Write-Host ("VERIFY-EN: {0} PASS / {1} FAIL" -f $pass, $fail) -ForegroundColor $col
if ($fail -eq 0) { exit 0 } else { exit 1 }
