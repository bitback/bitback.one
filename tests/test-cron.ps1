<#
    Testy cron/cleanup.php - skrypt CLI, nieosiagalny przez HTTP.

    Odpala cleanup.php przez php.exe z auto_prepend_file=bootstrap.php i wlasnym
    izolowanym DATA_DIR (temp), wypelnionym recznie spreparowanymi rekordami w
    roznych stanach wygasania, po czym weryfikuje co trafilo do trash, co zostalo
    i czy sekrety zostaly fizycznie skasowane.

    Uruchomienie samodzielne: X:\tests\test-cron.ps1
    Wolany przez run.ps1. Exit 0 = all PASS, 1 = jakikolwiek FAIL.
#>
param([string]$Php)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Php) { $Php = $env:BB_PHP }
if (-not $Php) { $Php = 'C:\programy\php-8.5.7-nts-Win32-vs17-x64\php.exe' }
if (-not (Test-Path $Php)) { $c = Get-Command php -ErrorAction SilentlyContinue; if ($c) { $Php = $c.Source } }

$pass = 0; $fail = 0
function chk($name, $cond) {
    if ($cond) { Write-Host "PASS $name" -ForegroundColor Green; $script:pass++ }
    else { Write-Host "FAIL $name" -ForegroundColor Red; $script:fail++ }
}
function b64($s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }

$dir = Join-Path $env:TEMP ("bb-cron-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $dir | Out-Null
$trash = Join-Path $dir '_trash'
$rl = Join-Path $dir '_ratelimit'
New-Item -ItemType Directory $rl | Out-Null

function Rec($id, $over) {
    $rec = @{
        id = $id; created = '2026-01-01T00:00:00Z'; expires_secrets = '2036-01-01T00:00:00Z'
        delete_after_days = 30; max_views = 15; current_views = 0; status = 'active'
        format = 3; kdf = $null; password_hash = $null; password_verifier = $null
        total_sections = 1; view_log = @()
        encrypted_text = (b64 'T'); encrypted_secrets = (b64 'S')
    }
    foreach ($k in $over.Keys) { $rec[$k] = $over[$k] }
    $rec | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $dir "$id.json") -Encoding UTF8
}

$past = [DateTimeOffset]::UtcNow.AddDays(-10).ToUnixTimeSeconds()

# A: niewygasly -> zostaje, sekrety zostaja
Rec 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' @{}
# B: wygasly czasowo + delete=0 -> od razu do trash
Rec 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' @{ expires_secrets = '2020-01-01T00:00:00Z'; delete_after_days = 0 }
# C: wygasly + _secrets_expired_at 10 dni temu + delete=1 -> deleteAt minal -> trash
Rec 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' @{ expires_secrets = '2020-01-01T00:00:00Z'; delete_after_days = 1; _secrets_expired_at = $past }
# D: wygasly przez max_views, brak _secrets_expired_at, delete=30 -> oznaczenie, zostaje
Rec 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' @{ current_views = 20; max_views = 15 }
# E: uszkodzony JSON -> pomijany, nietkniety
Set-Content (Join-Path $dir 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee.json') 'to-nie-jest-json' -Encoding UTF8
# ratelimit: stary (3h) -> unlink; swiezy -> zostaje
Set-Content (Join-Path $rl 'old.json') '[]' -Encoding UTF8
Set-Content (Join-Path $rl 'fresh.json') '[]' -Encoding UTF8
[IO.File]::SetLastWriteTimeUtc((Join-Path $rl 'old.json'), (Get-Date).ToUniversalTime().AddHours(-3))

# --- ODPAL cleanup.php ---
$env:BB_TEST_DATA_DIR = $dir
$prepend = Join-Path $PSScriptRoot 'bootstrap.php'
& $Php -d "auto_prepend_file=$prepend" (Join-Path $root 'cron\cleanup.php') | Out-Null
Remove-Item Env:\BB_TEST_DATA_DIR -ErrorAction SilentlyContinue

function InData($id) { Test-Path (Join-Path $dir "$id.json") }
function InTrash($id) { Test-Path (Join-Path $trash "$id.json") }
function Sec($id) { (Get-Content (Join-Path $dir "$id.json") -Raw | ConvertFrom-Json).encrypted_secrets }

chk "cron: niewygasly zostaje w DATA, sekrety nietkniete" ((InData 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa') -and $null -ne (Sec 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'))
chk "cron: wygasly+delete=0 -> do TRASH, znika z DATA" ((InTrash 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb') -and -not (InData 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'))
chk "cron: wygasly+deleteAt minal -> do TRASH" ((InTrash 'cccccccc-cccc-4ccc-8ccc-cccccccccccc') -and -not (InData 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'))
chk "cron: wygasly przez max_views -> oznaczony, zostaje, sekrety skasowane" ((InData 'dddddddd-dddd-4ddd-8ddd-dddddddddddd') -and $null -eq (Sec 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'))
chk "cron: swiezo oznaczony ma _secrets_expired_at" ($null -ne (Get-Content (Join-Path $dir 'dddddddd-dddd-4ddd-8ddd-dddddddddddd.json') -Raw | ConvertFrom-Json)._secrets_expired_at)
chk "cron: uszkodzony JSON pomijany (nietkniety, zostaje)" ((InData 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee') -and (Get-Content (Join-Path $dir 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee.json') -Raw) -match 'nie-jest-json')
chk "cron: stary plik ratelimit skasowany" (-not (Test-Path (Join-Path $rl 'old.json')))
chk "cron: swiezy plik ratelimit zostaje" (Test-Path (Join-Path $rl 'fresh.json'))

Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
$col = 'Red'; if ($fail -eq 0) { $col = 'Green' }
Write-Host "CRON: $pass PASS / $fail FAIL" -ForegroundColor $col
if ($fail -eq 0) { exit 0 } else { exit 1 }
