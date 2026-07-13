<#
    Testy endpointow: api/create-batch.php, api/create.php, bramka hasla view.php.
    Wywolywane przez run.ps1 (podaje -BaseUrl serwera z display_errors=0 oraz
    -DataDir katalogu rekordow tego serwera).
    Standalone: uruchom najpierw serwer z display_errors=0, potem podaj -BaseUrl.

    Cross-version: uzywa HttpWebRequest (identyczny w PS 5.1 i PS 7) - NIE
    -SkipHttpErrorCheck (brak w 5.1).

    Testy czytajace zapisany rekord wymagaja zapisywalnego DataDir - repo data/
    jest read-only, wiec run.ps1 przekierowuje storage do temp (tests/bootstrap.php).
    Rate-limit jest tam podniesiony i celowo NIE jest przedmiotem tej suite.

    Exit code: 0 gdy wszystko PASS, 1 gdy jakikolwiek FAIL.
#>
param(
    [string]$BaseUrl = 'http://127.0.0.1:8199',
    # Katalog rekordow serwera testowego (run.ps1 podaje temp; patrz bootstrap.php).
    [string]$DataDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'data')
)

$pass = 0; $fail = 0
function chk($name, $cond) {
    if ($cond) { Write-Host "PASS $name" -ForegroundColor Green; $script:pass++ }
    else { Write-Host "FAIL $name" -ForegroundColor Red; $script:fail++ }
}
# PostJson: @{code; body} bez rzucania na 4xx/5xx, dziala w PS 5.1 i 7
function PostJson($path, $obj, $method = 'POST') {
    $url = $BaseUrl + $path
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Method = $method
    $req.ContentType = 'application/json'
    if ($method -ne 'GET' -and $null -ne $obj) {
        $json = ($obj | ConvertTo-Json -Depth 6 -Compress)
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        $req.ContentLength = $bytes.Length
        $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
    }
    $resp = $null
    try { $resp = $req.GetResponse() }
    catch [System.Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { return @{ code = -1; body = $null } } }
    $code = [int]$resp.StatusCode
    $sr = New-Object IO.StreamReader($resp.GetResponseStream())
    $txt = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
    $b = $null; try { $b = $txt | ConvertFrom-Json } catch {}
    return @{ code = $code; body = $b }
}
function b64($s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }

# PostJson z naglowkiem Authorization: Bearer (sciezka API/token)
function PostJsonAuth($path, $obj, $token) {
    $req = [System.Net.HttpWebRequest]::Create($BaseUrl + $path)
    $req.Method = 'POST'; $req.ContentType = 'application/json'
    $req.Headers.Add('Authorization', "Bearer $token")
    if ($null -ne $obj) {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($obj | ConvertTo-Json -Depth 6 -Compress))
        $req.ContentLength = $bytes.Length
        $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
    }
    $resp = $null
    try { $resp = $req.GetResponse() }
    catch [System.Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { return @{ code = -1; body = $null } } }
    $code = [int]$resp.StatusCode
    $sr = New-Object IO.StreamReader($resp.GetResponseStream())
    $txt = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
    $b = $null; try { $b = $txt | ConvertFrom-Json } catch {}
    return @{ code = $code; body = $b }
}

# POST surowego ciala (do testow zlego JSON) - $body idzie 1:1, bez ConvertTo-Json.
function PostRaw($path, $body, $ctype = 'application/json') {
    $req = [System.Net.HttpWebRequest]::Create($BaseUrl + $path)
    $req.Method = 'POST'; $req.ContentType = $ctype
    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$body)
    $req.ContentLength = $bytes.Length
    $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
    $resp = $null
    try { $resp = $req.GetResponse() }
    catch [System.Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { return @{ code = -1; body = $null } } }
    $code = [int]$resp.StatusCode
    $sr = New-Object IO.StreamReader($resp.GetResponseStream())
    $txt = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
    $b = $null; try { $b = $txt | ConvertFrom-Json } catch {}
    return @{ code = $code; body = $b }
}

# swiezy challenge (wspolny secret HMAC z serwera)
$ch = Invoke-RestMethod -Uri "$BaseUrl/api/challenge.php" -UseBasicParsing
$math = @{ math_a = $ch.a; math_b = $ch.b; math_exp = $ch.exp; math_token = $ch.token; math_answer = ([int]$ch.a + [int]$ch.b) }
$validRec = @{ encrypted_text = (b64 'AAAABBBBCCCC'); encrypted_secrets = $null; total_sections = 3 }

# 1. GET -> 405
chk "GET -> 405" ((PostJson '/api/create-batch.php' $null 'GET').code -eq 405)
# 2. honeypot -> ok:true + N falszywych linkow
$r = PostJson '/api/create-batch.php' (@{ website_url = 'http://bot'; records = @($validRec, $validRec) })
chk "honeypot -> ok:true + 2 linki" ($r.body.ok -eq $true -and $r.body.links.Count -eq 2)
# 3. zly math -> 400 math
$r = PostJson '/api/create-batch.php' (@{ math_a = 1; math_b = 1; math_exp = $ch.exp; math_token = $ch.token; math_answer = 999; records = @($validRec) })
chk "zly math -> 400 'math'" ($r.code -eq 400 -and $r.body.error -eq 'math')
# 4. 0 rekordow -> 400 batch_size
$r = PostJson '/api/create-batch.php' ($math + @{ records = @() })
chk "0 rekordow -> 400 'batch_size'" ($r.code -eq 400 -and $r.body.error -eq 'batch_size')
# 5. zly base64 -> 400 invalid_payload
$r = PostJson '/api/create-batch.php' ($math + @{ records = @(@{ encrypted_text = '@@@notb64@@@'; total_sections = 1 }) })
chk "zly base64 -> 400 'invalid_payload'" ($r.code -eq 400 -and $r.body.error -eq 'invalid_payload')
# 6. rekord = string (nie obiekt) -> 400 invalid_payload, NIE 500
$r = PostJson '/api/create-batch.php' ($math + @{ records = @('jestem stringiem') })
chk "rekord=string -> 400 'invalid_payload' (nie 500)" ($r.code -eq 400 -and $r.body.error -eq 'invalid_payload')
# 7. brak encrypted_text -> 400 invalid_payload
$r = PostJson '/api/create-batch.php' ($math + @{ records = @(@{ total_sections = 1 }) })
chk "brak encrypted_text -> 400 'invalid_payload'" ($r.code -eq 400 -and $r.body.error -eq 'invalid_payload')

# sha256 po ASCII hex - odpowiednik PHP hash('sha256', $tag)
function shaHex($s) { [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($s))).Replace('-','').ToLower() }
$dataDir = $DataDir

# ===== create.php v3: auth_tag zamiast hasla =====
Write-Host ""
Write-Host "-- create.php v3 --"
$tag = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8'
$kdf = @{ alg = 'PBKDF2-SHA256'; iter = 600000 }
$base = $math + @{ encrypted_text = (b64 'AAAABBBBCCCC'); encrypted_secrets = $null; total_sections = 1 }

# 1. plaintext password -> 400
$r = PostJson '/api/create.php' ($base + @{ password = 'jawne' })
chk "create: plaintext password -> 400 'plaintext_password'" ($r.code -eq 400 -and $r.body.error -eq 'plaintext_password')
# 2. zly auth_tag (za krotki / wielkie litery) -> 400
$r = PostJson '/api/create.php' ($base + @{ auth_tag = 'ABCD'; kdf = $kdf })
chk "create: zly auth_tag -> 400 'invalid_auth_tag'" ($r.code -eq 400 -and $r.body.error -eq 'invalid_auth_tag')
# 3. auth_tag bez kdf -> 400
$r = PostJson '/api/create.php' ($base + @{ auth_tag = $tag })
chk "create: auth_tag bez kdf -> 400 'invalid_kdf'" ($r.code -eq 400 -and $r.body.error -eq 'invalid_kdf')
# 4. kdf.iter poza zakresem -> 400
$r = PostJson '/api/create.php' ($base + @{ auth_tag = $tag; kdf = @{ alg = 'PBKDF2-SHA256'; iter = 10 } })
chk "create: iter=10 -> 400 'invalid_kdf'" ($r.code -eq 400 -and $r.body.error -eq 'invalid_kdf')
# 5. poprawny v3 z haslem -> ok + rekord ma verifier=sha256(tag), format=3, bez password_hash
$r = PostJson '/api/create.php' ($base + @{ auth_tag = $tag; kdf = $kdf })
chk "create: v3 z auth_tag -> ok:true" ($r.body.ok -eq $true)
$uuid = ($r.body.url -split '/')[-1]
$rec = Get-Content (Join-Path $dataDir "$uuid.json") -Raw | ConvertFrom-Json
chk "create: password_verifier == sha256(auth_tag)" ($rec.password_verifier -eq (shaHex $tag))
chk "create: format == 3, kdf.iter == 600000" ($rec.format -eq 3 -and $rec.kdf.iter -eq 600000)
chk "create: password_hash == null (brak bcrypt)" ($null -eq $rec.password_hash)
Remove-Item (Join-Path $dataDir "$uuid.json") -Force
# 6. poprawny v3 BEZ hasla -> ok, verifier null, format 3
$r = PostJson '/api/create.php' $base
chk "create: v3 bez hasla -> ok:true" ($r.body.ok -eq $true)
$uuid2 = ($r.body.url -split '/')[-1]
$rec2 = Get-Content (Join-Path $dataDir "$uuid2.json") -Raw | ConvertFrom-Json
chk "create: bez hasla -> verifier null, format 3" ($null -eq $rec2.password_verifier -and $rec2.format -eq 3)
Remove-Item (Join-Path $dataDir "$uuid2.json") -Force

# ===== create-batch.php v3 =====
Write-Host ""
Write-Host "-- create-batch v3 --"
$tagA = ('ab' * 32); $tagB = ('cd' * 32)
$recA = @{ encrypted_text = (b64 'AAAA'); encrypted_secrets = $null; total_sections = 1; auth_tag = $tagA }
$recB = @{ encrypted_text = (b64 'BBBB'); encrypted_secrets = $null; total_sections = 1; auth_tag = $tagB }
$recNoTag = @{ encrypted_text = (b64 'CCCC'); encrypted_secrets = $null; total_sections = 1 }

# 1. plaintext password -> 400
$r = PostJson '/api/create-batch.php' ($math + @{ password = 'jawne'; records = @($recNoTag) })
chk "batch: plaintext password -> 400" ($r.code -eq 400 -and $r.body.error -eq 'plaintext_password')
# 2. kdf obecne, rekord bez auth_tag -> 400
$r = PostJson '/api/create-batch.php' ($math + @{ kdf = $kdf; records = @($recA, $recNoTag) })
chk "batch: kdf + rekord bez auth_tag -> 400 'invalid_auth_tag'" ($r.code -eq 400 -and $r.body.error -eq 'invalid_auth_tag')
# 3. auth_tag bez kdf -> 400
$r = PostJson '/api/create-batch.php' ($math + @{ records = @($recA) })
chk "batch: auth_tag bez kdf -> 400 'invalid_auth_tag'" ($r.code -eq 400 -and $r.body.error -eq 'invalid_auth_tag')
# 4. poprawna paczka z haslem -> 2 linki, verifiery per rekord
$r = PostJson '/api/create-batch.php' ($math + @{ kdf = $kdf; records = @($recA, $recB) })
chk "batch: v3 z haslem -> ok + 2 linki" ($r.body.ok -eq $true -and $r.body.links.Count -eq 2)
$u0 = ($r.body.links[0].url -split '/')[-1]; $u1 = ($r.body.links[1].url -split '/')[-1]
$r0 = Get-Content (Join-Path $dataDir "$u0.json") -Raw | ConvertFrom-Json
$r1 = Get-Content (Join-Path $dataDir "$u1.json") -Raw | ConvertFrom-Json
chk "batch: verifier rekordu 0 = sha256(tagA)" ($r0.password_verifier -eq (shaHex $tagA))
chk "batch: verifier rekordu 1 = sha256(tagB) (rozne per rekord)" ($r1.password_verifier -eq (shaHex $tagB) -and $r0.password_verifier -ne $r1.password_verifier)
chk "batch: format 3 + kdf w obu" ($r0.format -eq 3 -and $r1.kdf.iter -eq 600000)
Remove-Item (Join-Path $dataDir "$u0.json"), (Join-Path $dataDir "$u1.json") -Force
# 5. paczka bez hasla -> verifier null
$r = PostJson '/api/create-batch.php' ($math + @{ records = @($recNoTag) })
chk "batch: bez hasla -> ok" ($r.body.ok -eq $true)
$u2 = ($r.body.links[0].url -split '/')[-1]
$r2 = Get-Content (Join-Path $dataDir "$u2.json") -Raw | ConvertFrom-Json
chk "batch: bez hasla -> verifier null, format 3" ($null -eq $r2.password_verifier -and $r2.format -eq 3)
Remove-Item (Join-Path $dataDir "$u2.json") -Force

# ===== API token auth (sciezka integratora, pomija antybot) =====
Write-Host ""
Write-Host "-- API token auth --"
# fixture: plik tokenow w DataDir (= API_TOKENS_FILE wg bootstrap.php).
$apiTokFile = Join-Path $dataDir 'api-tokens.txt'
$tokSecret = 'sekret_testowy_ABCDEFghijkl0123456789_XYZ'  # z podkresleniem: test parsowania
$tokId = 'testid01'
$tokHash = shaHex $tokSecret          # PHP hash('sha256',$secret) na ASCII
$goodToken = "bbk_${tokId}_${tokSecret}"
# drugi token: linia NAME-LESS "id hash" (format zero-trust prod, bez etykiety)
$tokSecret2 = 'drugi_sekret_nameless_9876543210_ABC'
$tokId2 = 'testid02'
$tokHash2 = shaHex $tokSecret2
$goodToken2 = "bbk_${tokId2}_${tokSecret2}"
# plik: linia z etykieta (wsteczna zgodnosc) + linia name-less (nowy standard) + komentarz
@("# komentarz pomijany", "Test Token - Jan  $tokId  $tokHash", "$tokId2  $tokHash2") | Set-Content $apiTokFile -Encoding ASCII
$noMath = @{ encrypted_text = (b64 'API-TEXT'); encrypted_secrets = $null; total_sections = 1 }

# 1. wazny token, BEZ math -> ok (antybot pominiety)
$r = PostJsonAuth '/api/create.php' $noMath $goodToken
chk "token: wazny Bearer bez math -> ok:true" ($r.body.ok -eq $true)
if ($r.body.url) { $tu0 = ($r.body.url -split '/')[-1]; Remove-Item (Join-Path $dataDir "$tu0.json") -Force -ErrorAction SilentlyContinue }
# 1b. token z linii NAME-LESS (bez etykiety) tez autoryzuje
$r = PostJsonAuth '/api/create.php' $noMath $goodToken2
chk "token: linia name-less 'id hash' autoryzuje -> ok:true" ($r.body.ok -eq $true)
if ($r.body.url) { $tu0b = ($r.body.url -split '/')[-1]; Remove-Item (Join-Path $dataDir "$tu0b.json") -Force -ErrorAction SilentlyContinue }
# 1c. ponow z pierwszym tokenem, zeby test #1 nizej mial url do sprawdzenia rekordu
$r = PostJsonAuth '/api/create.php' $noMath $goodToken
chk "token: wazny Bearer (labeled) ponownie -> ok:true" ($r.body.ok -eq $true)
if ($r.body.url) {
    $tu = ($r.body.url -split '/')[-1]; $tf = Join-Path $dataDir "$tu.json"
    $trec = Get-Content $tf -Raw | ConvertFrom-Json
    chk "token: rekord format 3, ZERO sladu tokena w rekordzie" ($trec.format -eq 3 -and -not ($trec.PSObject.Properties.Name -match 'token|api_'))
    Remove-Item $tf -Force
}
# 2. brak Bearer + brak math -> 400 'math' (sciezka przegladarki NIENARUSZONA)
$r = PostJson '/api/create.php' $noMath
chk "token: brak Bearer + brak math -> 400 'math' (browser path intact)" ($r.code -eq 400 -and $r.body.error -eq 'math')
# 3. zly sekret przy dobrym id -> 401
$r = PostJsonAuth '/api/create.php' $noMath "bbk_${tokId}_zlySekretInny"
chk "token: zly sekret -> 401 'invalid_token'" ($r.code -eq 401 -and $r.body.error -eq 'invalid_token')
# 4. nieznany id -> 401
$r = PostJsonAuth '/api/create.php' $noMath "bbk_nieznane_$tokSecret"
chk "token: nieznany id -> 401 'invalid_token'" ($r.code -eq 401 -and $r.body.error -eq 'invalid_token')
# 5. smieciowy Bearer (nie bbk_) -> 401
$r = PostJsonAuth '/api/create.php' $noMath "cokolwiek-losowego"
chk "token: zly format Bearer -> 401 'invalid_token'" ($r.code -eq 401 -and $r.body.error -eq 'invalid_token')
# 6. token na create-batch.php bez math -> ok + 2 linki
$recT = @{ encrypted_text = (b64 'BT'); encrypted_secrets = $null; total_sections = 1 }
$r = PostJsonAuth '/api/create-batch.php' @{ records = @($recT, $recT) } $goodToken
chk "token: batch bez math -> ok + 2 linki" ($r.body.ok -eq $true -and $r.body.links.Count -eq 2)
if ($r.body.links) { foreach ($l in $r.body.links) { $lu = ($l.url -split '/')[-1]; Remove-Item (Join-Path $dataDir "$lu.json") -Force -ErrorAction SilentlyContinue } }
# 7. rate-limit per token -> 429
Remove-Item (Join-Path $dataDir '_ratelimit') -Recurse -Force -ErrorAction SilentlyContinue
$limFileT = Join-Path $dataDir '_limits.json'
'{ "api": 2 }' | Set-Content $limFileT -Encoding UTF8
$codesT = @()
for ($i = 0; $i -lt 4; $i++) {
    $rr = PostJsonAuth '/api/create.php' (@{ encrypted_text = (b64 "AT$i"); total_sections = 1 }) $goodToken
    $codesT += $rr.code
    if ($rr.body.url) { $uu = ($rr.body.url -split '/')[-1]; Remove-Item (Join-Path $dataDir "$uu.json") -Force -ErrorAction SilentlyContinue }
}
chk "token: rate per token pod prog=2 -> 429" ($codesT -contains 429)
Remove-Item $limFileT -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $dataDir '_ratelimit') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $apiTokFile -Force -ErrorAction SilentlyContinue

# POST form-urlencoded (bramka view.php czyta $_POST, nie JSON)
function PostForm($path, $fields) {
    $url = $BaseUrl + $path
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Method = 'POST'
    $req.ContentType = 'application/x-www-form-urlencoded'
    $pairs = @(); foreach ($k in $fields.Keys) { $pairs += ([Uri]::EscapeDataString($k) + '=' + [Uri]::EscapeDataString([string]$fields[$k])) }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($pairs -join '&'))
    $req.ContentLength = $bytes.Length
    $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
    $resp = $null
    try { $resp = $req.GetResponse() }
    catch [System.Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { return @{ code = -1; text = '' } } }
    $code = [int]$resp.StatusCode
    $sr = New-Object IO.StreamReader($resp.GetResponseStream())
    $txt = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
    return @{ code = $code; text = $txt }
}
function GetPage($path) {
    $req = [System.Net.HttpWebRequest]::Create($BaseUrl + $path); $req.Method = 'GET'
    $resp = $null
    try { $resp = $req.GetResponse() } catch [System.Net.WebException] { $resp = $_.Exception.Response }
    $code = [int]$resp.StatusCode
    $sr = New-Object IO.StreamReader($resp.GetResponseStream()); $txt = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
    return @{ code = $code; text = $txt }
}
# Wbudowany serwer PHP ignoruje .htaccess (produkcja przepisuje /uuid -> view.php?slug=uuid),
# wiec testy bramki uderzaja wprost w view.php.
function ViewUrl($u) { "/view.php?slug=$u" }
function Views($f) { (Get-Content $f -Raw | ConvertFrom-Json).current_views }

# ===== bramka v3 (view.php) =====
Write-Host ""
Write-Host "-- bramka v3 (view.php) --"
$gateTag = ('12' * 32)
$r = PostJson '/api/create.php' ($math + @{ encrypted_text = (b64 'GATE-TEXT'); encrypted_secrets = $null; total_sections = 1; auth_tag = $gateTag; kdf = $kdf })
$gu = ($r.body.url -split '/')[-1]
$gFile = Join-Path $dataDir "$gu.json"
# GET -> formularz hasla, bez blobu, view nie policzony
$g = GetPage (ViewUrl $gu)
chk "gate: GET -> formularz (jest pwdForm, brak ENC_TEXT)" ($g.text -match 'pwdForm' -and $g.text -notmatch 'ENC_TEXT')
chk "gate: GET nie liczy view" ((Views $gFile) -eq 0)
# zly auth_tag -> formularz z bledem, bez blobu, view nie policzony
$g = PostForm (ViewUrl $gu) @{ auth_tag = ('00' * 32) }
chk "gate: zly auth_tag -> formularz, brak blobu" ($g.text -match 'pwdForm' -and $g.text -notmatch 'ENC_TEXT')
chk "gate: zly auth_tag nie liczy view" ((Views $gFile) -eq 0)
# pusty auth_tag (submit bez JS) -> formularz BEZ komunikatu bledu
$g = PostForm (ViewUrl $gu) @{ auth_tag = '' }
chk "gate: pusty auth_tag -> formularz (jak GET)" ($g.text -match 'pwdForm')
# dobry auth_tag -> strona widoku z blobem, view policzony
$g = PostForm (ViewUrl $gu) @{ auth_tag = $gateTag }
chk "gate: dobry auth_tag -> strona widoku (ENC_TEXT)" ($g.text -match 'ENC_TEXT')
chk "gate: dobry auth_tag liczy view (1)" ((Views $gFile) -eq 1)
Remove-Item $gFile -Force

# ===== regresja v2: bcrypt + plaintext gate (fixture) =====
Write-Host ""
Write-Host "-- regresja v2 (fixture bcrypt) --"
# bcrypt('test123') - wygenerowany raz: php -r "echo password_hash('test123', PASSWORD_BCRYPT);"
$bcrypt = '$2y$12$RoAvDRjgJwqJyWAv73vWHuH2daBMn93D/Mukpgby2JRB08D2wRqy2'
$v2uuid = [guid]::NewGuid().ToString()
$v2 = @{
    id = $v2uuid; created = '2026-01-01T00:00:00Z'; expires_secrets = '2036-01-01T00:00:00Z'
    delete_after_days = 30; max_views = 15; current_views = 0; status = 'active'
    password_hash = $bcrypt; total_sections = 1; view_log = @()
    encrypted_text = (b64 'V2-TEXT'); encrypted_secrets = $null
}
$v2File = Join-Path $dataDir "$v2uuid.json"
$v2 | ConvertTo-Json -Depth 4 | Set-Content $v2File -Encoding UTF8
$g = GetPage (ViewUrl $v2uuid)
chk "v2: GET -> formularz hasla (plaintext gate)" ($g.text -match 'name="password"')
$g = PostForm (ViewUrl $v2uuid) @{ password = 'zle-haslo' }
chk "v2: zle haslo -> formularz, view=0" ($g.text -match 'pwdForm' -and (Views $v2File) -eq 0)
$g = PostForm (ViewUrl $v2uuid) @{ password = 'test123' }
chk "v2: dobre haslo -> strona widoku (ENC_TEXT), view=1" ($g.text -match 'ENC_TEXT' -and (Views $v2File) -eq 1)
Remove-Item $v2File -Force

# Zapisuje rekord v3 wprost do DataDir (omija antybot/ratelimit) i zwraca uuid+plik.
# Do testow cyklu zycia (wygasanie, trash), ktorych nie da sie wywolac przez API.
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
    $f = Join-Path $dataDir "$uuid.json"
    $rec | ConvertTo-Json -Depth 5 | Set-Content $f -Encoding UTF8
    return @{ uuid = $uuid; file = $f }
}
function Field($f, $name) { (Get-Content $f -Raw | ConvertFrom-Json).$name }

# ===== create.php - gałęzie błędów (nie tylko v3 happy path) =====
Write-Host ""
Write-Host "-- create.php gałęzie błędów --"
chk "create: GET -> 405" ((PostJson '/api/create.php' $null 'GET').code -eq 405)
chk "create: zły JSON -> 400 'Invalid JSON'" ((PostRaw '/api/create.php' '{niepoprawny').body.error -eq 'Invalid JSON')
$r = PostJson '/api/create.php' (@{ website_url = 'http://bot'; encrypted_text = (b64 'x') })
chk "create: honeypot -> cichy sukces (url /ok, bez ok:true)" ($r.body.url -match '/ok$')
$r = PostJson '/api/create.php' (@{ math_a = 1; math_b = 1; math_exp = $ch.exp; math_token = $ch.token; math_answer = 999; encrypted_text = (b64 'x') })
chk "create: zła matematyka -> 400 'math'" ($r.code -eq 400 -and $r.body.error -eq 'math')
$r = PostJson '/api/create.php' ($math + @{ encrypted_text = '' })
chk "create: puste encrypted_text -> 400 'empty'" ($r.code -eq 400 -and $r.body.error -eq 'empty')
$r = PostJson '/api/create.php' ($math + @{ encrypted_text = '@@@' })
chk "create: zły base64 -> 400 'invalid_payload'" ($r.code -eq 400 -and $r.body.error -eq 'invalid_payload')
# kdf: górna granica + zły alg (dziś testowana tylko dolna)
$r = PostJson '/api/create.php' ($base + @{ auth_tag = $tag; kdf = @{ alg = 'PBKDF2-SHA256'; iter = 5000001 } })
chk "create: iter > 5000000 -> 400 'invalid_kdf'" ($r.code -eq 400 -and $r.body.error -eq 'invalid_kdf')
$r = PostJson '/api/create.php' ($base + @{ auth_tag = $tag; kdf = @{ alg = 'scrypt'; iter = 600000 } })
chk "create: zły alg kdf -> 400 'invalid_kdf'" ($r.code -eq 400 -and $r.body.error -eq 'invalid_kdf')

# --- clampy wartosci liczbowych ---
Write-Host "-- create.php clampy --"
$r = PostJson '/api/create.php' ($math + @{ encrypted_text = (b64 'CLAMP'); expire_days = 99999; max_views = 0; delete_after_days = -5; total_sections = 99999 })
$cu = ($r.body.url -split '/')[-1]; $cf = Join-Path $dataDir "$cu.json"
chk "clamp: expire_days 99999 -> 3650" ((Field $cf 'max_views') -ge 1 -and (Get-Content $cf -Raw | ConvertFrom-Json).delete_after_days -eq 0)
$recc = Get-Content $cf -Raw | ConvertFrom-Json
$eDays = [math]::Round(([datetime]$recc.expires_secrets - [datetime]$recc.created).TotalDays)
chk "clamp: expire_days -> ~3650 dni" ($eDays -ge 3649 -and $eDays -le 3651)
chk "clamp: max_views 0 -> 1 (min)" ($recc.max_views -eq 1)
chk "clamp: delete_after_days -5 -> 0 (min)" ($recc.delete_after_days -eq 0)
chk "clamp: total_sections 99999 -> 1000 (max)" ($recc.total_sections -eq 1000)
Remove-Item $cf -Force

# ===== api/expire.php - pełne pokrycie (dziś 0%) =====
Write-Host ""
Write-Host "-- api/expire.php --"
chk "expire: GET -> 405" ((PostJson '/api/expire.php' $null 'GET').code -eq 405)
chk "expire: zły JSON -> 400" ((PostRaw '/api/expire.php' 'xxx').body.error -eq 'Invalid JSON')
chk "expire: zły UUID (path traversal) -> 400 'Invalid UUID'" ((PostJson '/api/expire.php' @{ uuid = '../../inc/config'; action = 'kill' }).body.error -eq 'Invalid UUID')
chk "expire: zła action -> 400 'Invalid action'" ((PostJson '/api/expire.php' @{ uuid = [guid]::NewGuid().ToString(); action = 'nuke' }).body.error -eq 'Invalid action')
chk "expire: nieistniejący plik -> 404" ((PostJson '/api/expire.php' @{ uuid = [guid]::NewGuid().ToString(); action = 'expire' }).code -eq 404)
# uszkodzony JSON w pliku -> 500 Read error
$badId = [guid]::NewGuid().ToString(); $badF = Join-Path $dataDir "$badId.json"
Set-Content $badF 'to-nie-jest-json' -Encoding UTF8
chk "expire: uszkodzony JSON -> 500 'Read error'" ((PostJson '/api/expire.php' @{ uuid = $badId; action = 'expire' }).code -eq 500)
Remove-Item $badF -Force

# expire: kasuje TYLKO sekrety, tekst zostaje
$rec = NewRecord @{ delete_after_days = 30 }
$r = PostJson '/api/expire.php' @{ uuid = $rec.uuid; action = 'expire' }
chk "expire: ok, secrets skasowane, tekst zostaje" ($r.body.ok -eq $true -and $null -eq (Field $rec.file 'encrypted_secrets') -and $null -ne (Field $rec.file 'encrypted_text'))
chk "expire: ustawia _expired_manually" ($null -ne (Field $rec.file '_expired_manually'))
# idempotencja
$r = PostJson '/api/expire.php' @{ uuid = $rec.uuid; action = 'expire' }
chk "expire: drugi raz -> already_expired" ($r.body.already_expired -eq $true)
Remove-Item $rec.file -Force

# expire + delete_after_days==0 -> od razu do TRASH
$rec = NewRecord @{ delete_after_days = 0 }
$r = PostJson '/api/expire.php' @{ uuid = $rec.uuid; action = 'expire' }
$trashF = Join-Path $dataDir "_trash\$($rec.uuid).json"
chk "expire: delete_after_days=0 -> deleted:true, plik w TRASH nie w DATA" ($r.body.deleted -eq $true -and -not (Test-Path $rec.file) -and (Test-Path $trashF))
Remove-Item $trashF -Force

# kill: kasuje tekst I sekrety
$rec = NewRecord @{}
$r = PostJson '/api/expire.php' @{ uuid = $rec.uuid; action = 'kill' }
chk "kill: killed:true, tekst i sekrety null" ($r.body.killed -eq $true -and $null -eq (Field $rec.file 'encrypted_text') -and $null -eq (Field $rec.file 'encrypted_secrets'))
chk "kill: ustawia _killed_manually" ($null -ne (Field $rec.file '_killed_manually'))
$r = PostJson '/api/expire.php' @{ uuid = $rec.uuid; action = 'kill' }
chk "kill: drugi raz -> already_killed (idempotencja)" ($r.body.already_killed -eq $true)
Remove-Item $rec.file -Force

# kill czyści też stare formaty (encrypted_payload / sections)
$rec = NewRecord @{ encrypted_payload = (b64 'V2'); sections = @('a', 'b') }
$r = PostJson '/api/expire.php' @{ uuid = $rec.uuid; action = 'kill' }
chk "kill: legacy encrypted_payload i sections wyzerowane" ($null -eq (Field $rec.file 'encrypted_payload') -and $null -eq (Field $rec.file 'sections'))
Remove-Item $rec.file -Force

# ===== view.php - cykl zycia rekordu =====
Write-Host ""
Write-Host "-- view.php cykl zycia --"
# zły slug / path traversal -> not_found (regex UUID chroni; brak wycieku pliku)
$pt = GetPage '/view.php?slug=..%2f..%2finc%2fconfig'
chk "view: path traversal slug -> 404, brak wycieku config" ($pt.code -eq 404 -and $pt.text -notmatch 'IP_HASH_SALT|DATA_DIR')
# uszkodzony JSON -> not_found (nie 500 na produkcji)
$badId = [guid]::NewGuid().ToString(); $badF = Join-Path $dataDir "$badId.json"
Set-Content $badF 'niejson' -Encoding UTF8
chk "view: uszkodzony JSON -> nie renderuje bloba" ((GetPage (ViewUrl $badId)).text -notmatch 'ENC_TEXT')
Remove-Item $badF -Force

# LAZY DELETE: expires_secrets w przeszlosci -> pierwszy odczyt FIZYCZNIE kasuje secrets
$rec = NewRecord @{ expires_secrets = '2020-01-01T00:00:00Z' }
chk "lazy: przed odczytem secrets istnieja" ($null -ne (Field $rec.file 'encrypted_secrets'))
$null = GetPage (ViewUrl $rec.uuid)
chk "lazy: po odczycie secrets FIZYCZNIE skasowane (null)" ($null -eq (Field $rec.file 'encrypted_secrets'))
chk "lazy: tekst pozostaje (dwustopniowe wygasanie)" ($null -ne (Field $rec.file 'encrypted_text'))
chk "lazy: ustawione _secrets_expired_at" ($null -ne (Field $rec.file '_secrets_expired_at'))
Remove-Item $rec.file -Force

# MAX_VIEWS: ostatnie dozwolone wyswietlenie kasuje secrets w tym samym widoku
$rec = NewRecord @{ max_views = 1; expires_secrets = '2036-01-01T00:00:00Z' }
$g = GetPage (ViewUrl $rec.uuid)
chk "max_views: ostatni widok pokazuje tresc (ENC_TEXT)" ($g.text -match 'ENC_TEXT')
chk "max_views=1: po 1 widoku current_views=1" ((Field $rec.file 'current_views') -eq 1)
chk "max_views=1: sekrety skasowane po ostatnim widoku" ($null -eq (Field $rec.file 'encrypted_secrets'))
$g2 = GetPage (ViewUrl $rec.uuid)
chk "max_views: drugie wejscie -> sekrety juz wygasle (nie liczy dalej ponad max)" ((Field $rec.file 'current_views') -eq 1)
Remove-Item $rec.file -Force

# TRASH: wygasly + delete_after_days=0 -> plik przeniesiony do trash przy odczycie
$rec = NewRecord @{ expires_secrets = '2020-01-01T00:00:00Z'; delete_after_days = 0 }
$null = GetPage (ViewUrl $rec.uuid)
$trashF = Join-Path $dataDir "_trash\$($rec.uuid).json"
chk "trash: wygasly+delete=0 -> plik znika z DATA, jest w TRASH" (-not (Test-Path $rec.file) -and (Test-Path $trashF))
Remove-Item $trashF -Force -ErrorAction SilentlyContinue

# KILL przez API -> view.php pokazuje expired (encText null)
$rec = NewRecord @{}
$null = PostJson '/api/expire.php' @{ uuid = $rec.uuid; action = 'kill' }
$g = GetPage (ViewUrl $rec.uuid)
chk "po kill: view.php nie oddaje ENC_TEXT (link martwy)" ($g.text -notmatch 'ENC_TEXT')
Remove-Item $rec.file -Force -ErrorAction SilentlyContinue

# ===== rate-limit 429 =====
Write-Host ""
Write-Host "-- rate-limit 429 --"
# bootstrap.php czyta _limits.json per request; obniz prog, potem przywroc.
# Czysty bucket PRZED testem - wczesniejsze testy zapchaly go przy progu 100000.
Remove-Item (Join-Path $dataDir '_ratelimit') -Recurse -Force -ErrorAction SilentlyContinue
$limFile = Join-Path $dataDir '_limits.json'
'{ "single": 2, "batch": 2 }' | Set-Content $limFile -Encoding UTF8
$codes = @()
for ($i = 0; $i -lt 4; $i++) {
    $rr = PostJson '/api/create.php' ($math + @{ encrypted_text = (b64 "RL$i"); total_sections = 1 })
    $codes += $rr.code
    if ($rr.body.url) { $uu = ($rr.body.url -split '/')[-1]; Remove-Item (Join-Path $dataDir "$uu.json") -Force -ErrorAction SilentlyContinue }
}
chk "rate: 3. request pod prog=2 -> 429" ($codes[2] -eq 429 -or $codes[3] -eq 429)
$lastRL = PostJson '/api/create.php' ($math + @{ encrypted_text = (b64 'RLx'); total_sections = 1 })
chk "rate: kolejny nad progiem -> 429 'ratelimit'" ($lastRL.code -eq 429 -and $lastRL.body.error -eq 'ratelimit')
Remove-Item $limFile -Force -ErrorAction SilentlyContinue
# posprzataj bucket zeby nie zatru kolejnych testow w tym samym przebiegu
Remove-Item (Join-Path $dataDir '_ratelimit') -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
$col = 'Red'; if ($fail -eq 0) { $col = 'Green' }
Write-Host "ENDPOINT: $pass PASS / $fail FAIL" -ForegroundColor $col
if ($fail -eq 0) { exit 0 } else { exit 1 }
