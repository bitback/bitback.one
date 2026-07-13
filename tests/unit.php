<?php
/**
 * Testy jednostkowe czystych funkcji PHP (bez HTTP, bez serwera).
 *
 * Po co osobno od test-endpoint.ps1: antybot (HMAC, wygasanie, hash_equals),
 * generate_uuid i parytet kluczy i18n sa albo nieosiagalne przez HTTP, albo
 * osiagalne tylko posrednio - blad w nich zamaskowalby sie jako "400 math".
 *
 * Uruchomienie: php tests/unit.php     (exit 0 = all PASS, 1 = jakikolwiek FAIL)
 * Wolany przez tests/run.ps1.
 *
 * NIE dotyka DATA_DIR ani sieci. Sekretow z config.php nie wypisuje.
 */

require_once __DIR__ . '/../inc/config.php';
require_once __DIR__ . '/../inc/antibot.php';
require_once __DIR__ . '/../inc/crypto.php';
require_once __DIR__ . '/../inc/i18n.php';

$pass = 0;
$fail = 0;
$skip = 0;

function ok(bool $cond, string $name): void {
    global $pass, $fail;
    if ($cond) { $pass++; echo "PASS $name\n"; }
    else       { $fail++; echo "FAIL $name\n"; }
}

function skip(string $name, string $why): void {
    global $skip;
    $skip++;
    echo "SKIP $name ($why)\n";
}

echo "-- antibot (HMAC challenge) --\n";
$ch = antibot_challenge();
ok(is_int($ch['a']) && $ch['a'] >= 1 && $ch['a'] <= 15, 'antibot: a w zakresie 1..15');
ok(is_int($ch['b']) && $ch['b'] >= 1 && $ch['b'] <= 15, 'antibot: b w zakresie 1..15');
ok(preg_match('/^[0-9a-f]{64}$/', $ch['token']) === 1, 'antibot: token = hex64 (HMAC-SHA256)');
ok(antibot_verify($ch['a'], $ch['b'], $ch['exp'], $ch['token'], $ch['a'] + $ch['b']), 'antibot: poprawna odpowiedz przechodzi');
ok(!antibot_verify($ch['a'], $ch['b'], $ch['exp'], $ch['token'], $ch['a'] + $ch['b'] + 1), 'antibot: zla odpowiedz odrzucona');

// Podrobiony token: zmiana a/b bez przeliczenia HMAC.
ok(!antibot_verify($ch['a'] + 1, $ch['b'], $ch['exp'], $ch['token'], $ch['a'] + 1 + $ch['b']), 'antibot: podmiana a bez HMAC odrzucona');
ok(!antibot_verify($ch['a'], $ch['b'], $ch['exp'], str_repeat('0', 64), $ch['a'] + $ch['b']), 'antibot: zmyslony token odrzucony');
ok(!antibot_verify($ch['a'], $ch['b'], $ch['exp'], '', $ch['a'] + $ch['b']), 'antibot: pusty token odrzucony');
ok(!antibot_verify($ch['a'], $ch['b'], $ch['exp'], null, $ch['a'] + $ch['b']), 'antibot: token nie-string odrzucony');

// Wygasniecie i exp z przyszlosci (falszerstwo: bot chce token na zawsze).
$expOld = time() - 1;
$tokOld = hash_hmac('sha256', "3|4|$expOld", hash('sha256', IP_HASH_SALT . '|antibot-v1'));
ok(!antibot_verify(3, 4, $expOld, $tokOld, 7), 'antibot: token wygasly odrzucony (mimo poprawnego HMAC)');
$expFar = time() + ANTIBOT_TTL + 3600;
$tokFar = hash_hmac('sha256', "3|4|$expFar", hash('sha256', IP_HASH_SALT . '|antibot-v1'));
ok(!antibot_verify(3, 4, $expFar, $tokFar, 7), 'antibot: exp z dalekiej przyszlosci odrzucony (mimo poprawnego HMAC)');

// Token JEST wielokrotnego uzytku do czasu wygasniecia - swiadoma decyzja
// (stateless, bez sesji). Test pilnuje, zeby nikt nie "naprawil" tego przypadkiem.
ok(antibot_verify($ch['a'], $ch['b'], $ch['exp'], $ch['token'], $ch['a'] + $ch['b']), 'antibot: ten sam token przechodzi drugi raz (stateless, celowo)');

// Typy z JSON-a: klient przysyla stringi.
ok(antibot_verify((string)$ch['a'], (string)$ch['b'], (string)$ch['exp'], $ch['token'], (string)($ch['a'] + $ch['b'])), 'antibot: wartosci jako stringi (JSON) przechodza');

echo "\n-- generate_uuid --\n";
$u = generate_uuid();
ok(preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $u) === 1, 'generate_uuid: format v4 (wariant 89ab)');
$seen = [];
for ($i = 0; $i < 500; $i++) { $seen[generate_uuid()] = true; }
ok(count($seen) === 500, 'generate_uuid: 500 wywolan = 500 roznych (brak kolizji)');

// view.php przepuszcza slug tylko przez ten sam regex - kazdy uuid musi go przejsc.
$viewRegex = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';
$allMatch = true;
foreach (array_slice(array_keys($seen), 0, 200) as $cand) {
    if (!preg_match($viewRegex, $cand)) { $allMatch = false; break; }
}
ok($allMatch, 'generate_uuid: kazdy uuid przechodzi regex slugu z view.php');

echo "\n-- decrypt_secret / decrypt_payload (legacy CBC, tylko odczyt) --\n";
if (!function_exists('openssl_encrypt')) {
    // Lokalny PHP CLI bywa bez php.ini (zero rozszerzen). run.ps1 dokleja
    // -d extension=openssl, wiec normalnie te testy JADA. Skip zamiast falszywego PASS.
    skip('decrypt_secret / decrypt_payload (5 asercji)', 'brak rozszerzenia openssl');
} else {
    $hexKey = bin2hex(random_bytes(16));
    $key = hash('sha256', $hexKey, true);
    $iv = random_bytes(16);
    $plain = json_encode(['a' => 1, 'b' => 'zażółć gęślą jaźń']);
    $blob = base64_encode($iv . openssl_encrypt($plain, CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv));
    ok(decrypt_secret($blob, $hexKey) === $plain, 'decrypt_secret: round-trip z poprawnym kluczem');
    ok(decrypt_payload($blob, $hexKey) === ['a' => 1, 'b' => 'zażółć gęślą jaźń'], 'decrypt_payload: zwraca tablice');
    ok(decrypt_secret($blob, bin2hex(random_bytes(16))) === null, 'decrypt_secret: zly klucz -> null (nie wyjatek)');
    ok(decrypt_secret(base64_encode('krotkie'), $hexKey) === null, 'decrypt_secret: payload < 17B -> null');
    ok(decrypt_payload(base64_encode($iv . 'niejson'), $hexKey) === null, 'decrypt_payload: nie-JSON -> null');
}

echo "\n-- i18n --\n";
$pl = get_strings('pl');
$en = get_strings('en');
$missingEn = array_diff(array_keys($pl), array_keys($en));
$missingPl = array_diff(array_keys($en), array_keys($pl));
ok(count($missingEn) === 0, 'i18n: kazdy klucz PL ma odpowiednik EN' . (count($missingEn) ? ' (brak: ' . implode(',', $missingEn) . ')' : ''));
ok(count($missingPl) === 0, 'i18n: kazdy klucz EN ma odpowiednik PL' . (count($missingPl) ? ' (brak: ' . implode(',', $missingPl) . ')' : ''));

$emptyPl = array_keys(array_filter($pl, fn($v) => !is_string($v) || trim($v) === ''));
$emptyEn = array_keys(array_filter($en, fn($v) => !is_string($v) || trim($v) === ''));
ok(count($emptyPl) === 0, 'i18n: brak pustych wartosci PL' . (count($emptyPl) ? ' (' . implode(',', $emptyPl) . ')' : ''));
ok(count($emptyEn) === 0, 'i18n: brak pustych wartosci EN' . (count($emptyEn) ? ' (' . implode(',', $emptyEn) . ')' : ''));

// Ogonki: polskie teksty maja byc UTF-8 z diakrytykami (zakaz ASCII-fikacji).
ok(preg_match('/[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]/u', implode(' ', $pl)) === 1, 'i18n: PL ma polskie znaki (UTF-8)');
// preg z modyfikatorem /u zwraca false na niepoprawnym UTF-8 - nie wymaga mbstring.
$badUtf = [];
foreach ($pl + $en as $k => $v) { if (preg_match('//u', $v) !== 1) { $badUtf[] = $k; } }
ok(count($badUtf) === 0, 'i18n: wszystkie teksty to poprawny UTF-8' . (count($badUtf) ? ' (zle: ' . implode(',', $badUtf) . ')' : ''));

ok(get_strings('klingon') === $en, 'i18n: nieznany jezyk -> fallback EN');

// Klucze v3 uzywane przez view.php / index.php musza istniec w OBU jezykach.
$v3keys = ['password_checking', 'password_wrong_or_corrupt', 'password_js_required',
           'password_reenter', 'password_unrecoverable', 'password_generate', 'deriving_keys'];
$haveAll = true;
foreach ($v3keys as $k) { if (!isset($pl[$k], $en[$k])) { $haveAll = false; break; } }
ok($haveAll, 'i18n: wszystkie klucze v3 obecne w PL i EN');

// Regresja: pasek stopki "fixed" w szablonach NIE moze zaszywac polskiego
// "Kod zrodlowy na" - ma isc przez $t['footer_source'] (inaczej ?lang=en pokazuje PL).
// Sygnatura hardcode: </span> tuz przed literalem. view_footer_html (. $s . '...') i
// i18n.php (wartosc klucza) tego wzorca nie maja, wiec nie sa falszywym trafieniem.
$footerHardcode = [];
foreach (['index.php', 'view.php', '404.php'] as $tpl) {
    $src = file_get_contents(__DIR__ . '/../' . $tpl);
    if ($src !== false && strpos($src, "</span>Kod \xc5\xbar\xc3\xb3d\xc5\x82owy na") !== false) {
        $footerHardcode[] = $tpl;
    }
}
ok(count($footerHardcode) === 0, 'i18n: stopka fixed nie zaszywa PL (uzywa footer_source)' . (count($footerHardcode) ? ' (hardcode w: ' . implode(',', $footerHardcode) . ')' : ''));

// Regresja parytetu trim hasla otwarcia. Tworzenie (index.php) tnie haslo
// (linkPassword.value.trim()); otwieranie (view.php) MUSI ciac tak samo, inaczej
// spacja wiodaca/koncowa daje inny authTag niz uzyty przy tworzeniu -> falszywy
// blad hasla i lockout (np. klawiatura mobilna doklejajaca spacje / copy-paste).
// deriveMasterV3 bierze haslo jako surowe bajty (NFC + TextEncoder), wiec backslash
// i inne znaki sa bezpieczne - jedyne ryzyko rozjazdu to wlasnie trim po jednej stronie.
$idxSrc = file_get_contents(__DIR__ . '/../index.php');
$vwSrc  = file_get_contents(__DIR__ . '/../view.php');
echo "\n-- haslo: parytet trim create/view --\n";
ok(substr_count($idxSrc, "linkPassword').value.trim()") >= 2, 'trim: index.php tnie haslo przy tworzeniu (single + bulk)');
ok(strpos($vwSrc, "getElementById('pwdInput').value.trim()") !== false, 'trim: view.php formularz v3 tnie haslo');
ok(strpos($vwSrc, 'resolve(input.value.trim())') !== false, 'trim: view.php inline prompt tnie haslo');
ok(strpos($vwSrc, "getElementById('pwdInput').value,") === false, 'trim: brak nietrymowanego odczytu pwdInput (regresja)');
ok(strpos($vwSrc, 'resolve(input.value)') === false, 'trim: brak nietrymowanego resolve inline (regresja)');

echo "\n";
echo "UNIT: $pass PASS / $fail FAIL" . ($skip ? " / $skip SKIP" : '') . "\n";
exit($fail === 0 ? 0 : 1);
