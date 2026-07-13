<?php
/**
 * Autoryzacja API tokenem (wzorzec Stripe: jawny id + sekret, serwer trzyma odcisk).
 *
 * Token dawany integratorowi: bbk_<id>_<sekret>
 *   - bbk_        prefiks (grep + skanery wyciekow rozpoznaja credential)
 *   - <id>        jawny handle (base32), losowy, NIEZALEZNY od sekretu
 *   - <sekret>    32 B base64url (256-bit entropii)
 *
 * Plik inc/api-tokens.txt (gitignored, web-denied): linia = "etykieta  id  sha256(sekret)".
 * W pliku ZERO materialu sekretnego - wyciek pliku ujawnia tylko etykiety, jawne
 * id i odciski. Serwer liczy sha256(sekret) z zadania i porownuje constant-time.
 * Hash chroni PLIK w spoczynku; TLS chroni token w transmisji.
 *
 * Token = bramka (pomija antybot) + klucz rate-bucketu. NIE trafia do rekordu.
 *
 * GOTCHA produkcja (Apache): naglowek Authorization bywa strippowany, zanim dojdzie
 * do PHP. php -S przekazuje go jako HTTP_AUTHORIZATION. Na Apache moze byc potrzebne
 * `CGIPassAuth On` albo w .htaccess:
 *   RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
 * Sprawdzamy tez REDIRECT_HTTP_AUTHORIZATION i getallheaders() jako fallback.
 */

function api_tokens_file(): string {
    return defined('API_TOKENS_FILE') ? API_TOKENS_FILE : __DIR__ . '/api-tokens.txt';
}

/** Surowa wartosc naglowka Authorization (roznymi drogami wg SAPI). */
function api_bearer_raw(): string {
    $h = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if ($h === '' && function_exists('getallheaders')) {
        foreach (getallheaders() as $k => $v) {
            if (strcasecmp($k, 'Authorization') === 0) { $h = (string)$v; break; }
        }
    }
    return is_string($h) ? $h : '';
}

/** Znajdz wpis po jawnym id. Zwraca ['label','id','hash'] albo null. */
function api_token_lookup(string $id): ?array {
    if ($id === '' || !preg_match('/^[A-Za-z0-9]{1,64}$/', $id)) return null;
    $file = api_tokens_file();
    if (!is_file($file)) return null;
    $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) return null;
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        $parts = preg_split('/\s+/', $line);
        if (count($parts) < 2) continue;           // minimum: id + hash (etykieta OPCJONALNA)
        $hash = array_pop($parts);
        $tid = array_pop($parts);
        $label = implode(' ', $parts);             // '' gdy linia jest name-less "id hash" (zero-trust)
        if (!preg_match('/^[0-9a-f]{64}$/', $hash)) continue;  // pomijaj smieciowe linie
        if ($tid === $id) {                        // id jawne - zwykle porownanie
            return ['label' => $label, 'id' => $tid, 'hash' => $hash];
        }
    }
    return null;
}

/**
 * Wynik autoryzacji:
 *   ['present'=>false, ...]                       brak naglowka Bearer -> sciezka przegladarki
 *   ['present'=>true,  'label'=>null, 'id'=>null] Bearer obecny ale NIEwazny -> 401
 *   ['present'=>true,  'label'=>'...', 'id'=>'..'] token wazny -> sciezka API
 */
function api_auth(): array {
    $none = ['present' => false, 'label' => null, 'id' => null];
    $bad  = ['present' => true,  'label' => null, 'id' => null];

    $raw = api_bearer_raw();
    if ($raw === '' || stripos($raw, 'Bearer ') !== 0) return $none;

    $token = trim(substr($raw, 7));
    if (strncmp($token, 'bbk_', 4) !== 0) return $bad;
    $rest = substr($token, 4);
    $pos = strpos($rest, '_');
    if ($pos === false || $pos === 0) return $bad;
    $id = substr($rest, 0, $pos);
    $secret = substr($rest, $pos + 1);
    if ($secret === '') return $bad;

    $entry = api_token_lookup($id);
    if ($entry === null) return $bad;

    $computed = hash('sha256', $secret);
    if (!hash_equals($entry['hash'], $computed)) return $bad;

    return ['present' => true, 'label' => $entry['label'], 'id' => $entry['id']];
}
