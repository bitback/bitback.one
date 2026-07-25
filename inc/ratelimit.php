<?php
/**
 * Rate limit — pliki na dysku, jeden algorytm dla wszystkich bucketow.
 *
 * Bucket = plik JSON z lista timestampow w oknie. Nazwy plikow sa czescia
 * kontraktu (istniejace bucket-y na produkcji): md5(ip).json, md5(ip)-batch.json,
 * tok-md5(id)[-suffix].json, pwd-md5(ip).json.
 */

/** Sciezka bucketu. $key jest juz bezpieczny (md5 + staly prefiks/sufiks). */
function rl_file(string $key): string {
    if (!is_dir(RATE_LIMIT_DIR)) {
        mkdir(RATE_LIMIT_DIR, 0755, true);
    }
    return RATE_LIMIT_DIR . '/' . $key . '.json';
}

/** Timestampy mieszczace sie w oknie (stare odfiltrowane). */
function rl_recent(string $key, int $window): array {
    $file = rl_file($key);
    if (!file_exists($file)) return [];
    $data = json_decode((string)file_get_contents($file), true);
    if (!is_array($data)) return [];
    $windowStart = time() - $window;
    return array_values(array_filter($data, fn($t) => $t > $windowStart));
}

/** Dopisz zdarzenie do bucketu (przycinajac stare). */
function rl_add(string $key, int $window): void {
    $timestamps = rl_recent($key, $window);
    $timestamps[] = time();
    file_put_contents(rl_file($key), json_encode($timestamps), LOCK_EX);
}

/** Czy pod progiem? Gdy tak - rejestruje zdarzenie i zwraca true. */
function rl_hit(string $key, int $max, int $window): bool {
    $timestamps = rl_recent($key, $window);
    if (count($timestamps) >= $max) {
        return false; // limit przekroczony
    }
    $timestamps[] = time();
    file_put_contents(rl_file($key), json_encode($timestamps), LOCK_EX);
    return true;
}

/** Czy prog juz przekroczony? Samo sprawdzenie, BEZ rejestrowania zdarzenia. */
function rl_exceeded(string $key, int $max, int $window): bool {
    return count(rl_recent($key, $window)) >= $max;
}

function check_rate_limit(string $ip): bool {
    return rl_hit(md5($ip), RATE_LIMIT_MAX, RATE_LIMIT_WINDOW);
}

/**
 * Rate limit dla sciezki API (token). OSOBNY bucket per token (klucz = jawne id),
 * niezalezny od bucketow IP przegladarki. Prog: API_RATE_MAX (fallback 120/okno).
 * $suffix rozdziela bucket single od batch dla tego samego tokena.
 */
function check_token_rate_limit(string $tokenId, string $suffix = ''): bool {
    $max = defined('API_RATE_MAX') ? API_RATE_MAX : 120;
    $win = defined('RATE_LIMIT_WINDOW') ? RATE_LIMIT_WINDOW : 3600;
    $tag = $suffix !== '' ? "-$suffix" : '';
    return rl_hit('tok-' . md5($tokenId) . $tag, $max, $win);
}

/**
 * Rate limit dla batcha (bulk) - OSOBNY bucket i osobny prog liczony w
 * PACZKACH, nie rekordach (paczka >5 osob od razu przekroczylaby zwykly limit).
 */
function check_batch_rate_limit(string $ip): bool {
    $max = defined('RATE_LIMIT_BATCH_MAX') ? RATE_LIMIT_BATCH_MAX : 10;
    $win = defined('RATE_LIMIT_BATCH_WINDOW') ? RATE_LIMIT_BATCH_WINDOW : 3600;
    return rl_hit(md5($ip) . '-batch', $max, $win);
}

/**
 * Bramka hasla otwarcia: throttling NIEUDANYCH prob, per IP.
 *
 * Bucket celowo po IP, NIE po uuid - inaczej ktokolwiek zna link moglby go
 * zaryglowac legalnemu odbiorcy (lockout-DoS). Liczone sa wylacznie porazki,
 * wiec poprawne haslo nigdy nie zjada budzetu.
 *
 * Chroni przed: online brute-force slabego hasla usera oraz CPU-DoS na legacy
 * v2 (kazda proba to bcrypt ~100 ms serwera).
 */
function pwd_rate_key(string $ip): string {
    return 'pwd-' . md5($ip);
}

function pwd_rate_window(): int {
    return defined('PWD_RATE_WINDOW') ? PWD_RATE_WINDOW : 3600;
}

/** Czy IP wyczerpal limit nieudanych prob hasla? */
function pwd_rate_blocked(string $ip): bool {
    $max = defined('PWD_RATE_MAX') ? PWD_RATE_MAX : 20;
    return rl_exceeded(pwd_rate_key($ip), $max, pwd_rate_window());
}

/** Zarejestruj NIEUDANA probe hasla. */
function pwd_rate_fail(string $ip): void {
    rl_add(pwd_rate_key($ip), pwd_rate_window());
}
