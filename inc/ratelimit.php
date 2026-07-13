<?php
/**
 * Rate limit na IP — pliki na dysku
 */

function check_rate_limit(string $ip): bool {
    if (!is_dir(RATE_LIMIT_DIR)) {
        mkdir(RATE_LIMIT_DIR, 0755, true);
    }

    $file = RATE_LIMIT_DIR . '/' . md5($ip) . '.json';
    $now = time();
    $windowStart = $now - RATE_LIMIT_WINDOW;

    $timestamps = [];
    if (file_exists($file)) {
        $data = json_decode(file_get_contents($file), true);
        if (is_array($data)) {
            // filtruj stare wpisy
            $timestamps = array_filter($data, fn($t) => $t > $windowStart);
        }
    }

    if (count($timestamps) >= RATE_LIMIT_MAX) {
        return false; // limit przekroczony
    }

    $timestamps[] = $now;
    file_put_contents($file, json_encode(array_values($timestamps)), LOCK_EX);
    return true;
}

/**
 * Rate limit dla sciezki API (token). OSOBNY bucket per token (klucz = jawne id),
 * niezalezny od bucketow IP przegladarki. Prog: API_RATE_MAX (fallback 120/okno),
 * okno RATE_LIMIT_WINDOW. $suffix rozdziela bucket single od batch dla tego samego
 * tokena. Nazwa pliku bezpieczna (md5 na id) - id jest [A-Za-z0-9], ale trzymamy
 * spojnosc z bucketami IP.
 */
function check_token_rate_limit(string $tokenId, string $suffix = ''): bool {
    $max = defined('API_RATE_MAX') ? API_RATE_MAX : 120;
    $win = defined('RATE_LIMIT_WINDOW') ? RATE_LIMIT_WINDOW : 3600;
    if (!is_dir(RATE_LIMIT_DIR)) {
        mkdir(RATE_LIMIT_DIR, 0755, true);
    }
    $tag = $suffix !== '' ? "-$suffix" : '';
    $file = RATE_LIMIT_DIR . '/tok-' . md5($tokenId) . $tag . '.json';
    $now = time();
    $windowStart = $now - $win;
    $timestamps = [];
    if (file_exists($file)) {
        $data = json_decode(file_get_contents($file), true);
        if (is_array($data)) {
            $timestamps = array_filter($data, fn($t) => $t > $windowStart);
        }
    }
    if (count($timestamps) >= $max) {
        return false;
    }
    $timestamps[] = $now;
    file_put_contents($file, json_encode(array_values($timestamps)), LOCK_EX);
    return true;
}

/**
 * Rate limit dla batcha (bulk) - OSOBNY bucket i osobny prog liczony w
 * PACZKACH, nie rekordach (paczka >5 osob od razu przekroczylaby zwykly limit).
 * Fallbacki gdy stale nie zdefiniowane w config.php: 10 paczek / 3600 s.
 */
function check_batch_rate_limit(string $ip): bool {
    $max = defined('RATE_LIMIT_BATCH_MAX') ? RATE_LIMIT_BATCH_MAX : 10;
    $win = defined('RATE_LIMIT_BATCH_WINDOW') ? RATE_LIMIT_BATCH_WINDOW : 3600;
    if (!is_dir(RATE_LIMIT_DIR)) {
        mkdir(RATE_LIMIT_DIR, 0755, true);
    }
    $file = RATE_LIMIT_DIR . '/' . md5($ip) . '-batch.json';
    $now = time();
    $windowStart = $now - $win;
    $timestamps = [];
    if (file_exists($file)) {
        $data = json_decode(file_get_contents($file), true);
        if (is_array($data)) {
            $timestamps = array_filter($data, fn($t) => $t > $windowStart);
        }
    }
    if (count($timestamps) >= $max) {
        return false;
    }
    $timestamps[] = $now;
    file_put_contents($file, json_encode(array_values($timestamps)), LOCK_EX);
    return true;
}
