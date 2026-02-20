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
