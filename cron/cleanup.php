<?php
/**
 * CRON: sprzątanie wygasłych linków → trash
 * Odpalać raz dziennie z Synology Task Scheduler:
 * php /volume.../web/bitback.one/cron/cleanup.php
 */

require_once __DIR__ . '/../inc/config.php';

if (!is_dir(DATA_DIR)) exit;
if (!is_dir(TRASH_DIR)) mkdir(TRASH_DIR, 0755, true);

$now = time();
$count = 0;

foreach (glob(DATA_DIR . '/*.json') as $file) {
    $data = json_decode(file_get_contents($file), true);
    if (!$data) continue;

    $secretsExpireTime = strtotime($data['expires_secrets'] ?? '2099-01-01');
    $viewsExceeded = ($data['current_views'] ?? 0) >= ($data['max_views'] ?? 9999);
    $secretsExpired = ($secretsExpireTime <= $now) || $viewsExceeded;

    if (!$secretsExpired) continue;

    $needSave = false;

    // --- FIZYCZNE KASOWANIE SEKRETÓW (jeśli jeszcze nie usunięte) ---
    if (isset($data['encrypted_secrets'])) {
        $data['encrypted_secrets'] = null;
        $needSave = true;
    }

    $deleteDays = $data['delete_after_days'] ?? 30;

    // natychmiastowe usunięcie
    if ($deleteDays == 0) {
        rename($file, TRASH_DIR . '/' . basename($file));
        $count++;
        continue;
    }

    // sprawdź kiedy secrety wygasły
    $expiredAt = $data['_secrets_expired_at'] ?? null;
    if ($expiredAt === null) {
        $data['_secrets_expired_at'] = $now;
        $needSave = true;
    }

    if ($needSave) {
        file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
    }

    if ($expiredAt === null) continue; // dopiero oznaczony, jeszcze nie czas

    $deleteAt = $expiredAt + ($deleteDays * 86400);
    if ($now >= $deleteAt) {
        rename($file, TRASH_DIR . '/' . basename($file));
        $count++;
    }
}

// sprzątnij stare pliki ratelimit (starsze niż 2h)
if (is_dir(RATE_LIMIT_DIR)) {
    foreach (glob(RATE_LIMIT_DIR . '/*.json') as $rlFile) {
        if (filemtime($rlFile) < $now - 7200) {
            unlink($rlFile);
        }
    }
}

echo date('Y-m-d H:i:s') . " — cleanup done, moved $count files to trash\n";
