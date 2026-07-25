<?php
/**
 * CRON: sprzątanie wygasłych linków → trash
 * Odpalać raz dziennie z Synology Task Scheduler:
 * php /volume.../web/bitback.one/cron/cleanup.php
 */

require_once __DIR__ . '/../inc/config.php';
require_once __DIR__ . '/../inc/harden.php';

// Codzienny backup self-healingu blokad WWW na katalogach runtime.
harden_runtime_dirs();

if (!is_dir(DATA_DIR)) exit;
if (!is_dir(TRASH_DIR)) mkdir(TRASH_DIR, 0755, true);

$now = time();
$count = 0;

foreach (glob(DATA_DIR . '/*.json') as $file) {
    // Read-modify-write pod exclusive lockiem - spojnie z view.php/expire.php.
    // Bez tego cron czyta stan sprzed rownoleglego zapisu i nadpisuje go swoja
    // kopia (np. kill z expire.php -> wskrzeszenie skasowanego linka).
    $fp = @fopen($file, 'r+');
    if ($fp === false) continue;
    flock($fp, LOCK_EX);
    $data = json_decode(stream_get_contents($fp), true);
    if (!is_array($data)) { fclose($fp); continue; }

    $secretsExpireTime = strtotime($data['expires_secrets'] ?? '2099-01-01');
    $viewsExceeded = ($data['current_views'] ?? 0) >= ($data['max_views'] ?? 9999);
    $secretsExpired = ($secretsExpireTime <= $now) || $viewsExceeded;

    if (!$secretsExpired) { fclose($fp); continue; }

    $needSave = false;

    // --- FIZYCZNE KASOWANIE SEKRETÓW (jeśli jeszcze nie usunięte) ---
    if (isset($data['encrypted_secrets'])) {
        $data['encrypted_secrets'] = null;
        $needSave = true;
    }

    $deleteDays = $data['delete_after_days'] ?? 30;

    // natychmiastowe usunięcie
    if ($deleteDays == 0) {
        fclose($fp); // zwolnij lock przed rename (Windows nie przenosi otwartego pliku)
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
        rewind($fp);
        ftruncate($fp, 0);
        fwrite($fp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        fflush($fp);
    }

    if ($expiredAt === null) { fclose($fp); continue; } // dopiero oznaczony, jeszcze nie czas

    $deleteAt = $expiredAt + ($deleteDays * 86400);
    if ($now >= $deleteAt) {
        fclose($fp); // zwolnij lock przed rename
        rename($file, TRASH_DIR . '/' . basename($file));
        $count++;
    } else {
        fclose($fp);
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
