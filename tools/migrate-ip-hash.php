<?php
/**
 * Migracja: zamienia surowe IP w view_log na sha256 hash (12 znaków)
 * Uruchom raz: php tools/migrate-ip-hash.php
 */

require_once __DIR__ . '/../inc/config.php';

$dir = DATA_DIR;
$files = glob($dir . '/*.json');
$total = count($files);
$migrated = 0;
$skipped = 0;
$errors = 0;

echo "=== Migracja IP -> ip_hash ===\n";
echo "Plików do sprawdzenia: $total\n\n";

foreach ($files as $file) {
    $data = json_decode(file_get_contents($file), true);
    if (!$data || !isset($data['view_log'])) {
        $skipped++;
        continue;
    }

    $changed = false;
    foreach ($data['view_log'] as &$entry) {
        if (isset($entry['ip'])) {
            $entry['ip_hash'] = substr(hash('sha256', $entry['ip'] . IP_HASH_SALT), 0, 12);
            unset($entry['ip']);
            $changed = true;
        }
    }
    unset($entry);

    if ($changed) {
        $result = file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
        if ($result === false) {
            echo "  BŁĄD: " . basename($file) . "\n";
            $errors++;
        } else {
            $migrated++;
        }
    } else {
        $skipped++;
    }
}

// Sprawdź też trash
$trashFiles = glob(TRASH_DIR . '/*.json');
$trashTotal = count($trashFiles);

foreach ($trashFiles as $file) {
    $data = json_decode(file_get_contents($file), true);
    if (!$data || !isset($data['view_log'])) {
        $skipped++;
        continue;
    }

    $changed = false;
    foreach ($data['view_log'] as &$entry) {
        if (isset($entry['ip'])) {
            $entry['ip_hash'] = substr(hash('sha256', $entry['ip'] . IP_HASH_SALT), 0, 12);
            unset($entry['ip']);
            $changed = true;
        }
    }
    unset($entry);

    if ($changed) {
        $result = file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
        if ($result === false) {
            echo "  BŁĄD: " . basename($file) . "\n";
            $errors++;
        } else {
            $migrated++;
        }
    } else {
        $skipped++;
    }
}

echo "Zmigrowano:  $migrated\n";
echo "Pominięto:   $skipped\n";
echo "Błędy:       $errors\n";
echo "Trash:       $trashTotal plików sprawdzonych\n";
echo "\nGotowe.\n";
