<?php
/**
 * Self-healing ochrona katalogow runtime (data/, trash/, _ratelimit/).
 *
 * Te katalogi powstaja w czasie dzialania przez PHP i sa gitignored, wiec
 * ich .htaccess NIE przychodzi z repo - swiezy deployment ma je odsloniete
 * dopoki ktos recznie nie wrzuci blokady. Ta funkcja gwarantuje, ze kazdy
 * ma aktualny plik blokujacy dostep WWW.
 *
 * PHP jest wlascicielem tych plikow (sam je tworzy), wiec moze je pisac
 * nawet gdy z poziomu SMB/innego usera sa read-only (przypadek dysku
 * sieciowego Synology).
 *
 * Skladnia dualna: Apache 2.4 (Require all denied) + fallback 2.2 (Deny
 * from all). Na 2.4 bez mod_access_compat samo "Deny from all" jest
 * ignorowane - katalog z zaszyfrowanymi danymi bylby web-czytalny.
 *
 * Wolane z api/create.php (sciezka zapisu) i cron/cleanup.php (codzienny
 * backup) - swiadomie NIE z view.php, zeby nie dokladac I/O sieciowego do
 * sciezki odczytu sekretu.
 */

const DIR_GUARD = "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Deny from all\n</IfModule>\n";

function ensure_dir_guard(string $dir): void {
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    $ht = $dir . '/.htaccess';
    // Pisz tylko gdy brak pliku albo stara skladnia - oszczedza I/O.
    $current = @file_get_contents($ht);
    if ($current === false || strpos($current, 'Require all denied') === false) {
        @file_put_contents($ht, DIR_GUARD);
    }
}

function harden_runtime_dirs(): void {
    ensure_dir_guard(DATA_DIR);
    ensure_dir_guard(TRASH_DIR);
    ensure_dir_guard(RATE_LIMIT_DIR);
}
