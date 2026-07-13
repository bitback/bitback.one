<?php
/**
 * Bootstrap TYLKO dla testow - ladowany przez auto_prepend_file (patrz run.ps1).
 *
 * Po co: repozytoryjne data/ jest read-only dla konta developerskiego i trzyma
 * realne rekordy. Testy, ktore tworza linki i sprawdzaja licznik wyswietlen,
 * musza pisac gdzie indziej. DATA_DIR siedzi w inc/config.php, ktorego NIE
 * wolno ruszac (jest sledzony przez git, a lokalnie trzyma sekret).
 *
 * Jak: config.php uzywa golego define(), a pierwszy define() wygrywa - ten plik
 * wykonuje sie przed nim, wiec ustawia storage na katalog tymczasowy. Kolejne
 * define() w config.php sa ignorowane.
 *
 * Gotcha: redefinicja stalej to E_WARNING (niewidoczny przy display_errors=0),
 * ale PHP 9 zamieni go na blad krytyczny. Gdy testy zaczna sypac fatalem na
 * "Constant DATA_DIR already defined" - config.php potrzebuje `defined() || define()`.
 *
 * Bez zmiennej BB_TEST_DATA_DIR plik nie robi nic (aplikacja dziala normalnie).
 */

$bbTestDir = getenv('BB_TEST_DATA_DIR');
if ($bbTestDir !== false && $bbTestDir !== '') {
    if (!is_dir($bbTestDir)) {
        mkdir($bbTestDir, 0777, true);
    }
    define('DATA_DIR', $bbTestDir);
    define('TRASH_DIR', $bbTestDir . '/_trash');
    define('RATE_LIMIT_DIR', $bbTestDir . '/_ratelimit');

    // Domyslnie rate-limit praktycznie wylaczony - progi produkcyjne ubilyby
    // testy tworzace kilkanascie linkow pod rzad. Test galezi 429 obniza prog,
    // zapisujac liczbe do pliku ponizej. Plik (nie zmienna srodowiskowa), bo
    // srodowisko procesu serwera jest zamrozone w momencie jego startu.
    $limitFile = $bbTestDir . '/_limits.json';
    $lim = is_file($limitFile) ? json_decode((string)file_get_contents($limitFile), true) : null;
    define('RATE_LIMIT_MAX', is_array($lim) && isset($lim['single']) ? (int)$lim['single'] : 100000);
    define('RATE_LIMIT_BATCH_MAX', is_array($lim) && isset($lim['batch']) ? (int)$lim['batch'] : 100000);
    define('API_RATE_MAX', is_array($lim) && isset($lim['api']) ? (int)$lim['api'] : 100000);
    // Duze okno: inaczej lokalny config (15 s) wygaszalby wpisy w trakcie suite
    // i test 429 bylby niedeterministyczny (raz liczy, raz nie).
    define('RATE_LIMIT_WINDOW', 86400);

    // Plik tokenow API w temp (aplikacja produkcyjna: inc/api-tokens.txt).
    define('API_TOKENS_FILE', $bbTestDir . '/api-tokens.txt');
}
