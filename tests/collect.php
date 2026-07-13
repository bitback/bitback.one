<?php
/**
 * Kolektor wyniku browser-suite (tylko testy).
 *
 * Harness po zakonczeniu POST-uje tu swoj werdykt. Runner czeka na ten plik,
 * zamiast zgadywac, kiedy przegladarka skonczyla - suite liczy realne PBKDF2/AES,
 * wiec zaden staly limit czasu (ani --virtual-time-budget, ktory odmierza czas
 * WIRTUALNY) nie jest wiarygodnym sygnalem ukonczenia.
 *
 * Aktywny wylacznie gdy BB_TEST_DATA_DIR jest ustawione (patrz bootstrap.php).
 */

$dir = getenv('BB_TEST_DATA_DIR');
if ($dir === false || $dir === '' || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(404);
    exit;
}
if (!is_dir($dir)) {
    mkdir($dir, 0777, true);
}
file_put_contents($dir . '/_result.txt', file_get_contents('php://input'), LOCK_EX);
header('Content-Type: text/plain');
echo 'ok';
