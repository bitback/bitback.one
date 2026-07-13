<?php
/**
 * Fixture endpoint TYLKO dla testow: zapisuje gotowy rekord do DATA_DIR z
 * podanych pol, omijajac antybota/ratelimit. Pozwala harnessowi utworzyc rekord
 * o dokladnie kontrolowanej tresci (bloby policzone w przegladarce) i zaladowac
 * go w drugim iframe przez /view.php?slug=uuid#hexKey.
 *
 * Bezpieczenstwo: aktywny WYLACZNIE gdy BB_TEST_DATA_DIR jest ustawione
 * (jak collect.php). W produkcji zwraca 404 - zero ryzyka zapisu obcego rekordu.
 */

$dir = getenv('BB_TEST_DATA_DIR');
if ($dir === false || $dir === '' || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(404);
    exit;
}
require_once __DIR__ . '/../inc/crypto.php'; // generate_uuid()

$in = json_decode(file_get_contents('php://input'), true);
if (!is_array($in)) { http_response_code(400); echo json_encode(['error' => 'bad']); exit; }

$uuid = generate_uuid();
$now = gmdate('Y-m-d\TH:i:s\Z');
$rec = [
    'id' => $uuid,
    'created' => $now,
    'expires_secrets' => $in['expires_secrets'] ?? gmdate('Y-m-d\TH:i:s\Z', time() + 30 * 86400),
    'delete_after_days' => (int)($in['delete_after_days'] ?? 30),
    'max_views' => (int)($in['max_views'] ?? 15),
    'current_views' => 0,
    'status' => 'active',
    'format' => (int)($in['format'] ?? 3),
    'kdf' => $in['kdf'] ?? null,
    'password_hash' => null,
    'password_verifier' => $in['password_verifier'] ?? null,
    'total_sections' => (int)($in['total_sections'] ?? 1),
    'view_log' => [],
    'encrypted_text' => $in['encrypted_text'] ?? null,
    'encrypted_secrets' => $in['encrypted_secrets'] ?? null,
];
if (!is_dir($dir)) { mkdir($dir, 0777, true); }
file_put_contents($dir . '/' . $uuid . '.json', json_encode($rec, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
header('Content-Type: application/json');
echo json_encode(['uuid' => $uuid]);
