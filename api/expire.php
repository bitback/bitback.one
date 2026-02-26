<?php
/**
 * API: Natychmiastowe wygaszenie sekretów lub ubicie całego linka
 * POST JSON { "uuid": "...", "action": "expire" | "kill" }
 *
 * action=expire (domyślne): kasuje encrypted_secrets, tekst zostaje
 * action=kill: kasuje encrypted_secrets + encrypted_text, link martwy
 *
 * Nie wymaga klucza — każdy kto ma UUID może wygasić/ubić dane.
 * (To bezpieczne — wygaszenie ≠ odczyt, a UUID bez klucza i tak jest bezużyteczny)
 */

header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/../inc/config.php';

// tylko POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
if (!$input) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON']);
    exit;
}

$uuid = $input['uuid'] ?? '';
$action = $input['action'] ?? 'expire'; // expire | kill

// Walidacja UUID v4
if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $uuid)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid UUID']);
    exit;
}

if (!in_array($action, ['expire', 'kill'], true)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid action']);
    exit;
}

$file = DATA_DIR . '/' . $uuid . '.json';

if (!file_exists($file)) {
    http_response_code(404);
    echo json_encode(['error' => 'Not found']);
    exit;
}

$data = json_decode(file_get_contents($file), true);
if (!$data) {
    http_response_code(500);
    echo json_encode(['error' => 'Read error']);
    exit;
}

$manualDate = gmdate('Y-m-d\TH:i:s\Z');

// === KILL: usuń cały link ===
if ($action === 'kill') {
    // Już usunięty?
    if (isset($data['_killed_manually'])) {
        echo json_encode(['ok' => true, 'already_killed' => true]);
        exit;
    }

    $data['encrypted_secrets'] = null;
    $data['encrypted_text'] = null;
    // wyczyść też stare formaty
    if (isset($data['encrypted_payload'])) $data['encrypted_payload'] = null;
    if (isset($data['sections'])) $data['sections'] = null;

    $data['_secrets_expired_at'] = $data['_secrets_expired_at'] ?? time();
    $data['_killed_manually'] = $manualDate;

    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
    echo json_encode(['ok' => true, 'killed' => true]);
    exit;
}

// === EXPIRE: wygaś tylko sekrety ===

// Już wygaszone?
if ($data['encrypted_secrets'] === null) {
    echo json_encode(['ok' => true, 'already_expired' => true]);
    exit;
}

$data['encrypted_secrets'] = null;
$data['_secrets_expired_at'] = time();
$data['_expired_manually'] = $manualDate;

// Permanentne usunięcie od razu jeśli delete_after_days == 0
if (($data['delete_after_days'] ?? 30) == 0) {
    if (!is_dir(TRASH_DIR)) {
        mkdir(TRASH_DIR, 0755, true);
    }
    rename($file, TRASH_DIR . '/' . $uuid . '.json');
    echo json_encode(['ok' => true, 'deleted' => true]);
    exit;
}

file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);

echo json_encode(['ok' => true]);
