<?php
/**
 * API: Tworzenie linka
 * POST JSON → zwraca URL
 */

header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/../inc/config.php';
require_once __DIR__ . '/../inc/crypto.php';
require_once __DIR__ . '/../inc/ratelimit.php';

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

// --- HONEYPOT ---
if (!empty($input['website_url'])) {
    // cichy sukces dla bota
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    echo json_encode(['url' => $scheme . '://' . $_SERVER['HTTP_HOST'] . '/ok']);
    exit;
}

// --- MATH ANTYBOT ---
$mathExpected = $input['math_expected'] ?? null;
$mathAnswer = $input['math_answer'] ?? null;
if ($mathExpected === null || $mathAnswer === null || (int)$mathAnswer !== (int)$mathExpected) {
    http_response_code(400);
    echo json_encode(['error' => 'math']);
    exit;
}

// --- RATE LIMIT ---
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
if (!check_rate_limit($ip)) {
    http_response_code(429);
    echo json_encode(['error' => 'ratelimit']);
    exit;
}

// --- WALIDACJA TREŚCI ---
$sections = $input['sections'] ?? [];
if (!is_array($sections) || count($sections) === 0) {
    http_response_code(400);
    echo json_encode(['error' => 'empty']);
    exit;
}

$hasContent = false;
foreach ($sections as $s) {
    if (!empty(trim($s['content'] ?? ''))) {
        $hasContent = true;
        break;
    }
}
if (!$hasContent) {
    http_response_code(400);
    echo json_encode(['error' => 'empty']);
    exit;
}

// --- WALIDACJA USTAWIEŃ ---
$expireDays = max(1, min(3650, (int)($input['expire_days'] ?? DEFAULT_EXPIRE_DAYS)));
$maxViews = max(1, min(10000, (int)($input['max_views'] ?? DEFAULT_MAX_VIEWS)));
$deleteDays = max(0, min(3650, (int)($input['delete_after_days'] ?? DEFAULT_DELETE_DAYS)));

// --- HASŁO (opcjonalne) ---
$password = trim($input['password'] ?? '');
$passwordHash = $password !== '' ? password_hash($password, PASSWORD_BCRYPT) : null;

// --- GENEROWANIE ---
$uuid = generate_uuid();
$key = generate_key();

// --- ROZDZIEL NA DWA BLOBY: tekst + sekrety ---
// Struktura: każda sekcja ma index (pozycja w oryginalnej kolejności)
// Blob "text" = sekcje jawne (type:text) z ich pozycjami
// Blob "secrets" = sekcje poufne (type:secret) z ich pozycjami
// Po wygaśnięciu serwer FIZYCZNIE kasuje blob secrets → nie do odzyskania

$textSections = [];
$secretSections = [];
$idx = 0;

foreach ($sections as $s) {
    $type = ($s['type'] ?? 'text') === 'secret' ? 'secret' : 'text';
    $entry = [
        'idx' => $idx,
        'content' => $s['content'] ?? '',
    ];
    if ($type === 'secret') {
        $secretSections[] = $entry;
    } else {
        $textSections[] = $entry;
    }
    $idx++;
}

// szyfruj oba bloby tym samym kluczem
$encryptedText = encrypt_payload($textSections, $key);
$encryptedSecrets = count($secretSections) > 0
    ? encrypt_payload($secretSections, $key)
    : null;

// --- ZAPIS ---
$now = gmdate('Y-m-d\TH:i:s\Z');
$expiresAt = gmdate('Y-m-d\TH:i:s\Z', time() + $expireDays * 86400);

$data = [
    'id' => $uuid,
    'created' => $now,
    'expires_secrets' => $expiresAt,
    'delete_after_days' => $deleteDays,
    'max_views' => $maxViews,
    'current_views' => 0,
    'status' => 'active',
    'password_hash' => $passwordHash,
    'view_log' => [],
    'encrypted_text' => $encryptedText,
    'encrypted_secrets' => $encryptedSecrets,
];

if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
}

$file = DATA_DIR . '/' . $uuid . '.json';
file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);

// --- ZWROT URL ---
// Klucz w #fragment — nigdy nie trafia do serwera (Apache loguje tylko /uuid)
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$url = $scheme . '://' . $_SERVER['HTTP_HOST'] . '/' . $uuid . '#' . $key;

echo json_encode([
    'ok' => true,
    'url' => $url,
]);
