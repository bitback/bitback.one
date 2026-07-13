<?php
/**
 * API: Tworzenie linka
 * POST JSON → zwraca URL (bez klucza — klucz dodaje przeglądarka)
 *
 * ZERO-TRUST: serwer NIGDY nie widzi plaintextu, klucza ani hasła.
 * Przeglądarka szyfruje dane (AES-256-GCM) i wysyła gotowe bloby (base64).
 * Hasło otwarcia nie opuszcza przeglądarki: przychodzi auth_tag (HKDF z klucza
 * PBKDF2), a zapisywany jest wyłącznie sha256(auth_tag) jako password_verifier.
 */

header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/../inc/config.php';
require_once __DIR__ . '/../inc/crypto.php';  // generate_uuid()
require_once __DIR__ . '/../inc/ratelimit.php';
require_once __DIR__ . '/../inc/antibot.php';
require_once __DIR__ . '/../inc/apiauth.php';
require_once __DIR__ . '/../inc/harden.php';

// Upewnij sie ze katalogi runtime maja aktualna blokade WWW (self-healing).
harden_runtime_dirs();

/**
 * Host do generowanych URL-i. HTTP_HOST jest kontrolowany przez klienta
 * (header injection / phishing) - przyjmujemy tylko poprawny hostname[:port],
 * inaczej fallback do SERVER_NAME. APP_HOST w config.php wymusza na sztywno.
 */
function safe_host(): string {
    if (defined('APP_HOST') && APP_HOST !== '') {
        return APP_HOST;
    }
    $host = $_SERVER['HTTP_HOST'] ?? '';
    if (preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:\d{1,5})?$/', $host)) {
        return $host;
    }
    return $_SERVER['SERVER_NAME'] ?? 'localhost';
}

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

// --- AUTORYZACJA: token API (integrator) vs przegladarka ---
$api = api_auth();
if ($api['present'] && $api['label'] === null) {
    // naglowek Bearer obecny, ale token niewazny - jawna odmowa (nie fallback do antybota)
    http_response_code(401);
    echo json_encode(['error' => 'invalid_token']);
    exit;
}

if ($api['present']) {
    // --- SCIEZKA API: token pomija honeypot + antybot, rate-bucket per token ---
    if (!check_token_rate_limit($api['id'])) {
        http_response_code(429);
        echo json_encode(['error' => 'ratelimit']);
        exit;
    }
} else {
    // --- SCIEZKA PRZEGLADARKI (bez zmian) ---
    // --- HONEYPOT ---
    if (!empty($input['website_url'])) {
        // cichy sukces dla bota
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        echo json_encode(['url' => $scheme . '://' . safe_host() . '/ok']);
        exit;
    }

    // --- MATH ANTYBOT (challenge podpisany HMAC przez serwer) ---
    if (!antibot_verify(
        $input['math_a'] ?? 0,
        $input['math_b'] ?? 0,
        $input['math_exp'] ?? 0,
        $input['math_token'] ?? '',
        $input['math_answer'] ?? null
    )) {
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
}

// --- WALIDACJA ZASZYFROWANYCH BLOBÓW ---
$encryptedText = $input['encrypted_text'] ?? null;
$encryptedSecrets = $input['encrypted_secrets'] ?? null;  // null = brak poufnych fragmentów

if (!$encryptedText || !is_string($encryptedText)) {
    http_response_code(400);
    echo json_encode(['error' => 'empty']);
    exit;
}

// Sprawdź czy to valid base64 o rozsądnej długości
if (base64_decode($encryptedText, true) === false || strlen($encryptedText) > 1048576) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_payload']);
    exit;
}

if ($encryptedSecrets !== null) {
    if (!is_string($encryptedSecrets) || base64_decode($encryptedSecrets, true) === false || strlen($encryptedSecrets) > 1048576) {
        http_response_code(400);
        echo json_encode(['error' => 'invalid_payload']);
        exit;
    }
}

// --- WALIDACJA USTAWIEŃ ---
$expireDays = max(1, min(3650, (int)($input['expire_days'] ?? DEFAULT_EXPIRE_DAYS)));
$maxViews = max(1, min(10000, (int)($input['max_views'] ?? DEFAULT_MAX_VIEWS)));
$deleteDays = max(0, min(3650, (int)($input['delete_after_days'] ?? DEFAULT_DELETE_DAYS)));

// --- TOTAL SECTIONS (do maskowników po wygaśnięciu) ---
$totalSections = max(1, min(1000, (int)($input['total_sections'] ?? 1)));

// --- HASLO v3: klient przysyla auth_tag (HKDF z master po PBKDF2), NIGDY plaintext ---
// Niepusty 'password' = stary/zly klient; odmowa zamiast cichego zapisu bez ochrony.
if (trim((string)($input['password'] ?? '')) !== '') {
    http_response_code(400);
    echo json_encode(['error' => 'plaintext_password']);
    exit;
}
$authTag = $input['auth_tag'] ?? null;
$passwordVerifier = null;
$kdf = null;
if ($authTag !== null && $authTag !== '') {
    if (!is_string($authTag) || !preg_match('/^[0-9a-f]{64}$/', $authTag)) {
        http_response_code(400);
        echo json_encode(['error' => 'invalid_auth_tag']);
        exit;
    }
    $iter = (int)(is_array($input['kdf'] ?? null) ? ($input['kdf']['iter'] ?? 0) : 0);
    $alg = is_array($input['kdf'] ?? null) ? ($input['kdf']['alg'] ?? '') : '';
    if ($alg !== 'PBKDF2-SHA256' || $iter < 100000 || $iter > 5000000) {
        http_response_code(400);
        echo json_encode(['error' => 'invalid_kdf']);
        exit;
    }
    $passwordVerifier = hash('sha256', $authTag);
    $kdf = ['alg' => 'PBKDF2-SHA256', 'iter' => $iter];
}

// --- GENEROWANIE UUID (klucz generuje przeglądarka, nie serwer!) ---
$uuid = generate_uuid();

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
    'format' => 3,
    'kdf' => $kdf,
    'password_hash' => null,
    'password_verifier' => $passwordVerifier,
    'total_sections' => $totalSections,
    'view_log' => [],
    'encrypted_text' => $encryptedText,
    'encrypted_secrets' => $encryptedSecrets,
];

if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
}

$file = DATA_DIR . '/' . $uuid . '.json';
file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);

// --- ZWROT URL (bez klucza! klucz dodaje przeglądarka jako #fragment) ---
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$url = $scheme . '://' . safe_host() . '/' . $uuid;

echo json_encode([
    'ok' => true,
    'url' => $url,
]);
