<?php
/**
 * API: Tworzenie paczki linkow (bulk / korespondencja seryjna)
 * POST JSON { records:[{encrypted_text, encrypted_secrets, total_sections}, ...],
 *             wspolne ustawienia, antybot } -> { ok:true, links:[{url}, ...] }
 *
 * ZERO-TRUST jak create.php: N niezaleznych par blobow, N kluczy w przegladarce.
 * Serwer NIGDY nie widzi plaintextu, kluczy ani hasla.
 *
 * Roznice vs create.php: two-pass walidacja WSZYSTKICH blobow przed zapisem
 * czegokolwiek, osobny rate-limit batchy, limit liczby rekordow i sumy rozmiaru.
 * Stale limitow maja fallbacki.
 *
 * Haslo paczki: kdf wspolny (top-level), ale auth_tag OSOBNY per rekord - kazdy
 * rekord ma wlasny hexKey, ktory jest saltem PBKDF2, wiec tagi sie roznia mimo
 * wspolnego hasla. Zapisywany jest sha256(auth_tag) tego rekordu.
 */

header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/../inc/config.php';
require_once __DIR__ . '/../inc/crypto.php';  // generate_uuid()
require_once __DIR__ . '/../inc/ratelimit.php';
require_once __DIR__ . '/../inc/antibot.php';
require_once __DIR__ . '/../inc/apiauth.php';
require_once __DIR__ . '/../inc/harden.php';

harden_runtime_dirs();

// Host do generowanych URL-i - kopia 1:1 z api/create.php (header injection guard).
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

$maxRecords = defined('BATCH_MAX_RECORDS') ? BATCH_MAX_RECORDS : 200;
$maxTotal   = defined('BATCH_MAX_TOTAL_BYTES') ? BATCH_MAX_TOTAL_BYTES : 8 * 1024 * 1024;

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

$records = $input['records'] ?? null;
$n = is_array($records) ? count($records) : 0;
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';

// --- AUTORYZACJA: token API (integrator) vs przegladarka ---
$api = api_auth();
if ($api['present'] && $api['label'] === null) {
    http_response_code(401);
    echo json_encode(['error' => 'invalid_token']);
    exit;
}

if (!$api['present']) {
    // --- SCIEZKA PRZEGLADARKI (bez zmian) ---
    // --- HONEYPOT ---
    // Cichy sukces: zwroc N falszywych linkow (nie jeden) - inaczej liczba linkow
    // zdradza botowi ze to endpoint bulk (fingerprinting).
    if (!empty($input['website_url'])) {
        $fake = [];
        for ($i = 0; $i < max(1, $n); $i++) {
            $fake[] = ['url' => $scheme . '://' . safe_host() . '/ok'];
        }
        echo json_encode(['ok' => true, 'links' => $fake]);
        exit;
    }

    // --- MATH ANTYBOT ---
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
}

// --- LICZBA REKORDOW (odrzuc PRZED rate-limitem) - wspolne dla obu sciezek ---
if ($n < 1 || $n > $maxRecords) {
    http_response_code(400);
    echo json_encode(['error' => 'batch_size']);
    exit;
}

// --- RATE LIMIT (osobny bucket batcha) ---
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
if ($api['present']) {
    if (!check_token_rate_limit($api['id'], 'batch')) {
        http_response_code(429);
        echo json_encode(['error' => 'ratelimit']);
        exit;
    }
} elseif (!check_batch_rate_limit($ip)) {
    http_response_code(429);
    echo json_encode(['error' => 'ratelimit']);
    exit;
}

// --- HASLO v3: wspolne kdf paczki + auth_tag per rekord (tagi zaleza od hexKey_i) ---
if (trim((string)($input['password'] ?? '')) !== '') {
    http_response_code(400);
    echo json_encode(['error' => 'plaintext_password']);
    exit;
}
$kdf = null;
if (isset($input['kdf'])) {
    $iter = (int)(is_array($input['kdf']) ? ($input['kdf']['iter'] ?? 0) : 0);
    $alg = is_array($input['kdf']) ? ($input['kdf']['alg'] ?? '') : '';
    if ($alg !== 'PBKDF2-SHA256' || $iter < 100000 || $iter > 5000000) {
        http_response_code(400);
        echo json_encode(['error' => 'invalid_kdf']);
        exit;
    }
    $kdf = ['alg' => 'PBKDF2-SHA256', 'iter' => $iter];
}

// --- TWO-PASS: waliduj WSZYSTKIE bloby PRZED zapisem czegokolwiek ---
$sum = 0;
foreach ($records as $r) {
    if (!is_array($r)) {
        http_response_code(400);
        echo json_encode(['error' => 'invalid_payload']);
        exit;
    }
    $et = $r['encrypted_text'] ?? null;
    $es = $r['encrypted_secrets'] ?? null;
    if (!$et || !is_string($et) || base64_decode($et, true) === false || strlen($et) > 1048576) {
        http_response_code(400);
        echo json_encode(['error' => 'invalid_payload']);
        exit;
    }
    $sum += strlen($et);
    if ($es !== null) {
        if (!is_string($es) || base64_decode($es, true) === false || strlen($es) > 1048576) {
            http_response_code(400);
            echo json_encode(['error' => 'invalid_payload']);
            exit;
        }
        $sum += strlen($es);
    }
    // auth_tag: wymagany dla kazdego rekordu paczki z haslem, zabroniony bez hasla
    $at = $r['auth_tag'] ?? null;
    if ($kdf !== null) {
        if (!is_string($at) || !preg_match('/^[0-9a-f]{64}$/', $at)) {
            http_response_code(400);
            echo json_encode(['error' => 'invalid_auth_tag']);
            exit;
        }
    } elseif ($at !== null) {
        http_response_code(400);
        echo json_encode(['error' => 'invalid_auth_tag']);
        exit;
    }
    if ($sum > $maxTotal) {
        http_response_code(413);
        echo json_encode(['error' => 'too_large']);
        exit;
    }
}

// --- WSPOLNE USTAWIENIA (jak create.php) ---
$expireDays = max(1, min(3650, (int)($input['expire_days'] ?? DEFAULT_EXPIRE_DAYS)));
$maxViews   = max(1, min(10000, (int)($input['max_views'] ?? DEFAULT_MAX_VIEWS)));
$deleteDays = max(0, min(3650, (int)($input['delete_after_days'] ?? DEFAULT_DELETE_DAYS)));

// --- ZAPIS N PLIKOW ---
if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
}
$now = gmdate('Y-m-d\TH:i:s\Z');
$expiresAt = gmdate('Y-m-d\TH:i:s\Z', time() + $expireDays * 86400);

$links = [];
foreach ($records as $r) {
    $uuid = generate_uuid();
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
        'password_verifier' => $kdf !== null ? hash('sha256', $r['auth_tag']) : null,
        'total_sections' => max(1, min(1000, (int)($r['total_sections'] ?? 1))),
        'view_log' => [],
        'encrypted_text' => $r['encrypted_text'],
        'encrypted_secrets' => $r['encrypted_secrets'] ?? null,
    ];
    file_put_contents(DATA_DIR . '/' . $uuid . '.json', json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
    $links[] = ['url' => $scheme . '://' . safe_host() . '/' . $uuid];
}

echo json_encode(['ok' => true, 'links' => $links]);
