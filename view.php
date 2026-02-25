<?php
/**
 * Odczyt linka: bitback.one/<uuid>#<key>
 * Zero-trust: klucz jest w #fragment (nigdy nie trafia do serwera)
 * Deszyfrowanie odbywa się w przeglądarce (Web Crypto API)
 *
 * Dwustopniowe wygasanie:
 *   1. Wygaśnięcie sekretów → serwer FIZYCZNIE kasuje encrypted_secrets z JSON
 *   2. Permanentne usunięcie → cały plik przeniesiony do trash
 */

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/i18n.php';

$lang = detect_lang();
$t = get_strings($lang);

// --- PARSUJ URL (tylko UUID, klucz jest w #fragment — nie trafia do serwera) ---
$slug = $_GET['slug'] ?? '';
$slug = trim($slug, '/');

if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i', $slug)) {
    show_not_found($t);
    exit;
}

$uuid = $slug;

// --- WCZYTAJ PLIK ---
$file = DATA_DIR . '/' . $uuid . '.json';
if (!file_exists($file)) {
    show_not_found($t);
    exit;
}

$data = json_decode(file_get_contents($file), true);
if (!$data) {
    show_not_found($t);
    exit;
}

// --- HASŁO (jeśli ustawione) ---
if (!empty($data['password_hash'])) {
    $submittedPassword = $_POST['password'] ?? null;
    if ($submittedPassword === null) {
        show_password_form($t, $slug);
        exit;
    }
    if (!password_verify($submittedPassword, $data['password_hash'])) {
        show_password_form($t, $slug, true);
        exit;
    }
}

// --- SPRAWDŹ STATUS ---
$now = time();
$secretsExpired = (strtotime($data['expires_secrets']) <= $now) || ($data['current_views'] >= $data['max_views']);

// permanentne usunięcie (delete_after_days == 0 → od razu)
if ($secretsExpired && $data['delete_after_days'] == 0) {
    move_to_trash($file, $uuid);
    show_expired($t);
    exit;
}

if ($secretsExpired && $data['delete_after_days'] > 0) {
    if (isset($data['_secrets_expired_at'])) {
        $deleteAt = $data['_secrets_expired_at'] + ($data['delete_after_days'] * 86400);
    } else {
        $data['_secrets_expired_at'] = $now;
    }

    if ($now >= ($deleteAt ?? $now + ($data['delete_after_days'] * 86400))) {
        move_to_trash($file, $uuid);
        show_expired($t);
        exit;
    }
}

// --- FIZYCZNE KASOWANIE SEKRETÓW (lazy — przy pierwszym odczycie po wygaśnięciu) ---
$needSave = false;

if ($secretsExpired && isset($data['encrypted_secrets'])) {
    // NIEODWRACALNE: usuwamy blob sekretów z pliku
    $data['encrypted_secrets'] = null;
    if (!isset($data['_secrets_expired_at'])) {
        $data['_secrets_expired_at'] = $now;
    }
    $needSave = true;
}

// --- LOGUJ WYŚWIETLENIE (tylko aktywne sekrety) ---
// Zachowaj sekrety dla ostatniego wyświetlenia (zanim zostaną skasowane z pliku)
$lastViewSecrets = $data['encrypted_secrets'] ?? null;

if (!$secretsExpired) {
    $data['current_views']++;
    $data['view_log'][] = [
        'time' => gmdate('Y-m-d\TH:i:s\Z'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
    ];

    if ($data['current_views'] >= $data['max_views']) {
        // To jest ostatnie dozwolone wyświetlenie — user jeszcze widzi dane,
        // ale w pliku kasujemy sekrety (następne odwiedziny = wygaszone)
        $data['_secrets_expired_at'] = $now;
        $data['encrypted_secrets'] = null;
        // $secretsExpired pozostaje false — ten widok jeszcze pokazuje dane
    }

    $needSave = true;
}

if ($needSave) {
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
}

// --- BACKWARD COMPAT: stary format (encrypted_payload lub sections) ---
if (isset($data['encrypted_payload'])) {
    // stary format v2: jeden blob → nie obsługuje dwustopniowego wygasania
    show_view_encrypted_v2($t, $data, $data['encrypted_payload'], $secretsExpired);
    exit;
}
if (isset($data['sections'])) {
    show_view_legacy($t, $data, $data['sections'], $secretsExpired);
    exit;
}

// --- NOWY FORMAT: dwa bloby ---
$encText = $data['encrypted_text'] ?? null;
// Użyj zachowanych sekretów ($lastViewSecrets) — ostatnie wyświetlenie je jeszcze pokazuje
$encSecrets = $lastViewSecrets;

if ($encText === null) {
    show_expired($t);
    exit;
}

show_view_encrypted($t, $data, $encText, $encSecrets, $secretsExpired);

// ============================================================
// FUNKCJE
// ============================================================

function linkify_html(string $escapedHtml): string {
    return preg_replace(
        '#(https?://[^\s<>\'"&]+(?:&amp;[^\s<>\'"&]+)*)#',
        '<a href="$1" target="_blank" rel="noopener" style="color:#6a9fd4;">$1</a>',
        $escapedHtml
    );
}

function move_to_trash(string $file, string $uuid): void {
    if (!is_dir(TRASH_DIR)) {
        mkdir(TRASH_DIR, 0755, true);
    }
    rename($file, TRASH_DIR . '/' . $uuid . '.json');
}

function show_password_form(array $t, string $slug, bool $wrongPassword = false): void {
    ?><!DOCTYPE html>
<html lang="<?= detect_lang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($t['title']) ?></title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a; color: #e0e0e0;
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
        }
        .box { text-align: center; padding: 2rem; width: 100%; max-width: 380px; }
        h1 { font-size: 1.4rem; font-weight: 300; color: #fff; margin-bottom: 0.3rem; }
        .sub { color: #555; font-size: 0.78rem; margin-bottom: 1.5rem; }
        .pwd-input {
            width: 100%; padding: 0.6rem 0.8rem;
            background: #111; border: 1px solid #252525; border-radius: 6px;
            color: #fff; font-size: 0.9rem; outline: none; text-align: center;
            font-family: monospace;
        }
        .pwd-input:focus { border-color: #444; }
        .pwd-btn {
            width: 100%; padding: 0.6rem; margin-top: 0.7rem;
            border-radius: 6px; border: none;
            background: #3a7bd5; color: #fff; font-size: 0.85rem;
            cursor: pointer; transition: background 0.15s;
        }
        .pwd-btn:hover { background: #4a8be5; }
        .error { color: #d44; font-size: 0.75rem; margin-top: 0.5rem; }
        .logo { color: #333; font-size: 0.75rem; margin-top: 2rem; letter-spacing: 0.1em; }
    </style>
</head>
<body>
    <div class="box">
        <h1><a href="/" style="color:inherit;text-decoration:none;"><?= htmlspecialchars($t['title']) ?></a></h1>
        <div class="sub"><?= htmlspecialchars($t['password_required'] ?? 'This link is password protected') ?></div>
        <form method="POST" action="/<?= htmlspecialchars($slug) ?>" id="pwdForm">
            <input type="password" name="password" class="pwd-input" placeholder="<?= htmlspecialchars($t['password_placeholder'] ?? 'Enter password') ?>" autofocus required>
            <button type="submit" class="pwd-btn"><?= htmlspecialchars($t['password_submit'] ?? 'Open') ?></button>
            <?php if ($wrongPassword): ?>
            <div class="error"><?= htmlspecialchars($t['password_wrong'] ?? 'Wrong password') ?></div>
            <?php endif; ?>
        </form>
        <div class="logo"><a href="/" style="color:inherit;text-decoration:none;"><?= htmlspecialchars($t['title']) ?></a></div>
        <div style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:#0a0a0a;border-top:1px solid #1a1a1a;padding:0.5rem 1rem;text-align:center;font-size:0.75rem;color:#555;white-space:nowrap;">
            <a href="https://bitback.pl" target="_blank" rel="noopener" style="color:#6a9fd4;text-decoration:none;"><strong>bitback.pl</strong></a>
            <span style="color:#2a2a2a;margin:0 0.5rem;">|</span>Kod źródłowy na <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener" style="color:#6a9fd4;text-decoration:none;">GitHub</a>
        </div>
    </div>
    <script>
    document.getElementById('pwdForm').addEventListener('submit', function() {
        this.action = '/' + <?= json_encode($slug) ?> + window.location.hash;
    });
    </script>
</body>
</html><?php
    exit;
}

function show_not_found(array $t): void {
    http_response_code(404);
    ?><!DOCTYPE html>
<html lang="<?= detect_lang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 — <?= htmlspecialchars($t['title']) ?></title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a; color: #e0e0e0;
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
            padding-bottom: 2.5rem;
        }
        .box { text-align: center; padding: 2rem; max-width: 500px; }
        .ghost {
            font-size: 4rem;
            margin-bottom: 1rem;
            animation: float 3s ease-in-out infinite;
        }
        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-12px); }
        }
        .code {
            font-size: 3.5rem;
            font-weight: 200;
            color: #222;
            letter-spacing: 0.15em;
            margin-bottom: 0.5rem;
        }
        h1 { font-size: 1.2rem; font-weight: 400; color: #888; margin-bottom: 0.8rem; }
        .sub { color: #444; font-size: 0.82rem; line-height: 1.6; margin-bottom: 0.5rem; }
        .hint { color: #333; font-size: 0.72rem; margin-top: 1rem; }
        .hint code { color: #f0c060; background: #1a1a0a; padding: 0.1em 0.3em; border-radius: 3px; }
        .home-link {
            display: inline-block; margin-top: 1.5rem;
            padding: 0.5rem 1.2rem; border-radius: 6px;
            border: 1px solid #1e1e1e; background: #111;
            color: #6a9fd4; text-decoration: none; font-size: 0.8rem;
            transition: background 0.15s;
        }
        .home-link:hover { background: #161616; }
    </style>
</head>
<body>
    <div class="box">
        <div class="ghost">👻</div>
        <div class="code">404</div>
        <h1><?= htmlspecialchars($t['not_found_title']) ?></h1>
        <div class="sub"><?= htmlspecialchars($t['not_found_sub']) ?></div>
        <div class="hint"><?= htmlspecialchars($t['not_found_hint']) ?> <code>#</code></div>
        <a href="/" class="home-link"><?= htmlspecialchars($t['title']) ?> →</a>
        <div style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:#0a0a0a;border-top:1px solid #1a1a1a;padding:0.5rem 1rem;text-align:center;font-size:0.75rem;color:#555;white-space:nowrap;">
            <a href="https://bitback.pl" target="_blank" rel="noopener" style="color:#6a9fd4;text-decoration:none;"><strong>bitback.pl</strong></a>
            <span style="color:#2a2a2a;margin:0 0.5rem;">|</span>Kod źródłowy na <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener" style="color:#6a9fd4;text-decoration:none;">GitHub</a>
        </div>
    </div>
</body>
</html><?php
    exit;
}

function show_expired(array $t): void {
    http_response_code(410);
    ?><!DOCTYPE html>
<html lang="<?= detect_lang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($t['link_expired']) ?> — <?= htmlspecialchars($t['title']) ?></title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a; color: #e0e0e0;
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
        }
        .box { text-align: center; padding: 2rem; }
        h1 { font-size: 1.4rem; font-weight: 300; color: #fff; margin-bottom: 0.5rem; }
        p { color: #555; font-size: 0.85rem; }
        .logo { color: #333; font-size: 0.75rem; margin-top: 2rem; letter-spacing: 0.1em; }
    </style>
</head>
<body>
    <div class="box">
        <h1><?= htmlspecialchars($t['link_expired']) ?></h1>
        <p><?= htmlspecialchars($t['link_expired_info']) ?></p>
        <div class="logo"><a href="/" style="color:inherit;text-decoration:none;"><?= htmlspecialchars($t['title']) ?></a></div>
        <div style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:#0a0a0a;border-top:1px solid #1a1a1a;padding:0.5rem 1rem;text-align:center;font-size:0.75rem;color:#555;white-space:nowrap;">
            <a href="https://bitback.pl" target="_blank" rel="noopener" style="color:#6a9fd4;text-decoration:none;"><strong>bitback.pl</strong></a>
            <span style="color:#2a2a2a;margin:0 0.5rem;">|</span>Kod źródłowy na <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener" style="color:#6a9fd4;text-decoration:none;">GitHub</a>
        </div>
    </div>
</body>
</html><?php
    exit;
}

// === CSS wspólne dla widoku ===
function view_css(): string {
    return '
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0a0a0a; color: #e0e0e0; min-height: 100vh; padding-bottom: 2.5rem; }
        .header { text-align: center; padding: 2rem 1rem 1.5rem; }
        .header h1 { font-size: 1.4rem; font-weight: 300; letter-spacing: 0.08em; color: #fff; }
        .container { max-width: 700px; margin: 0 auto; padding: 0 1rem 3rem; }
        .expired-banner { background: #1a1410; border: 1px solid #3a2a10; border-radius: 8px; padding: 0.7rem 1rem; margin-bottom: 1rem; font-size: 0.8rem; color: #d4922a; }
        .error-banner { background: #1a1010; border: 1px solid #3a1010; border-radius: 8px; padding: 0.7rem 1rem; margin-bottom: 1rem; font-size: 0.8rem; color: #d44; }
        .content-box { background: #111; border: 1px solid #1e1e1e; border-radius: 8px; padding: 1rem; font-family: "Consolas", "Monaco", "Courier New", monospace; font-size: 0.85rem; line-height: 1.7; white-space: pre-wrap; word-break: break-word; }
        .s-text { color: #ddd; }
        .s-text a { color: #6a9fd4; }
        .s-secret { background: rgba(212, 146, 42, 0.15); color: #f0c060; border-radius: 3px; padding: 0.05em 0.2em; border-bottom: 2px solid rgba(212, 146, 42, 0.4); }
        .s-secret a { color: inherit; }
        .s-masked { background: rgba(100, 100, 100, 0.2); color: #555; border-radius: 3px; padding: 0.05em 0.2em; letter-spacing: 0.1em; }
        .loading { text-align: center; padding: 2rem; color: #555; font-size: 0.85rem; }
        .loading .spinner { display: inline-block; width: 18px; height: 18px; border: 2px solid #333; border-top-color: #888; border-radius: 50%; animation: spin 0.6s linear infinite; margin-right: 0.5rem; vertical-align: middle; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .meta { margin-top: 1.2rem; display: flex; justify-content: space-between; align-items: flex-end; gap: 1rem; font-size: 0.72rem; color: #444; }
        .meta-big { font-size: 1.6rem; font-weight: 200; color: #555; line-height: 1; }
        .meta-big.warn { color: #d4922a; }
        .meta-sub { font-size: 0.65rem; color: #333; margin-top: 0.15rem; }
        .expire-info { background: #111; border: 1px solid #1e1e1e; border-radius: 8px; padding: 0.7rem 1rem; margin-top: 1rem; font-size: 0.75rem; color: #555; display: flex; justify-content: space-between; align-items: center; }
        .expire-info .date { color: #888; }
        .zt-badge { margin-top: 1.5rem; text-align: center; font-size: 0.65rem; color: #2a2a2a; }
        .zt-badge span { color: #333; }
        .expire-now-wrap { margin-top: 1rem; display: flex; flex-direction: column; align-items: center; gap: 0.6rem; }
        .expire-now-confirm { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.65rem 1.5rem; border: 1.5px solid transparent; border-radius: 8px; transition: border-color 0.2s; cursor: pointer; font-size: 0.85rem; line-height: 1.2; box-sizing: border-box; }
        .expire-now-confirm input[type="checkbox"] { accent-color: #d4922a; width: 16px; height: 16px; cursor: pointer; flex-shrink: 0; }
        .expire-now-confirm label { color: #888; font-size: 0.85rem; cursor: pointer; user-select: none; line-height: 1.2; }
        .expire-now-confirm.shake { border-color: #c0392b; animation: shakeBox 0.4s ease; }
        @keyframes shakeBox { 0%,100% { transform: translateX(0); } 20%,60% { transform: translateX(-4px); } 40%,80% { transform: translateX(4px); } }
        .expire-now-btn { background: rgba(212, 146, 42, 0.12); border: 1.5px solid #d4922a; color: #f0c060; font-size: 0.85rem; line-height: 1.2; padding: 0.65rem 1.5rem; border-radius: 8px; cursor: pointer; transition: all 0.15s; font-weight: 500; letter-spacing: 0.01em; box-sizing: border-box; }
        .expire-now-btn:hover { background: rgba(212, 146, 42, 0.22); border-color: #f0c060; color: #ffe0a0; }
        .expire-now-btn:disabled { opacity: 0.4; cursor: default; }
        .expire-now-btn.done { background: rgba(74, 138, 74, 0.12); border-color: #4a8a4a; color: #6aba6a; }
        .site-footer { position: fixed; bottom: 0; left: 0; right: 0; z-index: 100; background: #0a0a0a; border-top: 1px solid #1a1a1a; padding: 0.5rem 1rem; text-align: center; font-size: 0.75rem; color: #555; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .site-footer a { color: #6a9fd4; text-decoration: none; }
        .site-footer a:hover { color: #8abcf0; text-decoration: underline; }
        .site-footer .sep { color: #2a2a2a; margin: 0 0.5rem; }
    ';
}

function view_meta_html(array $t, array $data, bool $expired): string {
    $viewCount = $data['current_views'];
    $maxViews = $data['max_views'];
    $expiresTs = strtotime($data['expires_secrets']);
    $expiresDate = date('Y-m-d', $expiresTs);
    $daysLeft = max(0, (int)ceil(($expiresTs - time()) / 86400));
    $viewsLeft = max(0, $maxViews - $viewCount);
    $lang = detect_lang();

    $html = '';
    if (!$expired) {
        $html .= '<div class="expire-info">';
        $html .= '<span>' . htmlspecialchars($t['expires_on']) . ' <span class="date">' . $expiresDate . '</span></span>';
        $html .= '<span>' . $viewCount . '/' . $maxViews . ' ' . htmlspecialchars($t['views_count']) . '</span>';
        $html .= '</div>';
        $html .= '<div class="meta">';
        $html .= '<div class="meta-left"><div class="meta-big' . ($daysLeft <= 3 ? ' warn' : '') . '">' . $daysLeft . '</div>';
        $html .= '<div class="meta-sub">' . htmlspecialchars($t['days_left']) . '</div></div>';
        $html .= '<div class="meta-right"><div class="meta-big' . ($viewsLeft <= 3 ? ' warn' : '') . '">' . $viewsLeft . '</div>';
        $html .= '<div class="meta-sub">' . htmlspecialchars($t['views_left']) . '</div></div>';
        $html .= '</div>';
    } else {
        // --- Licznik permanentnego usunięcia ---
        $deleteDays = $data['delete_after_days'] ?? 30;
        $expiredAt = $data['_secrets_expired_at'] ?? null;

        $html .= '<div class="meta">';
        $html .= '<div class="meta-left">';
        $html .= '<div class="meta-sub">' . $viewCount . '/' . $maxViews . ' ' . htmlspecialchars($t['views_count']) . '</div>';
        $html .= '</div>';

        if ($expiredAt !== null && $deleteDays > 0) {
            $deleteAt = $expiredAt + ($deleteDays * 86400);
            $daysToDelete = max(0, (int)ceil(($deleteAt - time()) / 86400));
            $deleteDate = date('Y-m-d', $deleteAt);

            $html .= '<div class="meta-right">';
            if ($daysToDelete > 0) {
                $html .= '<div class="meta-big warn">' . $daysToDelete . '</div>';
                $html .= '<div class="meta-sub">' . htmlspecialchars($t['delete_permanent_in']) . '</div>';
            } else {
                $html .= '<div class="meta-big warn">&lt;1</div>';
                $html .= '<div class="meta-sub">' . htmlspecialchars($t['delete_permanent_today']) . '</div>';
            }
            $html .= '</div>';
        }

        $html .= '</div>';

        if ($expiredAt !== null && $deleteDays > 0) {
            $html .= '<div class="expire-info">';
            $html .= '<span>' . htmlspecialchars($t['delete_permanent_label']) . ' <span class="date">' . $deleteDate . '</span></span>';
            $html .= '</div>';
        }
    }

    $ztText = $lang === 'pl'
        ? 'Zero-trust: deszyfrowanie odbyło się w Twojej przeglądarce. Serwer nie miał dostępu do klucza.'
        : 'Zero-trust: decryption happened in your browser. The server never had access to the key.';
    $html .= '<div class="zt-badge"><span>&#128274;</span> ' . $ztText . '</div>';

    // Przycisk natychmiastowego wygaszenia — tylko gdy sekrety jeszcze aktywne
    if (!$expired) {
        $uuid = $data['id'] ?? '';
        $checkLabel = $lang === 'pl'
            ? 'Otrzymałem dane. Potwierdź'
            : 'I received the data. Confirm';
        $btnLabel = $lang === 'pl'
            ? 'wygaś poufne dane teraz'
            : 'expire secret data now';
        $successMsg = $lang === 'pl'
            ? 'Dane poufne zostały wygaszone.'
            : 'Secret data has been expired.';
        $errorMsg = $lang === 'pl'
            ? 'Nie udało się wygasić danych. Spróbuj ponownie.'
            : 'Failed to expire data. Please try again.';

        $html .= '<div class="expire-now-wrap">';
        $html .= '<div class="expire-now-confirm" id="expireConfirmWrap">';
        $html .= '<input type="checkbox" id="expireConfirmCb">';
        $html .= '<label for="expireConfirmCb">' . htmlspecialchars($checkLabel) . '</label>';
        $html .= '</div>';
        $html .= '<button type="button" class="expire-now-btn" onclick="expireNow(this)"';
        $html .= ' data-uuid="' . htmlspecialchars($uuid) . '"';
        $html .= ' data-success="' . htmlspecialchars($successMsg) . '"';
        $html .= ' data-error="' . htmlspecialchars($errorMsg) . '"';
        $html .= '>' . htmlspecialchars($btnLabel) . '</button>';
        $html .= '</div>';
    }

    return $html;
}

function view_footer_html(): string {
    $lang = detect_lang();
    $s = '<span class="sep">|</span>';
    if ($lang === 'pl') {
        return '<div class="site-footer">'
            . '<a href="https://bitback.pl" target="_blank" rel="noopener"><strong>bitback.pl</strong></a>'
            . $s . 'Zabezpieczamy pocztę, serwery i komputery'
            . $s . 'Zbigniew Gralewski'
            . $s . '<a href="mailto:zbigniew.gralewski@bitback.pl">zbigniew.gralewski@bitback.pl</a>'
            . $s . '609 505 065'
            . $s . 'Kod źródłowy na <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener">GitHub</a>'
            . '</div>';
    }
    return '<div class="site-footer">'
        . '<a href="https://bitback.pl" target="_blank" rel="noopener"><strong>bitback.pl</strong></a>'
        . $s . 'We secure email, servers and computers'
        . $s . 'Zbigniew Gralewski'
        . $s . '<a href="mailto:zbigniew.gralewski@bitback.pl">zbigniew.gralewski@bitback.pl</a>'
        . $s . '609 505 065'
        . $s . 'Source code on <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener">GitHub</a>'
        . '</div>';
}

/**
 * NOWY FORMAT: dwa osobne bloby (encrypted_text + encrypted_secrets)
 * Po wygaśnięciu encrypted_secrets jest null (fizycznie usunięty z JSON)
 */
function show_view_encrypted(array $t, array $data, string $encText, ?string $encSecrets, bool $expired): void {
    $lang = detect_lang();
    $loadingText = $lang === 'pl' ? 'Deszyfrowanie w przeglądarce...' : 'Decrypting in browser...';
    $noKeyError = $lang === 'pl'
        ? 'Brak klucza deszyfrującego w linku. Upewnij się, że skopiowano pełny URL.'
        : 'Missing decryption key in URL. Make sure you copied the full link.';
    ?><!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($t['title']) ?></title>
    <style><?= view_css() ?></style>
</head>
<body>
    <div class="header"><h1><a href="/" style="color:inherit;text-decoration:none;"><?= htmlspecialchars($t['title']) ?></a></h1></div>
    <div class="container">
        <?php if ($expired): ?>
        <div class="expired-banner">
            <?= htmlspecialchars($t['secrets_expired']) ?> — <?= htmlspecialchars($t['secrets_expired_info']) ?>
        </div>
        <?php endif; ?>

        <div id="errorBox" class="error-banner" style="display:none;"></div>

        <div id="loadingBox" class="loading">
            <span class="spinner"></span> <?= $loadingText ?>
        </div>

        <div class="content-box" id="contentBox" style="display:none;"></div>

        <?= view_meta_html($t, $data, $expired) ?>
    </div>
    <?= view_footer_html() ?>

    <script>
    // === ZERO-TRUST CLIENT-SIDE DECRYPTION ===
    // Dwa osobne bloby: tekst (zawsze) + sekrety (null jeśli wygasłe — fizycznie usunięte z serwera)

    const ENC_TEXT = <?= json_encode($encText) ?>;
    const ENC_SECRETS = <?= json_encode($encSecrets) ?>;  // null = sekrety fizycznie usunięte
    const TOTAL_SECTIONS = <?= (int)($data['total_sections'] ?? 0) ?>;
    const HAD_SECRETS = <?= ($expired && $encSecrets === null) ? 'true' : ($encSecrets !== null ? 'true' : 'false') ?>;

    (async function() {
        const loadingBox = document.getElementById('loadingBox');
        const contentBox = document.getElementById('contentBox');
        const errorBox = document.getElementById('errorBox');

        try {
            const hexKey = window.location.hash.substring(1);
            if (!hexKey || !/^[0-9a-f]{32}$/i.test(hexKey)) {
                throw new Error(<?= json_encode($noKeyError) ?>);
            }

            // Deszyfruj blob tekstu (zawsze dostępny)
            const textItems = await decryptBlob(ENC_TEXT, hexKey);

            // Deszyfruj blob sekretów (tylko jeśli nie wygasły)
            let secretItems = [];
            if (ENC_SECRETS) {
                secretItems = await decryptBlob(ENC_SECRETS, hexKey);
            }

            // Scal oba bloby wg idx (oryginalna kolejność)
            const all = [];
            for (const item of textItems) {
                all.push({ idx: item.idx, type: 'text', content: item.content });
            }
            for (const item of secretItems) {
                all.push({ idx: item.idx, type: 'secret', content: item.content });
            }
            all.sort((a, b) => a.idx - b.idx);

            // Jeśli sekrety wygasły, wstaw maskowniki w miejsce brakujących idx
            if (!ENC_SECRETS) {
                const filled = fillMasked(all);
                renderSections(filled, true);
            } else {
                renderSections(all, false);
            }

            loadingBox.style.display = 'none';
            contentBox.style.display = 'block';

        } catch (err) {
            loadingBox.style.display = 'none';
            errorBox.textContent = err.message;
            errorBox.style.display = 'block';
        }
    })();

    function fillMasked(textItems) {
        // Wstaw maskowniki w miejsca brakujących idx (fizycznie usunięte sekrety)
        // TOTAL_SECTIONS = łączna liczba sekcji (text + secret) z momentu tworzenia
        let total = TOTAL_SECTIONS;

        if (!total) {
            // Fallback dla starych linków (bez total_sections w JSON)
            if (textItems.length > 0) {
                const maxIdx = Math.max(...textItems.map(i => i.idx));
                const hasGaps = textItems.length < (maxIdx + 1);
                // Jeśli wiemy że były sekrety, a max idx nie pokrywa wszystkiego — dodaj ekstra
                total = hasGaps ? maxIdx + 2 : maxIdx + 1;
                // Jeśli były sekrety ale nie ma dziur, to sekrety były na końcu
                if (!hasGaps && HAD_SECRETS) total = maxIdx + 2;
            } else if (HAD_SECRETS) {
                // Cała treść to sekrety (brak tekstu)
                total = 1;
            }
        }

        if (!total) return textItems;

        const byIdx = {};
        for (const item of textItems) byIdx[item.idx] = item;

        const result = [];
        for (let i = 0; i < total; i++) {
            if (byIdx[i]) {
                result.push(byIdx[i]);
            } else {
                result.push({ idx: i, type: 'masked', content: '\u25CF\u25CF\u25CF\u25CF\u25CF\u25CF' });
            }
        }
        return result;
    }

    function renderSections(sections, expired) {
        const contentBox = document.getElementById('contentBox');
        let html = '';
        for (const s of sections) {
            const escaped = escapeHtml(s.content);
            if (s.type === 'masked') {
                html += '<span class="s-masked">' + escaped + '</span>';
            } else if (s.type === 'secret') {
                html += '<span class="s-secret">' + linkify(escaped) + '</span>';
            } else {
                html += '<span class="s-text">' + linkify(escaped) + '</span>';
            }
        }
        contentBox.innerHTML = html;
    }

    function linkify(escapedHtml) {
        // Regex na escaped HTML — URL może zawierać &amp; (escaped &)
        return escapedHtml.replace(
            /https?:\/\/[^\s<>'"]+/g,
            function(match) {
                return '<a href="' + match + '" target="_blank" rel="noopener" style="color:#6a9fd4;">' + match + '</a>';
            }
        );
    }

    // === AES-256-CBC DECRYPTION (Web Crypto API) ===

    async function decryptBlob(base64Blob, hexKey) {
        const keyBytes = await sha256(new TextEncoder().encode(hexKey));
        const raw = Uint8Array.from(atob(base64Blob), c => c.charCodeAt(0));
        if (raw.length < 17) throw new Error('Invalid payload');

        const iv = raw.slice(0, 16);
        const ciphertext = raw.slice(16);

        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: iv }, cryptoKey, ciphertext
        );

        const json = new TextDecoder().decode(decrypted);
        const items = JSON.parse(json);
        if (!Array.isArray(items)) throw new Error('Invalid data');
        return items;
    }

    async function sha256(data) {
        return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
    }

    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    async function expireNow(btn) {
        var wrap = document.getElementById('expireConfirmWrap');
        var cb = document.getElementById('expireConfirmCb');
        if (!cb.checked) {
            wrap.classList.remove('shake');
            void wrap.offsetWidth;
            wrap.classList.add('shake');
            return;
        }
        btn.disabled = true;
        cb.disabled = true;
        btn.textContent = '...';
        try {
            const resp = await fetch('/api/expire.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ uuid: btn.dataset.uuid }),
            });
            const result = await resp.json();
            if (result.ok) {
                btn.textContent = '\u2713 ' + btn.dataset.success;
                btn.classList.add('done');
                setTimeout(function() { location.reload(); }, 1500);
            } else {
                btn.textContent = btn.dataset.error;
                btn.disabled = false;
                cb.disabled = false;
            }
        } catch (e) {
            btn.textContent = btn.dataset.error;
            btn.disabled = false;
            cb.disabled = false;
        }
    }
    </script>
</body>
</html><?php
}

/**
 * Backward compat v2: stary format z jednym encrypted_payload
 */
function show_view_encrypted_v2(array $t, array $data, string $encryptedPayload, bool $expired): void {
    $lang = detect_lang();
    $loadingText = $lang === 'pl' ? 'Deszyfrowanie w przeglądarce...' : 'Decrypting in browser...';
    $noKeyError = $lang === 'pl'
        ? 'Brak klucza deszyfrującego w linku. Upewnij się, że skopiowano pełny URL.'
        : 'Missing decryption key in URL. Make sure you copied the full link.';
    ?><!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($t['title']) ?></title>
    <style><?= view_css() ?></style>
</head>
<body>
    <div class="header"><h1><a href="/" style="color:inherit;text-decoration:none;"><?= htmlspecialchars($t['title']) ?></a></h1></div>
    <div class="container">
        <?php if ($expired): ?>
        <div class="expired-banner">
            <?= htmlspecialchars($t['secrets_expired']) ?> — <?= htmlspecialchars($t['secrets_expired_info']) ?>
        </div>
        <?php endif; ?>
        <div id="errorBox" class="error-banner" style="display:none;"></div>
        <div id="loadingBox" class="loading"><span class="spinner"></span> <?= $loadingText ?></div>
        <div class="content-box" id="contentBox" style="display:none;"></div>
        <?= view_meta_html($t, $data, $expired) ?>
    </div>
    <?= view_footer_html() ?>
    <script>
    const ENCRYPTED_PAYLOAD = <?= json_encode($encryptedPayload) ?>;
    const SECRETS_EXPIRED = <?= $expired ? 'true' : 'false' ?>;

    (async function() {
        const loadingBox = document.getElementById('loadingBox');
        const contentBox = document.getElementById('contentBox');
        const errorBox = document.getElementById('errorBox');
        try {
            const hexKey = window.location.hash.substring(1);
            if (!hexKey || !/^[0-9a-f]{32}$/i.test(hexKey)) {
                throw new Error(<?= json_encode($noKeyError) ?>);
            }
            const keyBytes = await sha256(new TextEncoder().encode(hexKey));
            const raw = Uint8Array.from(atob(ENCRYPTED_PAYLOAD), c => c.charCodeAt(0));
            const iv = raw.slice(0, 16);
            const ciphertext = raw.slice(16);
            const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
            const decrypted = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, cryptoKey, ciphertext);
            const sections = JSON.parse(new TextDecoder().decode(decrypted));
            let html = '';
            for (const s of sections) {
                const escaped = escapeHtml(s.content);
                if (s.type === 'secret') {
                    html += SECRETS_EXPIRED ? '<span class="s-masked">●●●●●●</span>' : '<span class="s-secret">' + linkify(escaped) + '</span>';
                } else {
                    html += '<span class="s-text">' + linkify(escaped) + '</span>';
                }
            }
            loadingBox.style.display = 'none';
            contentBox.innerHTML = html;
            contentBox.style.display = 'block';
        } catch (err) {
            loadingBox.style.display = 'none';
            errorBox.textContent = err.message;
            errorBox.style.display = 'block';
        }
    })();
    async function sha256(data) { return new Uint8Array(await crypto.subtle.digest('SHA-256', data)); }
    function escapeHtml(str) { const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }
    function linkify(escapedHtml) {
        return escapedHtml.replace(/https?:\/\/[^\s<>'"]+/g, function(m) {
            return '<a href="' + m + '" target="_blank" rel="noopener" style="color:#6a9fd4;">' + m + '</a>';
        });
    }
    async function expireNow(btn) {
        var wrap = document.getElementById('expireConfirmWrap');
        var cb = document.getElementById('expireConfirmCb');
        if (!cb.checked) { wrap.classList.remove('shake'); void wrap.offsetWidth; wrap.classList.add('shake'); return; }
        btn.disabled = true; cb.disabled = true; btn.textContent = '...';
        try {
            const r = await fetch('/api/expire.php', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({uuid: btn.dataset.uuid}) });
            const j = await r.json();
            if (j.ok) { btn.textContent = '\u2713 ' + btn.dataset.success; btn.classList.add('done'); setTimeout(()=>location.reload(), 1500); }
            else { btn.textContent = btn.dataset.error; btn.disabled = false; cb.disabled = false; }
        } catch(e) { btn.textContent = btn.dataset.error; btn.disabled = false; cb.disabled = false; }
    }
    </script>
</body>
</html><?php
}

/**
 * Legacy v1: stare linki z nieszyfrowanymi sections
 */
function show_view_legacy(array $t, array $data, array $sections, bool $expired): void {
    $htmlSections = [];
    foreach ($sections as $s) {
        if ($s['type'] === 'secret') {
            $htmlSections[] = $expired
                ? ['type' => 'masked', 'content' => '●●●●●●']
                : ['type' => 'secret', 'content' => $s['content']];
        } else {
            $htmlSections[] = ['type' => 'text', 'content' => $s['content']];
        }
    }
    ?><!DOCTYPE html>
<html lang="<?= detect_lang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($t['title']) ?></title>
    <style><?= view_css() ?></style>
</head>
<body>
    <div class="header"><h1><a href="/" style="color:inherit;text-decoration:none;"><?= htmlspecialchars($t['title']) ?></a></h1></div>
    <div class="container">
        <?php if ($expired): ?>
        <div class="expired-banner">
            <?= htmlspecialchars($t['secrets_expired']) ?> — <?= htmlspecialchars($t['secrets_expired_info']) ?>
        </div>
        <?php endif; ?>
        <div class="content-box"><?php
            foreach ($htmlSections as $s) {
                $esc = htmlspecialchars($s['content']);
                $linked = ($s['type'] !== 'masked') ? linkify_html($esc) : $esc;
                switch ($s['type']) {
                    case 'secret': echo '<span class="s-secret">' . $linked . '</span>'; break;
                    case 'masked': echo '<span class="s-masked">' . $esc . '</span>'; break;
                    default: echo '<span class="s-text">' . $linked . '</span>';
                }
            }
        ?></div>
        <?= view_meta_html($t, $data, $expired) ?>
    </div>
    <?= view_footer_html() ?>
    <?php if (!$expired): ?>
    <script>
    async function expireNow(btn) {
        var wrap = document.getElementById('expireConfirmWrap');
        var cb = document.getElementById('expireConfirmCb');
        if (!cb.checked) { wrap.classList.remove('shake'); void wrap.offsetWidth; wrap.classList.add('shake'); return; }
        btn.disabled = true; cb.disabled = true; btn.textContent = '...';
        try {
            const r = await fetch('/api/expire.php', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({uuid: btn.dataset.uuid}) });
            const j = await r.json();
            if (j.ok) { btn.textContent = '\u2713 ' + btn.dataset.success; btn.classList.add('done'); setTimeout(()=>location.reload(), 1500); }
            else { btn.textContent = btn.dataset.error; btn.disabled = false; cb.disabled = false; }
        } catch(e) { btn.textContent = btn.dataset.error; btn.disabled = false; cb.disabled = false; }
    }
    </script>
    <?php endif; ?>
</body>
</html><?php
}
