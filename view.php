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
require_once __DIR__ . '/inc/logo.php';
require_once __DIR__ . '/inc/icons.php';

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

// --- WCZYTAJ PLIK (z exclusive lockiem - atomowy read-modify-write) ---
// Bez locka dwa rownoczesne wejscia na ostatnie wyswietlenie moglyby:
// oba zobaczyc sekrety, albo jeden wskrzesic skasowany blob nadpisujac plik.
$file = DATA_DIR . '/' . $uuid . '.json';
$fp = @fopen($file, 'r+');
if ($fp === false) {
    show_not_found($t);
    exit;
}
flock($fp, LOCK_EX);
$data = json_decode(stream_get_contents($fp), true);
if (!is_array($data)) {
    fclose($fp); // zwalnia tez lock
    show_not_found($t);
    exit;
}

// Zapis danych pod trzymanym lockiem (nadpisanie w miejscu).
function save_locked($fp, array $data): void {
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, $json);
    fflush($fp);
}

// --- HASLO ---
// v3 (password_verifier): bramka na auth_tag policzonym w przegladarce
//     (PBKDF2 z hasla + hexKey -> HKDF "bb3-auth"). Serwer NIGDY nie widzi hasla.
// v2 (password_hash): legacy bramka plaintext POST - bez zmian az stare linki wygasna.
if (!empty($data['password_verifier'])) {
    $submittedTag = $_POST['auth_tag'] ?? null;
    if ($submittedTag === null || $submittedTag === '') {
        fclose($fp);
        show_password_form_v3($t, $slug, $data);
        exit;
    }
    if (!is_string($submittedTag)
        || !preg_match('/^[0-9a-f]{64}$/', $submittedTag)
        || !hash_equals($data['password_verifier'], hash('sha256', $submittedTag))) {
        fclose($fp);
        show_password_form_v3($t, $slug, $data, true);
        exit;
    }
} elseif (!empty($data['password_hash'])) {
    $submittedPassword = $_POST['password'] ?? null;
    if ($submittedPassword === null) {
        fclose($fp);
        show_password_form($t, $slug);
        exit;
    }
    if (!password_verify($submittedPassword, $data['password_hash'])) {
        fclose($fp);
        show_password_form($t, $slug, true);
        exit;
    }
}

// --- SPRAWDŹ STATUS ---
$now = time();
$secretsExpired = (strtotime($data['expires_secrets']) <= $now)
    || ($data['current_views'] >= $data['max_views'])
    || ($data['encrypted_secrets'] === null && isset($data['_secrets_expired_at']));

// permanentne usunięcie (delete_after_days == 0 → od razu)
if ($secretsExpired && $data['delete_after_days'] == 0) {
    fclose($fp); // zwolnij lock przed rename (Windows nie przenosi otwartego pliku)
    move_to_trash($file, $uuid);
    show_expired($t, $data['_killed_manually'] ?? null, $data['_expired_manually'] ?? null);
    exit;
}

if ($secretsExpired && $data['delete_after_days'] > 0) {
    if (isset($data['_secrets_expired_at'])) {
        $deleteAt = $data['_secrets_expired_at'] + ($data['delete_after_days'] * 86400);
    } else {
        $data['_secrets_expired_at'] = $now;
    }

    if ($now >= ($deleteAt ?? $now + ($data['delete_after_days'] * 86400))) {
        fclose($fp);
        move_to_trash($file, $uuid);
        show_expired($t, $data['_killed_manually'] ?? null, $data['_expired_manually'] ?? null);
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
$lastView = false;

if (!$secretsExpired) {
    $data['current_views']++;
    $data['view_log'][] = [
        'time' => gmdate('Y-m-d\TH:i:s\Z'),
        'ip_hash' => substr(hash('sha256', ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0') . IP_HASH_SALT), 0, 12),
    ];
    // ogranicz dlugosc logu (przy duzym max_views plik nie puchnie bez limitu)
    if (count($data['view_log']) > 100) {
        $data['view_log'] = array_slice($data['view_log'], -100);
    }

    if ($data['current_views'] >= $data['max_views']) {
        // To jest ostatnie dozwolone wyświetlenie — user jeszcze widzi dane,
        // ale w pliku kasujemy sekrety (następne odwiedziny = wygaszone)
        $data['_secrets_expired_at'] = $now;
        $data['encrypted_secrets'] = null;
        $lastView = true; // ukryj przycisk expire — dane właśnie wygasają
    }

    $needSave = true;
}

if ($needSave) {
    save_locked($fp, $data);
}
fclose($fp); // zwolnij lock przed renderowaniem strony

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
    show_expired($t, $data['_killed_manually'] ?? null, $data['_expired_manually'] ?? null);
    exit;
}

show_view_encrypted($t, $data, $encText, $encSecrets, $secretsExpired);

// ============================================================
// FUNKCJE
// ============================================================

function linkify_html(string $escapedHtml): string {
    return preg_replace(
        '#(https?://[^\s<>\'"&]+(?:&amp;[^\s<>\'"&]+)*)#',
        '<a href="$1" target="_blank" rel="noopener" style="color:var(--bb-accent-link);">$1</a>',
        $escapedHtml
    );
}

function move_to_trash(string $file, string $uuid): void {
    if (!is_dir(TRASH_DIR)) {
        mkdir(TRASH_DIR, 0755, true);
    }
    rename($file, TRASH_DIR . '/' . $uuid . '.json');
}

function og_view_meta(array $t): void {
    $lang = detect_lang();
    $locale = $lang === 'pl' ? 'pl_PL' : 'en_US';
    $alt = $lang === 'pl' ? 'en_US' : 'pl_PL';
    ?>
    <meta property="og:type" content="website">
    <meta property="og:title" content="<?= htmlspecialchars($t['og_view_title']) ?>">
    <meta property="og:description" content="<?= htmlspecialchars($t['og_view_description']) ?>">
    <meta property="og:site_name" content="bitback.one">
    <meta property="og:locale" content="<?= $locale ?>">
    <meta property="og:locale:alternate" content="<?= $alt ?>">
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="<?= htmlspecialchars($t['og_view_title']) ?>">
    <meta name="twitter:description" content="<?= htmlspecialchars($t['og_view_description']) ?>">
    <link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
    <link rel="stylesheet" href="/assets/fonts.css?v=<?= filemtime(__DIR__ . '/assets/fonts.css') ?>">
    <link rel="stylesheet" href="/assets/tokens.css?v=<?= filemtime(__DIR__ . '/assets/tokens.css') ?>">
    <?php
}

function bb_page_art(): void {
    ?>
    <div class="bb-page-art bb-page-art-tl" aria-hidden="true"></div>
    <div class="bb-page-art bb-page-art-tr" aria-hidden="true"></div>
    <div class="bb-page-art bb-page-art-br" aria-hidden="true"></div>
    <div class="bb-page-art bb-page-art-bl" aria-hidden="true"></div>
    <?php
}

function show_password_form(array $t, string $slug, bool $wrongPassword = false): void {
    ?><!DOCTYPE html>
<html lang="<?= detect_lang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($t['title']) ?></title>
    <?php og_view_meta($t); ?>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: var(--bb-font-sans);
            background: var(--bb-bg); color: var(--bb-fg-1);
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
        }
        .box { text-align: center; padding: 2rem; width: 100%; max-width: 380px; }
        h1 { font-size: 1.4rem; font-weight: 300; color: var(--bb-fg); margin-bottom: 0.3rem; }
        .sub { color: var(--bb-fg-3); font-size: 0.88rem; margin-bottom: 1.5rem; }
        .pwd-input {
            width: 100%; padding: 0.65rem 0.85rem;
            background: var(--bb-surface-sunk); border: 1px solid var(--bb-border-mid); border-radius: 8px;
            color: var(--bb-fg); font-size: 0.95rem; outline: none; text-align: center;
            font-family: var(--bb-font-mono);
        }
        .pwd-input:focus { border-color: var(--bb-accent); box-shadow: 0 0 0 3px rgba(61, 130, 232, 0.15); }
        /* FLAT solid blue */
        .pwd-btn {
            width: 100%; padding: 0.7rem; margin-top: 0.7rem;
            border-radius: 8px; border: none;
            background: var(--bb-accent);
            color: #fff; font-size: 0.92rem; font-weight: 700;
            cursor: pointer; transition: background 140ms var(--bb-ease), transform 140ms var(--bb-ease);
        }
        .pwd-btn:hover { background: var(--bb-accent-hover); transform: translateY(-1px); }
        .pwd-btn:active { background: var(--bb-accent-press); transform: translateY(0); }
        .error { color: var(--bb-danger-light); font-size: 0.84rem; margin-top: 0.5rem; }
        .logo { color: var(--bb-fg-7); font-size: 0.75rem; margin-top: 2rem; letter-spacing: 0.1em; }
    </style>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="box bb-frame">
        <?= render_logo($t['title'], '/') ?>
        <div class="sub"><?= htmlspecialchars($t['password_required'] ?? 'This link is password protected') ?></div>
        <form method="POST" action="/<?= htmlspecialchars($slug) ?>" id="pwdForm">
            <input type="password" name="password" class="pwd-input" placeholder="<?= htmlspecialchars($t['password_placeholder'] ?? 'Enter password') ?>" autofocus required>
            <button type="submit" class="pwd-btn"><?= htmlspecialchars($t['password_submit'] ?? 'Open') ?></button>
            <?php if ($wrongPassword): ?>
            <div class="error"><?= htmlspecialchars($t['password_wrong'] ?? 'Wrong password') ?></div>
            <?php endif; ?>
        </form>
        <div class="logo"><a href="/" style="color:inherit;text-decoration:none;"><?= htmlspecialchars($t['title']) ?></a></div>
        <div style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:var(--bb-bg);border-top:1px solid var(--bb-border-soft);padding:0.5rem 1rem;text-align:center;font-size:0.75rem;color:var(--bb-fg-5);white-space:nowrap;">
            <a href="https://bitback.pl" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;"><strong>bitback.pl</strong></a>
            <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><?= htmlspecialchars($t['footer_source']) ?> <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;">GitHub</a><span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><strong style="color:var(--bb-accent-link);"><?= htmlspecialchars($t['footer_commercial']) ?></strong>
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

/**
 * Formularz hasła v3: KDF liczy się w przeglądarce, do serwera idzie tylko auth_tag.
 * Wygląd 1:1 z show_password_form (v2), różnice są wyłącznie w transporcie.
 */
function show_password_form_v3(array $t, string $slug, array $data, bool $wrongPassword = false): void {
    $iter = (int)($data['kdf']['iter'] ?? 600000);
    ?><!DOCTYPE html>
<html lang="<?= detect_lang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($t['title']) ?></title>
    <?php og_view_meta($t); ?>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: var(--bb-font-sans);
            background: var(--bb-bg); color: var(--bb-fg-1);
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
        }
        .box { text-align: center; padding: 2rem; width: 100%; max-width: 380px; }
        h1 { font-size: 1.4rem; font-weight: 300; color: var(--bb-fg); margin-bottom: 0.3rem; }
        .sub { color: var(--bb-fg-3); font-size: 0.88rem; margin-bottom: 1.5rem; }
        .pwd-input {
            width: 100%; padding: 0.65rem 0.85rem;
            background: var(--bb-surface-sunk); border: 1px solid var(--bb-border-mid); border-radius: 8px;
            color: var(--bb-fg); font-size: 0.95rem; outline: none; text-align: center;
            font-family: var(--bb-font-mono);
        }
        .pwd-input:focus { border-color: var(--bb-accent); box-shadow: 0 0 0 3px rgba(61, 130, 232, 0.15); }
        /* FLAT solid blue */
        .pwd-btn {
            width: 100%; padding: 0.7rem; margin-top: 0.7rem;
            border-radius: 8px; border: none;
            background: var(--bb-accent);
            color: #fff; font-size: 0.92rem; font-weight: 700;
            cursor: pointer; transition: background 140ms var(--bb-ease), transform 140ms var(--bb-ease);
        }
        .pwd-btn:hover { background: var(--bb-accent-hover); transform: translateY(-1px); }
        .pwd-btn:active { background: var(--bb-accent-press); transform: translateY(0); }
        .pwd-btn:disabled { opacity: 0.7; cursor: default; transform: none; }
        .error { color: var(--bb-danger-light); font-size: 0.84rem; margin-top: 0.5rem; }
        .logo { color: var(--bb-fg-7); font-size: 0.75rem; margin-top: 2rem; letter-spacing: 0.1em; }
    </style>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="box bb-frame">
        <?= render_logo($t['title'], '/') ?>
        <div class="sub"><?= htmlspecialchars($t['password_required'] ?? 'This link is password protected') ?></div>
        <form method="POST" action="/<?= htmlspecialchars($slug) ?>" id="pwdForm">
            <!-- pole hasla CELOWO BEZ atrybutu name: plaintext strukturalnie nie moze pojsc do serwera -->
            <input type="password" id="pwdInput" class="pwd-input" placeholder="<?= htmlspecialchars($t['password_placeholder'] ?? 'Enter password') ?>" autofocus required>
            <input type="hidden" name="auth_tag" id="authTag" value="">
            <button type="submit" class="pwd-btn" id="pwdBtn"><?= htmlspecialchars($t['password_submit'] ?? 'Open') ?></button>
            <?php if ($wrongPassword): ?>
            <div class="error"><?= htmlspecialchars($t['password_wrong'] ?? 'Wrong password') ?></div>
            <?php endif; ?>
            <div class="error" id="jsError" style="display:none;"></div>
            <noscript><div class="error"><?= htmlspecialchars($t['password_js_required']) ?></div></noscript>
        </form>
        <div class="logo"><a href="/" style="color:inherit;text-decoration:none;"><?= htmlspecialchars($t['title']) ?></a></div>
        <div style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:var(--bb-bg);border-top:1px solid var(--bb-border-soft);padding:0.5rem 1rem;text-align:center;font-size:0.75rem;color:var(--bb-fg-5);white-space:nowrap;">
            <a href="https://bitback.pl" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;"><strong>bitback.pl</strong></a>
            <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><?= htmlspecialchars($t['footer_source']) ?> <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;">GitHub</a><span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><strong style="color:var(--bb-accent-link);"><?= htmlspecialchars($t['footer_commercial']) ?></strong>
        </div>
    </div>
    <script src="/crypto.js?v=<?= filemtime(__DIR__ . '/crypto.js') ?>" integrity="sha384-4BY47Z9e+fuHtuSztPUqLut6qM8DMIDJsVMAutU/wlrPqn2vo+ZHbxJlH6ymu/d0"></script>
    <script>
    // v3: haslo NIE opuszcza przegladarki. Liczymy master (PBKDF2, ~0.3-1s),
    // wysylamy tylko authTag; master laduje w sessionStorage dla strony widoku
    // (kasowany tam natychmiast po odczycie).
    const SLUG = <?= json_encode($slug) ?>;
    const ITER = <?= $iter ?>;
    const form = document.getElementById('pwdForm');
    form.addEventListener('submit', async function(ev) {
        ev.preventDefault();
        const btn = document.getElementById('pwdBtn');
        const errBox = document.getElementById('jsError');
        errBox.style.display = 'none';
        const hexKey = window.location.hash.substring(1);
        if (!/^[0-9a-f]{32}$/i.test(hexKey)) {
            errBox.textContent = <?= json_encode($t['password_wrong_or_corrupt']) ?>;
            errBox.style.display = 'block';
            return;
        }
        const originalText = btn.textContent;
        btn.disabled = true;
        btn.textContent = <?= json_encode($t['password_checking']) ?>;
        try {
            const master = await deriveMasterV3(document.getElementById('pwdInput').value.trim(), hexKey, ITER);
            document.getElementById('authTag').value = await authTagFromMaster(master);
            try { sessionStorage.setItem('bb3m:' + SLUG, bytesToHex(master)); } catch (e) { /* tryb prywatny - fallback na stronie widoku */ }
            form.action = '/' + SLUG + window.location.hash;
            form.submit(); // programowy submit nie odpala tego handlera ponownie
        } catch (e) {
            btn.disabled = false;
            btn.textContent = originalText;
            errBox.textContent = <?= json_encode($t['password_wrong_or_corrupt']) ?>;
            errBox.style.display = 'block';
        }
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
    <?php og_view_meta($t); ?>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: var(--bb-font-sans);
            background: var(--bb-bg); color: var(--bb-fg-1);
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
            color: var(--bb-fg-7);
            letter-spacing: 0.15em;
            margin-bottom: 0.5rem;
        }
        h1 { font-size: 1.2rem; font-weight: 400; color: var(--bb-fg-4); margin-bottom: 0.8rem; }
        .sub { color: var(--bb-fg-6); font-size: 0.82rem; line-height: 1.6; margin-bottom: 0.5rem; }
        .hint { color: var(--bb-fg-7); font-size: 0.72rem; margin-top: 1rem; }
        .hint code { color: var(--bb-secret); background: #1a1a0a; padding: 0.1em 0.3em; border-radius: 3px; }
        .home-link {
            display: inline-block; margin-top: 1.5rem;
            padding: 0.5rem 1.2rem; border-radius: 6px;
            border: 1px solid var(--bb-border); background: var(--bb-surface-1);
            color: var(--bb-accent-link); text-decoration: none; font-size: 0.8rem;
            transition: background 0.15s;
        }
        .home-link:hover { background: var(--bb-surface-2); }
    </style>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="box bb-frame">
        <div class="ghost"><?= bb_icon('ghost') ?></div>
        <div class="code">404</div>
        <h1><?= htmlspecialchars($t['not_found_title']) ?></h1>
        <div class="sub"><?= htmlspecialchars($t['not_found_sub']) ?></div>
        <div class="hint"><?= htmlspecialchars($t['not_found_hint']) ?> <code>#</code></div>
        <a href="/" class="home-link"><?= htmlspecialchars($t['title']) ?> →</a>
        <div style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:var(--bb-bg);border-top:1px solid var(--bb-border-soft);padding:0.5rem 1rem;text-align:center;font-size:0.75rem;color:var(--bb-fg-5);white-space:nowrap;">
            <a href="https://bitback.pl" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;"><strong>bitback.pl</strong></a>
            <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><?= htmlspecialchars($t['footer_source']) ?> <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;">GitHub</a><span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><strong style="color:var(--bb-accent-link);"><?= htmlspecialchars($t['footer_commercial']) ?></strong>
        </div>
    </div>
</body>
</html><?php
    exit;
}

function show_expired(array $t, ?string $killedAt = null, ?string $expiredManually = null): void {
    http_response_code(410);
    $lang = detect_lang();
    // Info o manualnym ubiciu/wygaszeniu
    $manualInfo = '';
    if ($killedAt) {
        $date = substr($killedAt, 0, 10); // YYYY-MM-DD
        $manualInfo = $lang === 'pl'
            ? 'Link został ręcznie usunięty dnia ' . $date . '.'
            : 'Link was manually deleted on ' . $date . '.';
    } elseif ($expiredManually) {
        $date = substr($expiredManually, 0, 10);
        $manualInfo = $lang === 'pl'
            ? 'Dane poufne zostały ręcznie wygaszone dnia ' . $date . '.'
            : 'Secret data was manually expired on ' . $date . '.';
    }
    ?><!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($t['link_expired']) ?> — <?= htmlspecialchars($t['title']) ?></title>
    <?php og_view_meta($t); ?>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: var(--bb-font-sans);
            background: var(--bb-bg); color: var(--bb-fg-1);
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
        }
        .box { text-align: center; padding: 2rem; }
        h1 { font-size: 1.4rem; font-weight: 300; color: var(--bb-fg); margin-bottom: 0.5rem; }
        p { color: var(--bb-fg-5); font-size: 0.85rem; }
        .manual-info { color: var(--bb-secret-ink); font-size: 0.8rem; margin-top: 0.5rem; }
        .logo { color: var(--bb-fg-7); font-size: 0.75rem; margin-top: 2rem; letter-spacing: 0.1em; }
    </style>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="box bb-frame">
        <h1><?= htmlspecialchars($t['link_expired']) ?></h1>
        <p><?= htmlspecialchars($t['link_expired_info']) ?></p>
        <?php if ($manualInfo): ?>
        <p class="manual-info"><?= htmlspecialchars($manualInfo) ?></p>
        <?php endif; ?>
        <div class="logo"><a href="/" style="color:inherit;text-decoration:none;"><?= htmlspecialchars($t['title']) ?></a></div>
        <div style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:var(--bb-bg);border-top:1px solid var(--bb-border-soft);padding:0.5rem 1rem;text-align:center;font-size:0.75rem;color:var(--bb-fg-5);white-space:nowrap;">
            <a href="https://bitback.pl" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;"><strong>bitback.pl</strong></a>
            <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><?= htmlspecialchars($t['footer_source']) ?> <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;">GitHub</a><span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><strong style="color:var(--bb-accent-link);"><?= htmlspecialchars($t['footer_commercial']) ?></strong>
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
        body { font-family: var(--bb-font-sans); background: var(--bb-bg); color: var(--bb-fg-1); min-height: 100vh; padding-bottom: 2.5rem; }
        .header { text-align: center; padding: 2rem 1rem 1.5rem; }
        .header h1 { font-size: 1.4rem; font-weight: 300; letter-spacing: 0.08em; color: var(--bb-fg); }
        .container { max-width: 700px; margin: 0 auto; padding: 0 1rem 3rem; }
        .expired-banner { border-radius: 10px; padding: 0.75rem 1rem; margin-bottom: 1rem; font-size: 0.88rem; color: var(--bb-secret); /* background i border z bb-card-secret */ }
        .error-banner { background: var(--bb-danger-bg); border: 1px solid var(--bb-danger-border); border-radius: 10px; padding: 0.75rem 1rem; margin-bottom: 1rem; font-size: 0.88rem; color: var(--bb-danger-light); }
        .content-box { background: var(--bb-surface-sunk); border: 1px solid var(--bb-border); border-radius: 10px; padding: 1rem; font-family: var(--bb-font-mono); font-size: 0.95rem; line-height: 1.7; white-space: pre-wrap; word-break: break-word; }
        .s-text { color: var(--bb-fg-2); }
        .s-text a { color: var(--bb-accent-link); }
        .s-secret { background: rgba(212, 146, 42, 0.15); color: var(--bb-secret); border-radius: 3px; padding: 0.05em 0.2em; border-bottom: 2px solid rgba(212, 146, 42, 0.4); }
        .s-secret a { color: inherit; }
        .s-masked { background: rgba(100, 100, 100, 0.2); color: var(--bb-fg-5); border-radius: 3px; padding: 0.05em 0.2em; letter-spacing: 0.1em; }
        .bb-totp-zone { margin-top: 1.2rem; display: flex; flex-direction: column; gap: 1rem; }
        .bb-totp { border: 1px solid var(--bb-border); background: var(--bb-surface-1); padding: 1rem; display: flex; flex-direction: column; align-items: center; gap: 0.75rem; }
        .bb-totp-head { font-size: 0.78rem; letter-spacing: 0.08em; text-transform: uppercase; color: var(--bb-fg-4); text-align: center; }
        .bb-totp-label { font-family: var(--bb-font-mono); font-size: 0.82rem; color: var(--bb-fg-3); text-align: center; word-break: break-all; }
        .bb-totp-qr { background: #fff; padding: 12px; line-height: 0; }
        .bb-totp-qr svg { display: block; max-width: 100%; height: auto; shape-rendering: crispEdges; image-rendering: pixelated; }
        .bb-totp-row { display: flex; align-items: stretch; width: 100%; max-width: 360px; }
        .bb-totp-secret { flex: 1; font-family: var(--bb-font-mono); font-size: 0.82rem; background: var(--bb-surface-sunk); color: var(--bb-secret); padding: 0.5rem 0.7rem; word-break: break-all; user-select: all; border: 1px solid var(--bb-border); border-right: none; display: flex; align-items: center; }
        .bb-totp-copy { background: var(--bb-accent); color: #fff; border: none; padding: 0 1rem; font-size: 0.8rem; font-weight: 700; cursor: pointer; white-space: nowrap; transition: background 140ms var(--bb-ease); }
        .bb-totp-copy:hover { background: var(--bb-accent-hover); }
        .loading { text-align: center; padding: 2rem; color: var(--bb-fg-5); font-size: 0.85rem; }
        .loading .spinner { display: inline-block; width: 18px; height: 18px; border: 2px solid var(--bb-fg-7); border-top-color: var(--bb-fg-4); border-radius: 50%; animation: spin 0.6s linear infinite; margin-right: 0.5rem; vertical-align: middle; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .meta { margin-top: 1.2rem; display: flex; justify-content: space-between; align-items: flex-end; gap: 1rem; font-size: 0.8rem; color: var(--bb-fg-5); }
        .meta-big { font-size: 2rem; font-weight: 300; color: var(--bb-fg-3); line-height: 1; }
        .meta-big.warn { color: var(--bb-secret); }
        .meta-sub { font-size: 0.72rem; color: var(--bb-fg-6); margin-top: 0.15rem; }
        .expire-info { background: var(--bb-surface-1); border: 1px solid var(--bb-border); border-radius: 10px; padding: 0.75rem 1rem; margin-top: 1rem; font-size: 0.84rem; color: var(--bb-fg-5); display: flex; justify-content: space-between; align-items: center; }
        .expire-info .date { color: var(--bb-fg-3); }
        .zt-badge { margin-top: 1.5rem; text-align: center; font-size: 0.72rem; color: var(--bb-fg-7); }
        .zt-badge span { color: var(--bb-fg-6); }
        .expire-now-wrap { margin-top: 1rem; display: flex; flex-direction: column; align-items: center; gap: 0.6rem; }
        .expire-now-confirm { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.65rem 1.5rem; border: 1.5px solid transparent; border-radius: 8px; transition: border-color 0.2s; cursor: pointer; font-size: 0.85rem; line-height: 1.2; box-sizing: border-box; }
        .expire-now-confirm input[type="checkbox"] { accent-color: var(--bb-secret-ink); width: 16px; height: 16px; cursor: pointer; flex-shrink: 0; }
        .expire-now-confirm label { color: var(--bb-fg-4); font-size: 0.85rem; cursor: pointer; user-select: none; line-height: 1.2; }
        .expire-now-confirm.shake { border-color: var(--bb-danger); animation: shakeBox 0.4s ease; }
        @keyframes shakeBox { 0%,100% { transform: translateX(0); } 20%,60% { transform: translateX(-4px); } 40%,80% { transform: translateX(4px); } }
        /* expire-now: FLAT solid gold (akcja secret) */
        .expire-now-btn {
          padding: 0.7rem 1.5rem; border-radius: 8px; border: none;
          background: var(--bb-secret);
          color: #2a1d08;
          font-size: 0.92rem; font-weight: 700; line-height: 1.2; letter-spacing: 0.01em;
          cursor: pointer; box-sizing: border-box;
          transition: filter 140ms var(--bb-ease), transform 140ms var(--bb-ease);
        }
        .expire-now-btn:hover { filter: brightness(1.07); transform: translateY(-1px); }
        .expire-now-btn:active { filter: brightness(0.93); transform: translateY(0); }
        .expire-now-btn:disabled { opacity: 0.4; cursor: default; transform: none; }

        /* done state: FLAT solid green (sukces) */
        .expire-now-btn.done {
          background: var(--bb-success);
          color: var(--bb-success-ink);
        }

        /* kill variant: FLAT solid red (danger) */
        .expire-now-btn.kill {
          background: var(--bb-danger);
          color: #fff;
          font-size: 0.84rem; padding: 0.5rem 1.2rem;
        }
        .site-footer { position: fixed; bottom: 0; left: 0; right: 0; z-index: 100; background: var(--bb-bg); border-top: 1px solid var(--bb-border-soft); padding: 0.5rem 1rem; text-align: center; font-size: 0.8rem; color: var(--bb-fg-5); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .site-footer a { color: var(--bb-accent-link); text-decoration: none; }
        .site-footer a:hover { color: #8abcf0; text-decoration: underline; }
        .site-footer .sep { color: var(--bb-fg-8); margin: 0 0.5rem; }
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
    $html .= '<div class="zt-badge">' . bb_icon('lock') . ' ' . $ztText . '</div>';

    // Przyciski natychmiastowego wygaszenia/ubicia — tylko gdy sekrety aktywne i nie jest to ostatni widok
    global $lastView;
    if (!$expired && empty($lastView)) {
        $uuid = $data['id'] ?? '';
        $checkLabel = $lang === 'pl'
            ? 'Otrzymałem dane. Potwierdź'
            : 'I received the data. Confirm';
        $btnExpire = $lang === 'pl'
            ? 'wygaś poufne dane teraz'
            : 'expire secret data now';
        $btnKill = $lang === 'pl'
            ? 'usuń cały link teraz'
            : 'delete entire link now';
        $successExpire = $lang === 'pl'
            ? 'Dane poufne zostały wygaszone.'
            : 'Secret data has been expired.';
        $successKill = $lang === 'pl'
            ? 'Link został usunięty.'
            : 'Link has been deleted.';
        $errorMsg = $lang === 'pl'
            ? 'Nie udało się. Spróbuj ponownie.'
            : 'Failed. Please try again.';

        $html .= '<div class="expire-now-wrap">';
        $html .= '<div class="expire-now-confirm" id="expireConfirmWrap">';
        $html .= '<input type="checkbox" id="expireConfirmCb" autocomplete="off">';
        $html .= '<label for="expireConfirmCb">' . htmlspecialchars($checkLabel) . '</label>';
        $html .= '</div>';
        $html .= '<button type="button" class="expire-now-btn" onclick="expireNow(this,\'expire\')"';
        $html .= ' data-uuid="' . htmlspecialchars($uuid) . '"';
        $html .= ' data-success="' . htmlspecialchars($successExpire) . '"';
        $html .= ' data-error="' . htmlspecialchars($errorMsg) . '"';
        $html .= '>' . htmlspecialchars($btnExpire) . '</button>';
        $html .= '<button type="button" class="expire-now-btn kill" onclick="expireNow(this,\'kill\')"';
        $html .= ' data-uuid="' . htmlspecialchars($uuid) . '"';
        $html .= ' data-success="' . htmlspecialchars($successKill) . '"';
        $html .= ' data-error="' . htmlspecialchars($errorMsg) . '"';
        $html .= '>' . htmlspecialchars($btnKill) . '</button>';
        $html .= '</div>';
    }

    // Przycisk usunięcia linka na widoku wygaszonym (sekrety expired, ale link jeszcze żyje)
    if ($expired && !isset($data['_killed_manually'])) {
        $uuid = $data['id'] ?? '';
        $checkLabelKill = $lang === 'pl'
            ? 'Potwierdzam usunięcie'
            : 'Confirm deletion';
        $btnKillOnly = $lang === 'pl'
            ? 'usuń cały link teraz'
            : 'delete entire link now';
        $successKillOnly = $lang === 'pl'
            ? 'Link został usunięty.'
            : 'Link has been deleted.';
        $errorMsgKill = $lang === 'pl'
            ? 'Nie udało się. Spróbuj ponownie.'
            : 'Failed. Please try again.';

        $html .= '<div class="expire-now-wrap">';
        $html .= '<div class="expire-now-confirm" id="expireConfirmWrap">';
        $html .= '<input type="checkbox" id="expireConfirmCb" autocomplete="off">';
        $html .= '<label for="expireConfirmCb">' . htmlspecialchars($checkLabelKill) . '</label>';
        $html .= '</div>';
        $html .= '<button type="button" class="expire-now-btn kill" onclick="expireNow(this,\'kill\')"';
        $html .= ' data-uuid="' . htmlspecialchars($uuid) . '"';
        $html .= ' data-success="' . htmlspecialchars($successKillOnly) . '"';
        $html .= ' data-error="' . htmlspecialchars($errorMsgKill) . '"';
        $html .= '>' . htmlspecialchars($btnKillOnly) . '</button>';
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
            . $s . '<strong style="color:var(--bb-accent-link);">Użycie komercyjne wymaga licencji</strong>'
            . '</div>';
    }
    return '<div class="site-footer">'
        . '<a href="https://bitback.pl" target="_blank" rel="noopener"><strong>bitback.pl</strong></a>'
        . $s . 'We secure email, servers and computers'
        . $s . 'Zbigniew Gralewski'
        . $s . '<a href="mailto:zbigniew.gralewski@bitback.pl">zbigniew.gralewski@bitback.pl</a>'
        . $s . '609 505 065'
        . $s . 'Source code on <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener">GitHub</a>'
        . $s . '<strong style="color:var(--bb-accent-link);">Commercial use requires a license</strong>'
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
    <?php og_view_meta($t); ?>
    <style><?= view_css() ?></style>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="header"><?= render_logo($t['title'], '/') ?></div>
    <div class="container">
        <?php if ($expired): ?>
        <div class="expired-banner bb-card bb-card-secret bb-art bb-art-gold">
            <?= htmlspecialchars($t['secrets_expired']) ?> — <?= htmlspecialchars($t['secrets_expired_info']) ?>
            <?php if (isset($data['_expired_manually'])): ?>
            <br><small style="color:var(--bb-secret-ink);"><?= $lang === 'pl'
                ? 'Ręcznie wygaszone dnia ' . substr($data['_expired_manually'], 0, 10) . '.'
                : 'Manually expired on ' . substr($data['_expired_manually'], 0, 10) . '.' ?></small>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <div id="errorBox" class="error-banner" style="display:none;"></div>

        <div id="loadingBox" class="loading">
            <span class="spinner"></span> <?= $loadingText ?>
        </div>

        <div class="content-box" id="contentBox" style="display:none;"></div>
        <div id="totpZone" class="bb-totp-zone"></div>

        <?= view_meta_html($t, $data, $expired) ?>
    </div>
    <?= view_footer_html() ?>

    <script src="/crypto.js?v=<?= filemtime(__DIR__ . '/crypto.js') ?>" integrity="sha384-4BY47Z9e+fuHtuSztPUqLut6qM8DMIDJsVMAutU/wlrPqn2vo+ZHbxJlH6ymu/d0"></script>
    <script src="/assets/js/qrcode.min.js?v=<?= filemtime(__DIR__ . '/assets/js/qrcode.min.js') ?>" integrity="sha384-mZT2gIty7ZDdOGkxfP6joZcYdMW1Jvj9dRlfpTmaJAKKXTqzygtB22k7FLe+KZC1"></script>
    <script src="/assets/js/totp-qr.js?v=<?= filemtime(__DIR__ . '/assets/js/totp-qr.js') ?>" integrity="sha384-B3FEtW6GOMAbXTOr7mk6bAo6FV6TKCFXiLMOpnFXmTxwsrViJxFZyOP5Cqp3kVf1"></script>
    <script>
    // === ZERO-TRUST CLIENT-SIDE DECRYPTION ===
    // Dwa osobne bloby: tekst (zawsze) + sekrety (null jeśli wygasłe — fizycznie usunięte z serwera)

    const ENC_TEXT = <?= json_encode($encText) ?>;
    const ENC_SECRETS = <?= json_encode($encSecrets) ?>;  // null = sekrety fizycznie usunięte
    const TOTAL_SECTIONS = <?= (int)($data['total_sections'] ?? 0) ?>;
    const HAD_SECRETS = <?= ($expired && $encSecrets === null) ? 'true' : ($encSecrets !== null ? 'true' : 'false') ?>;
    const TOTP_STRINGS = <?= json_encode(['title' => $t['totp_qr_title'], 'copy' => $t['copy'], 'copied' => $t['copied']]) ?>;
    const FORMAT = <?= (int)($data['format'] ?? 2) ?>;
    const KDF_ITER = <?= (int)($data['kdf']['iter'] ?? 0) ?>;
    const HAS_VERIFIER = <?= !empty($data['password_verifier']) ? 'true' : 'false' ?>;
    const UUID = <?= json_encode($data['id'] ?? '') ?>;
    const T_WRONG = <?= json_encode($t['password_wrong_or_corrupt']) ?>;
    const T_REENTER = <?= json_encode($t['password_reenter']) ?>;
    const T_CHECKING = <?= json_encode($t['password_checking']) ?>;
    const T_SUBMIT = <?= json_encode($t['password_submit'] ?? 'Open') ?>;

    // Deklaracja MUSI stac przed IIFE: inline prompt bywa wolany z jego
    // SYNCHRONICZNEGO prefiksu (przed pierwszym await), gdy brak mastera w
    // sessionStorage. `let` nizej bylby wtedy w temporal dead zone i zamiast
    // pytania o haslo leciałby ReferenceError.
    let inlineWrap = null, inlineErr = null;

    (async function() {
        const loadingBox = document.getElementById('loadingBox');
        const contentBox = document.getElementById('contentBox');
        const errorBox = document.getElementById('errorBox');

        try {
            const hexKey = window.location.hash.substring(1);
            if (!hexKey || !/^[0-9a-f]{32}$/i.test(hexKey)) {
                throw new Error(<?= json_encode($noKeyError) ?>);
            }

            let textItems, secretItems = [];
            if (FORMAT === 3) {
                const dec = await decryptV3(hexKey);
                textItems = dec.text; secretItems = dec.secrets;
            } else {
                textItems = await decryptBlob(ENC_TEXT, hexKey);
                if (ENC_SECRETS) secretItems = await decryptBlob(ENC_SECRETS, hexKey);
            }
            if (inlineWrap) inlineWrap.style.display = 'none';

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

            if (window.BBTotp) BBTotp.scan(contentBox, document.getElementById('totpZone'), TOTP_STRINGS);

        } catch (err) {
            loadingBox.style.display = 'none';
            // GCM nie odroznia zlego klucza od uszkodzonego blobu - komunikat laczony.
            errorBox.textContent = (err && err.name === 'OperationError') ? T_WRONG : err.message;
            errorBox.style.display = 'block';
        }
    })();

    async function tryDecryptV3(aesKey) {
        const text = await decryptBlobV3(ENC_TEXT, aesKey);
        const secrets = ENC_SECRETS ? await decryptBlobV3(ENC_SECRETS, aesKey) : [];
        return { text: text, secrets: secrets };
    }

    async function decryptV3(hexKey) {
        // 1. link bez hasla
        if (!HAS_VERIFIER) {
            return tryDecryptV3(await aesKeyNoPassV3(hexKey));
        }
        // 2. master przekazany z formularza hasla (sessionStorage, kasowany od razu)
        let masterHex = null;
        try {
            const k = 'bb3m:' + UUID;
            masterHex = sessionStorage.getItem(k);
            sessionStorage.removeItem(k);
        } catch (e) {}
        if (masterHex && /^[0-9a-f]{64}$/.test(masterHex)) {
            try {
                return await tryDecryptV3(await aesKeyFromMaster(hexToBytes(masterHex)));
            } catch (e) { /* spadnij do re-promptu */ }
        }
        // 3. fallback: inline haslo. Blob JUZ w pamieci - retry hasla bez refetch,
        //    bez spalania kolejnego view (bramke przeszlismy).
        while (true) {
            const pwd = await promptPasswordInline();
            const master = await deriveMasterV3(pwd, hexKey, KDF_ITER);
            try {
                return await tryDecryptV3(await aesKeyFromMaster(master));
            } catch (e) {
                showInlineError(T_WRONG);
            }
        }
    }

    // Inline formularz hasla w miejscu loadera; resolve po kliknieciu/enterze.
    function promptPasswordInline() {
        return new Promise(function(resolve) {
            const loadingBox = document.getElementById('loadingBox');
            loadingBox.style.display = 'none';
            if (!inlineWrap) {
                inlineWrap = document.createElement('div');
                inlineWrap.style.cssText = 'text-align:center;padding:1.5rem 0;';
                inlineWrap.innerHTML =
                    '<div style="color:var(--bb-fg-3);font-size:0.88rem;margin-bottom:0.6rem;">' + escapeHtml(T_REENTER) + '</div>' +
                    '<input type="password" id="inlinePwd" class="pwd-input" style="max-width:300px;width:100%;padding:0.6rem;background:var(--bb-surface-sunk);border:1px solid var(--bb-border-mid);border-radius:8px;color:var(--bb-fg);text-align:center;font-family:var(--bb-font-mono);outline:none;">' +
                    '<br><button type="button" id="inlinePwdBtn" style="margin-top:0.6rem;padding:0.6rem 1.6rem;border-radius:8px;border:none;background:var(--bb-accent);color:#fff;font-weight:700;cursor:pointer;">' + escapeHtml(T_SUBMIT) + '</button>' +
                    '<div id="inlinePwdErr" style="color:var(--bb-danger-light);font-size:0.84rem;margin-top:0.5rem;display:none;"></div>';
                document.getElementById('errorBox').parentNode.insertBefore(inlineWrap, document.getElementById('loadingBox'));
                inlineErr = inlineWrap.querySelector('#inlinePwdErr');
            }
            inlineWrap.style.display = '';
            const input = inlineWrap.querySelector('#inlinePwd');
            const btn = inlineWrap.querySelector('#inlinePwdBtn');
            input.value = ''; input.focus();
            function go() {
                btn.disabled = true; btn.textContent = T_CHECKING;
                // trim spojnie z tworzeniem (index.php: linkPassword.value.trim()) - inaczej
                // spacja wiodaca/koncowa daje inny authTag niz przy tworzeniu -> falszywy blad hasla.
                resolve(input.value.trim());
            }
            btn.onclick = go;
            input.onkeydown = function(e) { if (e.key === 'Enter') go(); };
        });
    }
    function showInlineError(msg) {
        const btn = inlineWrap.querySelector('#inlinePwdBtn');
        btn.disabled = false; btn.textContent = T_SUBMIT;
        inlineErr.textContent = msg; inlineErr.style.display = 'block';
    }

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
                return '<a href="' + match + '" target="_blank" rel="noopener" style="color:var(--bb-accent-link);">' + match + '</a>';
            }
        );
    }

    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    async function expireNow(btn, action) {
        var wrap = document.getElementById('expireConfirmWrap');
        var cb = document.getElementById('expireConfirmCb');
        if (!cb.checked) {
            wrap.classList.remove('shake');
            void wrap.offsetWidth;
            wrap.classList.add('shake');
            return;
        }
        // Wyłącz oba przyciski
        document.querySelectorAll('.expire-now-btn').forEach(function(b) { b.disabled = true; });
        cb.disabled = true;
        btn.textContent = '...';
        const ctrl = new AbortController();
        const timer = setTimeout(function() { ctrl.abort(); }, 15000);
        try {
            const resp = await fetch('/api/expire.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                signal: ctrl.signal,
                body: JSON.stringify({ uuid: btn.dataset.uuid, action: action || 'expire' }),
            });
            clearTimeout(timer);
            const result = await resp.json();
            if (result.ok) {
                btn.textContent = '\u2713 ' + btn.dataset.success;
                btn.classList.add('done');
                setTimeout(function() { location.reload(); }, 1500);
            } else {
                btn.textContent = btn.dataset.error;
                document.querySelectorAll('.expire-now-btn').forEach(function(b) { b.disabled = false; });
                cb.disabled = false;
            }
        } catch (e) {
            btn.textContent = btn.dataset.error;
            document.querySelectorAll('.expire-now-btn').forEach(function(b) { b.disabled = false; });
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
    <?php og_view_meta($t); ?>
    <style><?= view_css() ?></style>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="header"><?= render_logo($t['title'], '/') ?></div>
    <div class="container">
        <?php if ($expired): ?>
        <div class="expired-banner bb-card bb-card-secret bb-art bb-art-gold">
            <?= htmlspecialchars($t['secrets_expired']) ?> — <?= htmlspecialchars($t['secrets_expired_info']) ?>
            <?php if (isset($data['_expired_manually'])): ?>
            <br><small style="color:var(--bb-secret-ink);"><?= $lang === 'pl'
                ? 'Ręcznie wygaszone dnia ' . substr($data['_expired_manually'], 0, 10) . '.'
                : 'Manually expired on ' . substr($data['_expired_manually'], 0, 10) . '.' ?></small>
            <?php endif; ?>
        </div>
        <?php endif; ?>
        <div id="errorBox" class="error-banner" style="display:none;"></div>
        <div id="loadingBox" class="loading"><span class="spinner"></span> <?= $loadingText ?></div>
        <div class="content-box" id="contentBox" style="display:none;"></div>
        <div id="totpZone" class="bb-totp-zone"></div>
        <?= view_meta_html($t, $data, $expired) ?>
    </div>
    <?= view_footer_html() ?>
    <script src="/crypto.js?v=<?= filemtime(__DIR__ . '/crypto.js') ?>" integrity="sha384-4BY47Z9e+fuHtuSztPUqLut6qM8DMIDJsVMAutU/wlrPqn2vo+ZHbxJlH6ymu/d0"></script>
    <script src="/assets/js/qrcode.min.js?v=<?= filemtime(__DIR__ . '/assets/js/qrcode.min.js') ?>" integrity="sha384-mZT2gIty7ZDdOGkxfP6joZcYdMW1Jvj9dRlfpTmaJAKKXTqzygtB22k7FLe+KZC1"></script>
    <script src="/assets/js/totp-qr.js?v=<?= filemtime(__DIR__ . '/assets/js/totp-qr.js') ?>" integrity="sha384-B3FEtW6GOMAbXTOr7mk6bAo6FV6TKCFXiLMOpnFXmTxwsrViJxFZyOP5Cqp3kVf1"></script>
    <script>
    const ENCRYPTED_PAYLOAD = <?= json_encode($encryptedPayload) ?>;
    const TOTP_STRINGS = <?= json_encode(['title' => $t['totp_qr_title'], 'copy' => $t['copy'], 'copied' => $t['copied']]) ?>;
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
            if (window.BBTotp) BBTotp.scan(contentBox, document.getElementById('totpZone'), TOTP_STRINGS);
        } catch (err) {
            loadingBox.style.display = 'none';
            errorBox.textContent = err.message;
            errorBox.style.display = 'block';
        }
    })();
    function escapeHtml(str) { const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }
    function linkify(escapedHtml) {
        return escapedHtml.replace(/https?:\/\/[^\s<>'"]+/g, function(m) {
            return '<a href="' + m + '" target="_blank" rel="noopener" style="color:var(--bb-accent-link);">' + m + '</a>';
        });
    }
    async function expireNow(btn, action) {
        var wrap = document.getElementById('expireConfirmWrap');
        var cb = document.getElementById('expireConfirmCb');
        if (!cb.checked) { wrap.classList.remove('shake'); void wrap.offsetWidth; wrap.classList.add('shake'); return; }
        document.querySelectorAll('.expire-now-btn').forEach(b => b.disabled = true);
        cb.disabled = true; btn.textContent = '...';
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 15000);
        try {
            const r = await fetch('/api/expire.php', { method: 'POST', headers: {'Content-Type':'application/json'}, signal: ctrl.signal, body: JSON.stringify({uuid: btn.dataset.uuid, action: action || 'expire'}) });
            clearTimeout(timer);
            const j = await r.json();
            if (j.ok) { btn.textContent = '\u2713 ' + btn.dataset.success; btn.classList.add('done'); setTimeout(()=>location.reload(), 1500); }
            else { btn.textContent = btn.dataset.error; document.querySelectorAll('.expire-now-btn').forEach(b => b.disabled = false); cb.disabled = false; }
        } catch(e) { btn.textContent = btn.dataset.error; document.querySelectorAll('.expire-now-btn').forEach(b => b.disabled = false); cb.disabled = false; }
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
    <?php og_view_meta($t); ?>
    <style><?= view_css() ?></style>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="header"><?= render_logo($t['title'], '/') ?></div>
    <div class="container">
        <?php if ($expired): $ll = detect_lang(); ?>
        <div class="expired-banner bb-card bb-card-secret bb-art bb-art-gold">
            <?= htmlspecialchars($t['secrets_expired']) ?> — <?= htmlspecialchars($t['secrets_expired_info']) ?>
            <?php if (isset($data['_expired_manually'])): ?>
            <br><small style="color:var(--bb-secret-ink);"><?= $ll === 'pl'
                ? 'Ręcznie wygaszone dnia ' . substr($data['_expired_manually'], 0, 10) . '.'
                : 'Manually expired on ' . substr($data['_expired_manually'], 0, 10) . '.' ?></small>
            <?php endif; ?>
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
    <script>
    async function expireNow(btn, action) {
        var wrap = document.getElementById('expireConfirmWrap');
        var cb = document.getElementById('expireConfirmCb');
        if (!cb.checked) { wrap.classList.remove('shake'); void wrap.offsetWidth; wrap.classList.add('shake'); return; }
        document.querySelectorAll('.expire-now-btn').forEach(b => b.disabled = true);
        cb.disabled = true; btn.textContent = '...';
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 15000);
        try {
            const r = await fetch('/api/expire.php', { method: 'POST', headers: {'Content-Type':'application/json'}, signal: ctrl.signal, body: JSON.stringify({uuid: btn.dataset.uuid, action: action || 'expire'}) });
            clearTimeout(timer);
            const j = await r.json();
            if (j.ok) { btn.textContent = '\u2713 ' + btn.dataset.success; btn.classList.add('done'); setTimeout(()=>location.reload(), 1500); }
            else { btn.textContent = btn.dataset.error; document.querySelectorAll('.expire-now-btn').forEach(b => b.disabled = false); cb.disabled = false; }
        } catch(e) { btn.textContent = btn.dataset.error; document.querySelectorAll('.expire-now-btn').forEach(b => b.disabled = false); cb.disabled = false; }
    }
    </script>
</body>
</html><?php
}
