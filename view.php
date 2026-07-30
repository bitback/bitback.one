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
require_once __DIR__ . '/inc/ratelimit.php';
require_once __DIR__ . '/inc/util.php';    // save_locked()
require_once __DIR__ . '/inc/assets.php'; // asset_css()
require_once __DIR__ . '/inc/footer.php'; // site_footer_html()

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

// --- WYGASLY LEGACY: kasuj PRZED bramka hasla ---
// Legacy (v2/v1) ma jeden wspolny blob, wiec po wygasnieciu nie ma czego pokazac -
// pytanie o haslo byloby bez sensu. Gdyby kasowanie stalo za bramka, rekord
// chroniony haslem NIGDY by sie nie wyczyscil przez web (nikt nie przechodzi
// bramki bez hasla), a bcrypt liczony dla martwego linku to darmowy CPU-DoS.
$legacyFields = ['encrypted_payload', 'sections'];
$isLegacy = false;
foreach ($legacyFields as $lf) { if (isset($data[$lf])) { $isLegacy = true; break; } }

if ($isLegacy
    && ((strtotime($data['expires_secrets'] ?? '2099-01-01') <= time())
        || (($data['current_views'] ?? 0) >= ($data['max_views'] ?? 9999)))) {
    foreach ($legacyFields as $lf) {
        if (isset($data[$lf])) { $data[$lf] = null; }
    }
    $data['_secrets_expired_at'] = $data['_secrets_expired_at'] ?? time();
    save_locked($fp, $data);
    fclose($fp);
    show_expired($t, $data['_killed_manually'] ?? null, $data['_expired_manually'] ?? null);
    exit;
}

// --- HASLO ---
// v3 (password_verifier): bramka na auth_tag policzonym w przegladarce
//     (PBKDF2 z hasla + hexKey -> HKDF "bb3-auth"). Serwer NIGDY nie widzi hasla.
// v2 (password_hash): legacy bramka plaintext POST - bez zmian az stare linki wygasna.
// Throttling NIEUDANYCH prob per IP (nie per uuid - inaczej ktokolwiek zna link
// moglby go zaryglowac odbiorcy). Poprawne haslo nie zjada budzetu.
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

if (!empty($data['password_verifier'])) {
    $submittedTag = $_POST['auth_tag'] ?? null;
    if ($submittedTag === null || $submittedTag === '') {
        fclose($fp);
        show_password_form_v3($t, $slug, $data);
        exit;
    }
    if (pwd_rate_blocked($clientIp)) {
        fclose($fp);
        http_response_code(429);
        show_password_form_v3($t, $slug, $data, false, true);
        exit;
    }
    if (!is_string($submittedTag)
        || !preg_match('/^[0-9a-f]{64}$/', $submittedTag)
        || !hash_equals($data['password_verifier'], hash('sha256', $submittedTag))) {
        pwd_rate_fail($clientIp);
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
    // Sprawdzenie PRZED password_verify: bcrypt to ~100 ms CPU serwera na probe,
    // wiec throttling jest tu tez ochrona przed CPU-DoS.
    if (pwd_rate_blocked($clientIp)) {
        fclose($fp);
        http_response_code(429);
        show_password_form($t, $slug, false, true);
        exit;
    }
    if (!password_verify($submittedPassword, $data['password_hash'])) {
        pwd_rate_fail($clientIp);
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

$expiredAtJustSet = false;
if ($secretsExpired && $data['delete_after_days'] > 0) {
    if (isset($data['_secrets_expired_at'])) {
        $deleteAt = $data['_secrets_expired_at'] + ($data['delete_after_days'] * 86400);
    } else {
        $data['_secrets_expired_at'] = $now;
        // utrwal znacznik startu odliczania tez dla rekordow BEZ sekretow (blok nizej
        // go pomija, bo isset(encrypted_secrets=null)===false) - inaczej odliczanie do
        // permanentnego usuniecia startuje od nowa przy kazdym wejsciu az do crona.
        $expiredAtJustSet = true;
    }

    if ($now >= ($deleteAt ?? $now + ($data['delete_after_days'] * 86400))) {
        fclose($fp);
        move_to_trash($file, $uuid);
        show_expired($t, $data['_killed_manually'] ?? null, $data['_expired_manually'] ?? null);
        exit;
    }
}

// --- FIZYCZNE KASOWANIE SEKRETÓW (lazy — przy pierwszym odczycie po wygaśnięciu) ---
$needSave = $expiredAtJustSet;

if ($secretsExpired && isset($data['encrypted_secrets'])) {
    // NIEODWRACALNE: usuwamy blob sekretów z pliku
    $data['encrypted_secrets'] = null;
    if (!isset($data['_secrets_expired_at'])) {
        $data['_secrets_expired_at'] = $now;
    }
    $needSave = true;
}

// LEGACY v2/v1: jeden wspolny blob, wiec serwer nie umie wyciac z niego samych
// sekretow bez klucza. Dawniej po wygasnieciu blob nadal szedl do przegladarki,
// a maskowanie robil TYLKO JS - kto mial link z kluczem, odczytywal "wygaszone"
// dane z devtools. Teraz wygasniecie kasuje caly ciphertext, zgodnie z obietnica
// fizycznego usuwania. Rekord zostaje jako martwy (widok "link wygasl").
if ($secretsExpired) {
    foreach (['encrypted_payload', 'sections'] as $legacyField) {
        if (isset($data[$legacyField])) {
            $data[$legacyField] = null;
            $needSave = true;
        }
    }
    if ($needSave && !isset($data['_secrets_expired_at'])) {
        $data['_secrets_expired_at'] = $now;
    }
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
// UWAGA: isset() na null daje false, wiec legacy wyzerowany wyzej po wygasnieciu
// NIE wchodzi w te galezie - spada nizej i konczy na show_expired(). Celowe.
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
    <?= asset_css('assets/fonts.css', 'assets/tokens.css') ?>
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

function show_password_form(array $t, string $slug, bool $wrongPassword = false, bool $tooMany = false): void {
    ?><!DOCTYPE html>
<html lang="<?= detect_lang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($t['title']) ?></title>
    <?php og_view_meta($t); ?>
    <?= asset_css('assets/css/gate.css', 'assets/css/footer.css') ?>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="box bb-frame">
        <?= render_logo($t['title'], '/') ?>
        <div class="sub"><?= htmlspecialchars($t['password_required'] ?? 'This link is password protected') ?></div>
        <form method="POST" action="/<?= htmlspecialchars($slug) ?>" id="pwdForm">
            <input type="password" name="password" class="pwd-input" placeholder="<?= htmlspecialchars($t['password_placeholder'] ?? 'Enter password') ?>" autofocus required>
            <button type="submit" class="pwd-btn"><?= htmlspecialchars($t['password_submit'] ?? 'Open') ?></button>
            <?php if ($tooMany): ?>
            <div class="error"><?= htmlspecialchars($t['password_too_many']) ?></div>
            <?php elseif ($wrongPassword): ?>
            <div class="error"><?= htmlspecialchars($t['password_wrong'] ?? 'Wrong password') ?></div>
            <?php endif; ?>
        </form>
        <div class="logo"><a href="/"><?= htmlspecialchars($t['title']) ?></a></div>
        <?= site_footer_html(true) ?>
    </div>
    <?= json_island('bb-gate', ['slug' => $slug]) ?>
    <?= asset_js('assets/js/gate-v2.js') ?>
</body>
</html><?php
    exit;
}

/**
 * Formularz hasła v3: KDF liczy się w przeglądarce, do serwera idzie tylko auth_tag.
 * Wygląd 1:1 z show_password_form (v2), różnice są wyłącznie w transporcie.
 */
function show_password_form_v3(array $t, string $slug, array $data, bool $wrongPassword = false, bool $tooMany = false): void {
    $iter = (int)($data['kdf']['iter'] ?? 600000);
    ?><!DOCTYPE html>
<html lang="<?= detect_lang() ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($t['title']) ?></title>
    <?php og_view_meta($t); ?>
    <?= asset_css('assets/css/gate.css', 'assets/css/footer.css') ?>
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
            <?php if ($tooMany): ?>
            <div class="error"><?= htmlspecialchars($t['password_too_many']) ?></div>
            <?php elseif ($wrongPassword): ?>
            <div class="error"><?= htmlspecialchars($t['password_wrong'] ?? 'Wrong password') ?></div>
            <?php endif; ?>
            <div class="error" id="jsError" style="display:none;"></div>
            <noscript><div class="error"><?= htmlspecialchars($t['password_js_required']) ?></div></noscript>
        </form>
        <div class="logo"><a href="/"><?= htmlspecialchars($t['title']) ?></a></div>
        <?= site_footer_html(true) ?>
    </div>
    <script src="/crypto.js?v=<?= filemtime(__DIR__ . '/crypto.js') ?>" integrity="sha384-RQoDrUypIasRu3YH/1KbhpaEtfmzmQlvafmSuNpL1E3zl8rpuvHzLF/C9jqmsD53"></script>
    <?= json_island('bb-gate', [
        'slug' => $slug,
        'iter' => $iter,
        't'    => [
            'wrongOrCorrupt' => $t['password_wrong_or_corrupt'],
            'checking'       => $t['password_checking'],
        ],
    ]) ?>
    <?= asset_js('assets/js/gate-v3.js') ?>
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
    <?= asset_css('assets/css/notfound.css', 'assets/css/footer.css') ?>
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
        <?= site_footer_html(true) ?>
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
    <?= asset_css('assets/css/expired.css', 'assets/css/footer.css') ?>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="box bb-frame">
        <h1><?= htmlspecialchars($t['link_expired']) ?></h1>
        <p><?= htmlspecialchars($t['link_expired_info']) ?></p>
        <?php if ($manualInfo): ?>
        <p class="manual-info"><?= htmlspecialchars($manualInfo) ?></p>
        <?php endif; ?>
        <div class="logo"><a href="/"><?= htmlspecialchars($t['title']) ?></a></div>
        <?= site_footer_html(true) ?>
    </div>
</body>
</html><?php
    exit;
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
        $html .= '<button type="button" class="expire-now-btn" data-bb-action="expire"';
        $html .= ' data-uuid="' . htmlspecialchars($uuid) . '"';
        $html .= ' data-success="' . htmlspecialchars($successExpire) . '"';
        $html .= ' data-error="' . htmlspecialchars($errorMsg) . '"';
        $html .= '>' . htmlspecialchars($btnExpire) . '</button>';
        $html .= '<button type="button" class="expire-now-btn kill" data-bb-action="kill"';
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
        $html .= '<button type="button" class="expire-now-btn kill" data-bb-action="kill"';
        $html .= ' data-uuid="' . htmlspecialchars($uuid) . '"';
        $html .= ' data-success="' . htmlspecialchars($successKillOnly) . '"';
        $html .= ' data-error="' . htmlspecialchars($errorMsgKill) . '"';
        $html .= '>' . htmlspecialchars($btnKillOnly) . '</button>';
        $html .= '</div>';
    }

    return $html;
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
    <?= asset_css('assets/css/view.css', 'assets/css/footer.css') ?>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="header"><?= render_logo($t['title'], '/') ?></div>
    <div class="container">
        <?php if ($expired): ?>
        <div class="expired-banner bb-card bb-card-secret bb-art bb-art-gold">
            <?= htmlspecialchars($t['secrets_expired']) ?> — <?= htmlspecialchars($t['secrets_expired_info']) ?>
            <?php if (isset($data['_expired_manually'])): ?>
            <br><small><?= $lang === 'pl'
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
    <?= site_footer_html() ?>

    <script src="/crypto.js?v=<?= filemtime(__DIR__ . '/crypto.js') ?>" integrity="sha384-RQoDrUypIasRu3YH/1KbhpaEtfmzmQlvafmSuNpL1E3zl8rpuvHzLF/C9jqmsD53"></script>
    <script src="/assets/js/qrcode.min.js?v=<?= filemtime(__DIR__ . '/assets/js/qrcode.min.js') ?>" integrity="sha384-mZT2gIty7ZDdOGkxfP6joZcYdMW1Jvj9dRlfpTmaJAKKXTqzygtB22k7FLe+KZC1"></script>
    <script src="/assets/js/totp-qr.js?v=<?= filemtime(__DIR__ . '/assets/js/totp-qr.js') ?>" integrity="sha384-B3FEtW6GOMAbXTOr7mk6bAo6FV6TKCFXiLMOpnFXmTxwsrViJxFZyOP5Cqp3kVf1"></script>
    <?= json_island('bb-view', [
        'encText'       => $encText,
        'encSecrets'    => $encSecrets,
        'totalSections' => (int)($data['total_sections'] ?? 0),
        'hadSecrets'    => ($expired && $encSecrets === null) ? true : ($encSecrets !== null),
        'totp'          => ['title' => $t['totp_qr_title'], 'copy' => $t['copy'], 'copied' => $t['copied']],
        'format'        => (int)($data['format'] ?? 2),
        'kdfIter'       => (int)($data['kdf']['iter'] ?? 0),
        'hasVerifier'   => !empty($data['password_verifier']),
        'uuid'          => $data['id'] ?? '',
        'noKeyError'    => $noKeyError,
        't'             => [
            'wrong'    => $t['password_wrong_or_corrupt'],
            'reenter'  => $t['password_reenter'],
            'checking' => $t['password_checking'],
            'submit'   => $t['password_submit'] ?? 'Open',
        ],
    ]) ?>
    <?= asset_js('assets/js/view-common.js', 'assets/js/view-decrypt.js') ?>
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
    <?= asset_css('assets/css/view.css', 'assets/css/footer.css') ?>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="header"><?= render_logo($t['title'], '/') ?></div>
    <div class="container">
        <?php if ($expired): ?>
        <div class="expired-banner bb-card bb-card-secret bb-art bb-art-gold">
            <?= htmlspecialchars($t['secrets_expired']) ?> — <?= htmlspecialchars($t['secrets_expired_info']) ?>
            <?php if (isset($data['_expired_manually'])): ?>
            <br><small><?= $lang === 'pl'
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
    <?= site_footer_html() ?>
    <script src="/crypto.js?v=<?= filemtime(__DIR__ . '/crypto.js') ?>" integrity="sha384-RQoDrUypIasRu3YH/1KbhpaEtfmzmQlvafmSuNpL1E3zl8rpuvHzLF/C9jqmsD53"></script>
    <script src="/assets/js/qrcode.min.js?v=<?= filemtime(__DIR__ . '/assets/js/qrcode.min.js') ?>" integrity="sha384-mZT2gIty7ZDdOGkxfP6joZcYdMW1Jvj9dRlfpTmaJAKKXTqzygtB22k7FLe+KZC1"></script>
    <script src="/assets/js/totp-qr.js?v=<?= filemtime(__DIR__ . '/assets/js/totp-qr.js') ?>" integrity="sha384-B3FEtW6GOMAbXTOr7mk6bAo6FV6TKCFXiLMOpnFXmTxwsrViJxFZyOP5Cqp3kVf1"></script>
    <?= json_island('bb-view', [
        'payload'        => $encryptedPayload,
        'totp'           => ['title' => $t['totp_qr_title'], 'copy' => $t['copy'], 'copied' => $t['copied']],
        'secretsExpired' => $expired,
        'noKeyError'     => $noKeyError,
    ]) ?>
    <?= asset_js('assets/js/view-common.js', 'assets/js/view-decrypt-v2.js') ?>
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
    <?= asset_css('assets/css/view.css', 'assets/css/footer.css') ?>
</head>
<body>
    <?php bb_page_art(); ?>
    <div class="header"><?= render_logo($t['title'], '/') ?></div>
    <div class="container">
        <?php if ($expired): $ll = detect_lang(); ?>
        <div class="expired-banner bb-card bb-card-secret bb-art bb-art-gold">
            <?= htmlspecialchars($t['secrets_expired']) ?> — <?= htmlspecialchars($t['secrets_expired_info']) ?>
            <?php if (isset($data['_expired_manually'])): ?>
            <br><small><?= $ll === 'pl'
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
    <?= site_footer_html() ?>
    <?= asset_js('assets/js/view-common.js') ?>
</body>
</html><?php
}
