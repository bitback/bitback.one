<?php
/**
 * Custom 404 — friendly ghost for lost visitors
 */

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/i18n.php';
require_once __DIR__ . '/inc/icons.php';
require_once __DIR__ . '/inc/assets.php';
require_once __DIR__ . '/inc/footer.php';

$lang = detect_lang();
$t = get_strings($lang);

http_response_code(404);
?><!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 — <?= htmlspecialchars($t['title']) ?></title>
    <meta property="og:type" content="website">
    <meta property="og:title" content="<?= htmlspecialchars($t['meta_title'] ?? $t['title']) ?>">
    <meta property="og:description" content="<?= htmlspecialchars($t['og_description'] ?? '') ?>">
    <meta property="og:site_name" content="bitback.one">
    <link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
    <?= asset_css('assets/fonts.css', 'assets/tokens.css', 'assets/css/notfound.css', 'assets/css/footer.css') ?>
</head>
<body>
    <div class="box">
        <div class="ghost"><?= bb_icon('ghost') ?></div>
        <div class="code">404</div>
        <h1><?= htmlspecialchars($t['not_found_title']) ?></h1>
        <div class="sub"><?= htmlspecialchars($t['not_found_sub']) ?></div>
        <div class="hint"><?= htmlspecialchars($t['not_found_hint']) ?> <code>#</code></div>
        <a href="/" class="home-link"><?= htmlspecialchars($t['title']) ?> →</a>
        <?= site_footer_html(true) ?>
    </div>
</body>
</html>
