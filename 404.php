<?php
/**
 * Custom 404 — friendly ghost for lost visitors
 */

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/i18n.php';
require_once __DIR__ . '/inc/icons.php';
require_once __DIR__ . '/inc/assets.php';

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
    <?= asset_css('assets/fonts.css', 'assets/tokens.css', 'assets/css/notfound.css') ?>
</head>
<body>
    <div class="box">
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
</html>
