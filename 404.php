<?php
/**
 * Custom 404 — friendly ghost for lost visitors
 */

require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/i18n.php';

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
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/tokens.css?v=<?= filemtime(__DIR__ . '/assets/tokens.css') ?>">
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
    <div class="box">
        <div class="ghost"><i data-lucide="ghost"></i></div>
        <div class="code">404</div>
        <h1><?= htmlspecialchars($t['not_found_title']) ?></h1>
        <div class="sub"><?= htmlspecialchars($t['not_found_sub']) ?></div>
        <div class="hint"><?= htmlspecialchars($t['not_found_hint']) ?> <code>#</code></div>
        <a href="/" class="home-link"><?= htmlspecialchars($t['title']) ?> →</a>
        <div style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:var(--bb-bg);border-top:1px solid var(--bb-border-soft);padding:0.5rem 1rem;text-align:center;font-size:0.75rem;color:var(--bb-fg-5);white-space:nowrap;">
            <a href="https://bitback.pl" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;"><strong>bitback.pl</strong></a>
            <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span>Kod źródłowy na <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;">GitHub</a>
        </div>
    </div>
<script src="https://unpkg.com/lucide@latest"></script>
<script>lucide.createIcons();</script>
</body>
</html>
