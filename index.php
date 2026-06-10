<?php
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/i18n.php';
require_once __DIR__ . '/inc/logo.php';
require_once __DIR__ . '/inc/antibot.php';
require_once __DIR__ . '/inc/icons.php';
$lang = detect_lang();
$t = get_strings($lang);
$challenge = antibot_challenge();
?>
<!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
    <title><?= htmlspecialchars($t['meta_title']) ?></title>
    <!-- Open Graph -->
    <meta property="og:type" content="website">
    <meta property="og:title" content="<?= htmlspecialchars($t['meta_title']) ?>">
    <meta property="og:description" content="<?= htmlspecialchars($t['og_description']) ?>">
    <meta property="og:url" content="https://bitback.one/">
    <meta property="og:site_name" content="bitback.one">
    <meta property="og:locale" content="<?= $lang === 'pl' ? 'pl_PL' : 'en_US' ?>">
    <meta property="og:locale:alternate" content="<?= $lang === 'pl' ? 'en_US' : 'pl_PL' ?>">
    <!-- Twitter Card -->
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="<?= htmlspecialchars($t['meta_title']) ?>">
    <meta name="twitter:description" content="<?= htmlspecialchars($t['og_description']) ?>">
    <link rel="stylesheet" href="/assets/fonts.css?v=<?= filemtime(__DIR__ . '/assets/fonts.css') ?>">
    <link rel="stylesheet" href="/assets/tokens.css?v=<?= filemtime(__DIR__ . '/assets/tokens.css') ?>">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: var(--bb-font-sans);
            background: var(--bb-bg);
            color: var(--bb-fg-1);
            min-height: 100vh;
            padding-bottom: 2.5rem;
        }

        .header {
            text-align: center;
            padding: 2rem 1rem 1.5rem;
        }
        .header h1 {
            font-size: 1.6rem;
            font-weight: 300;
            letter-spacing: 0.08em;
            color: var(--bb-fg);
        }
        .header p {
            color: var(--bb-fg);
            font-size: 0.9rem;
            font-weight: 500;
            letter-spacing: 0.02em;
            margin-top: 0.5rem;
        }

        /* ====== TRUST BAR ====== */
        .trust {
            max-width: 1100px;
            margin: 0 auto 1.5rem;
            padding: 0 1rem;
        }
        .trust-box {
            border-radius: 10px;
            padding: 1rem;
            /* background i border z bb-card-default */
        }
        .trust-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1rem;
        }
        @media (max-width: 768px) {
            .trust-grid { grid-template-columns: 1fr; }
        }
        .trust-item {
            padding: 0.4rem;
            border-radius: 6px;
            transition: background 220ms var(--bb-ease), transform 220ms var(--bb-ease);
        }
        .trust-item:hover {
            background: rgba(120,140,200,0.06);
            transform: translateY(-1px);
        }
        .trust-icon {
            font-size: 1.1rem;
            margin-bottom: 0.3rem;
        }
        .trust-title {
            font-size: 0.72rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #b8c5d8; /* cool tinted, dostrojony do aurora cool tla */
            margin-bottom: 0.25rem;
        }
        .trust-desc {
            font-size: 0.7rem;
            color: #8090a8; /* cool tinted, jasniejszy niz poprzednio */
            line-height: 1.5;
        }
        .trust-box .trust-icon [data-lucide] { color: #b8c5d8; }

        /* ====== HINT BAR ====== */
        .hint-bar {
            background: #0d0d10;
            border: 1px solid #1c1c22;
            border-radius: 8px;
            padding: 0.6rem 0.8rem;
            margin-bottom: 0.6rem;
            display: flex;
            align-items: center;
            gap: 0.6rem;
            font-size: 0.75rem;
            color: var(--bb-fg-4);
        }
        .hint-bar kbd {
            display: inline-block;
            padding: 0.15em 0.5em;
            background: #14141c;
            border: 1px solid #2a2a36;
            border-radius: 4px;
            font-family: var(--bb-font-mono);
            font-size: 0.8rem;
            color: #c8d0e8;
            white-space: nowrap;
        }
        .hint-bar .hint-text { color: var(--bb-fg-4); }
        .hint-bar .hint-text strong { color: #c8d0e8; font-weight: 500; }

        .main {
            max-width: 1100px;
            margin: 0 auto;
            padding: 0 1rem 3rem;
        }

        /* --- LAYOUT DWU-KOLUMNOWY --- */
        .two-col {
            display: grid;
            grid-template-columns: 1fr 300px;
            gap: 1.5rem;
            align-items: start;
        }
        @media (max-width: 768px) {
            .two-col { grid-template-columns: 1fr; }
        }

        .col-label {
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--bb-fg-5);
            margin-bottom: 0.6rem;
        }

        /* ====== LEWA KOLUMNA — EDYTOR ====== */
        .col-left { min-width: 0; }

        /* placeholder edytora */

        /* edytor contenteditable - czysty dark, akcent przez focus i secret highlight */
        .editor {
            width: 100%;
            min-height: 220px;
            padding: 0.8rem;
            background: #0d0d10;
            border: 1px solid #1c1c22;
            border-radius: 10px;
            color: var(--bb-fg-2);
            font-family: var(--bb-font-mono);
            font-size: 0.85rem;
            line-height: 1.7;
            outline: none;
            white-space: pre-wrap;
            word-break: break-word;
            cursor: text;
            transition: border-color 0.15s;
        }
        .editor:focus { border-color: var(--bb-accent); box-shadow: 0 0 0 3px rgba(58, 123, 213, 0.12); }
        .editor:empty::before {
            content: '<?= str_replace("'", "\\'", str_replace("\n", "\\A", $t['editor_placeholder'])) ?>';
            color: var(--bb-fg-7);
            pointer-events: none;
            white-space: pre-wrap;
        }

        /* oznaczone fragmenty poufne */
        .editor .secret {
            background: rgba(212, 146, 42, 0.15);
            color: var(--bb-secret);
            border-radius: 3px;
            padding: 0.05em 0.15em;
            border-bottom: 2px solid rgba(212, 146, 42, 0.4);
        }

        /* ====== PRAWA KOLUMNA — KONFIG ====== */
        .col-right {
            position: sticky;
            top: 1.5rem;
        }

        .config-panel {
            background: #0d0d10;
            border: 1px solid #1c1c22;
            border-radius: 10px;
            padding: 1rem;
            box-shadow: var(--bb-shadow-sm);
        }

        .config-group {
            margin-bottom: 1rem;
        }
        .config-group:last-child { margin-bottom: 0; }

        .config-group label {
            display: block;
            font-size: 0.68rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--bb-fg-5);
            margin-bottom: 0.3rem;
        }

        .config-row {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .config-input {
            width: 70px;
            padding: 0.4rem 0.5rem;
            background: var(--bb-bg);
            border: 1px solid var(--bb-border-mid);
            border-radius: 4px;
            color: var(--bb-fg);
            font-size: 0.85rem;
            text-align: center;
            outline: none;
        }
        .config-input:focus { border-color: var(--bb-accent); box-shadow: 0 0 0 3px rgba(58, 123, 213, 0.12); }

        .config-unit {
            font-size: 0.72rem;
            color: var(--bb-fg-6);
        }

        .config-sep {
            border: none;
            border-top: 1px solid var(--bb-border-soft);
            margin: 1rem 0;
        }

        /* antybot */
        .antibot-q {
            font-size: 0.82rem;
            color: var(--bb-fg-4);
            margin-bottom: 0.4rem;
        }
        .antibot-options {
            display: flex;
            gap: 0.5rem;
        }
        .antibot-opt {
            flex: 1;
            padding: 0.45rem;
            border-radius: 5px;
            border: 1px solid var(--bb-border-mid);
            background: var(--bb-bg);
            color: var(--bb-fg-4);
            font-size: 0.85rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.15s;
            user-select: none;
        }
        .antibot-opt:hover {
            border-color: var(--bb-fg-6);
            color: var(--bb-fg-body);
        }
        .antibot-opt.selected {
            border-color: var(--bb-accent);
            background: var(--bb-accent-tint);
            color: var(--bb-accent-light);
        }

        /* honeypot */
        .ohnohoney {
            position: absolute;
            left: -9999px;
            opacity: 0;
            height: 0;
            width: 0;
            pointer-events: none;
        }

        /* przycisk generuj - teal cyber gradient + magenta hairline leading edge */
        .generate-btn {
            position: relative;
            width: 100%;
            padding: 0.75rem;
            margin-top: 1rem;
            border-radius: 6px;
            border: 1px solid transparent;
            background: linear-gradient(135deg, #2a9080 0%, #1a6a5e 48%, #0a4038 100%);
            box-shadow:
              inset 0 0 0 1px rgba(255,255,255,0.08),
              inset 1px 0 0 rgba(160,120,220,0.45),
              inset 0 -1px 0 rgba(0,0,0,0.35);
            color: #d8f0ea;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 160ms var(--bb-ease), filter 160ms var(--bb-ease);
            letter-spacing: 0.02em;
            isolation: isolate;
        }
        .generate-btn::after {
            content: "";
            position: absolute;
            inset: -4px;
            border-radius: 10px;
            background: rgba(60,220,200,1);
            filter: blur(10px);
            opacity: 0;
            z-index: -1;
            transition: opacity 220ms var(--bb-ease);
        }
        .generate-btn:hover { transform: translateY(-1px); }
        .generate-btn:hover::after { opacity: 0.28; }
        .generate-btn:active { transform: translateY(0); filter: brightness(0.95); }
        .generate-btn:active::after { opacity: 0.15; }
        .generate-btn:disabled { opacity: 0.7; cursor: not-allowed; transform: none; }
        .generate-btn:disabled::after { opacity: 0; }
        .generate-btn .spinner {
            display: inline-block;
            width: 0.9em;
            height: 0.9em;
            border: 2px solid rgba(255,255,255,0.25);
            border-top-color: var(--bb-fg);
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
            vertical-align: -0.15em;
            margin-right: 0.5em;
        }
        @keyframes spin { to { transform: rotate(360deg); } }

        /* przycisk oznaczania poufnych - diagonal gold gradient z dark text */
        .mark-secret-btn {
            position: relative;
            display: inline-flex;
            align-items: center;
            gap: 0.5em;
            width: 270px;
            padding: 0.6rem 1rem;
            margin-top: 0.6rem;
            border-radius: 6px;
            border: 1px solid rgba(90,140,200,0.5);
            background: linear-gradient(135deg, #2a4a78 0%, #1e3860 48%, #15264a 100%);
            box-shadow:
              inset 0 0 0 1px rgba(200,220,255,0.12),
              inset 0 -8px 12px -8px rgba(0,0,20,0.5);
            color: #d8e5f5;
            font-size: 0.82rem;
            font-weight: 500;
            cursor: pointer;
            transition: transform 160ms var(--bb-ease), filter 160ms var(--bb-ease);
            letter-spacing: 0.02em;
            justify-content: center;
            isolation: isolate;
        }
        .mark-secret-btn::after {
            content: "";
            position: absolute;
            inset: -4px;
            border-radius: 10px;
            background: rgba(90,160,232,0.8);
            filter: blur(10px);
            opacity: 0;
            z-index: -1;
            transition: opacity 220ms var(--bb-ease);
        }
        .mark-secret-btn:hover { transform: translateY(-1px); }
        .mark-secret-btn:hover::after { opacity: 0.28; }
        .mark-secret-btn:active {
            transform: translateY(0);
            filter: brightness(0.95);
        }
        .mark-secret-btn [data-lucide] { width: 18px; height: 18px; stroke-width: 2; }

        /* ====== PODGLĄD WYGAŚNIĘCIA ====== */
        .preview-section {
            margin-top: 1.5rem;
        }
        .preview-bar {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }
        .preview-bar .col-label { margin-bottom: 0; }
        .preview-tabs {
            display: flex;
            gap: 0.3rem;
        }
        .preview-tab {
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            border: 1px solid var(--bb-border);
            background: transparent;
            color: var(--bb-fg-6);
            font-size: 0.65rem;
            cursor: pointer;
            transition: all 0.15s;
        }
        .preview-tab.active {
            border-color: var(--bb-fg-7);
            color: var(--bb-fg-tab);
            background: var(--bb-surface-2);
        }
        .preview-box {
            background: #0d0d10;
            border: 1px solid #1c1c22;
            border-radius: 10px;
            padding: 0.8rem;
            font-family: var(--bb-font-mono);
            font-size: 0.85rem;
            line-height: 1.7;
            white-space: pre-wrap;
            word-break: break-word;
            min-height: 60px;
            box-shadow: var(--bb-shadow-sm);
        }
        .preview-box .masked {
            background: rgba(100, 100, 100, 0.2);
            color: var(--bb-fg-5);
            border-radius: 3px;
            padding: 0.05em 0.15em;
            letter-spacing: 0.1em;
        }
        .preview-box .secret {
            background: rgba(212, 146, 42, 0.15);
            color: var(--bb-secret);
            border-radius: 3px;
            padding: 0.05em 0.15em;
            border-bottom: 2px solid rgba(212, 146, 42, 0.4);
        }
        .preview-empty {
            color: var(--bb-fg-6);
            font-style: italic;
            font-size: 0.78rem;
        }

        /* ====== WYNIK ====== */
        .result {
            margin-top: 1.5rem;
            display: none;
        }
        .result.show {
            display: block;
            animation: result-reveal 480ms cubic-bezier(0.16, 1, 0.3, 1) both;
        }
        .result.show .result-box {
            animation: result-pulse 1800ms ease-out 200ms both;
        }
        @keyframes result-reveal {
            from { opacity: 0; transform: translateY(10px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes result-pulse {
            0%, 100% { box-shadow: 0 0 0 0 rgba(125,215,125,0); }
            30%      { box-shadow: 0 0 0 8px rgba(125,215,125,0.18); }
            70%      { box-shadow: 0 0 0 4px rgba(125,215,125,0.06); }
        }
        @media (prefers-reduced-motion: reduce) {
            .result.show, .result.show .result-box { animation: none; }
        }

        .result-box {
            border-radius: 10px;
            padding: 0.8rem 1rem;
            /* background i border z bb-card-success */
        }
        .result-label {
            font-size: 0.68rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--bb-success-ink);
            margin-bottom: 0.4rem;
        }
        .result-link {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .result-url {
            flex: 1;
            padding: 0.45rem 0.6rem;
            background: var(--bb-surface-sunk);
            border: 1px solid var(--bb-border-mid);
            border-radius: 4px;
            color: var(--bb-success);
            font-family: var(--bb-font-mono);
            font-size: 0.8rem;
            outline: none;
        }
        .copy-btn {
            position: relative;
            padding: 0.45rem 0.9rem;
            border-radius: 6px;
            border: 1px solid transparent;
            background: linear-gradient(135deg, #2a5a2a 0%, #1a3a1a 50%, #0e2210 100%);
            box-shadow:
              inset 0 0 0 1px rgba(160,230,160,0.2),
              inset 1px 0 0 rgba(160,230,160,0.4),
              inset 0 -1px 0 rgba(0,0,0,0.3);
            color: #d0f0c8;
            font-size: 0.75rem;
            font-weight: 500;
            cursor: pointer;
            transition: transform 160ms var(--bb-ease), filter 160ms var(--bb-ease);
            white-space: nowrap;
            isolation: isolate;
        }
        .copy-btn::after {
            content: ""; position: absolute; inset: -4px; border-radius: 10px;
            background: #4aa04a; filter: blur(10px); opacity: 0; z-index: -1;
            transition: opacity 220ms var(--bb-ease);
        }
        .copy-btn:hover { transform: translateY(-1px); }
        .copy-btn:hover::after { opacity: 0.28; }
        .copy-btn:active { transform: translateY(0); filter: brightness(0.95); }

        .result-password {
            margin-top: 0.6rem;
            padding: 0.5rem 0.7rem;
            background: var(--bb-success-bg-2);
            border: 1px solid var(--bb-success-border);
            border-radius: 4px;
            font-size: 0.78rem;
            color: var(--bb-success-mid);
            display: none;
        }
        .result-password.show { display: block; }
        .result-password strong {
            color: var(--bb-success-light);
            font-family: var(--bb-font-mono);
            font-weight: 500;
        }

    </style>
</head>
<body class="bb-landing">

<div class="header bb-rise-1">
    <?= render_logo('bitback.one', 'https://bitback.one') ?>
    <p><?= htmlspecialchars($t['subtitle']) ?></p>
</div>

<div class="trust bb-rise-2">
    <div class="trust-box bb-card bb-hero-cool bb-art bb-art-aurora">
        <div class="trust-grid">
            <div class="trust-item">
                <div class="trust-icon"><?= bb_icon('lock') ?></div>
                <div class="trust-title"><?= htmlspecialchars($t['trust1_title']) ?></div>
                <div class="trust-desc"><?= htmlspecialchars($t['trust1_desc']) ?></div>
            </div>
            <div class="trust-item">
                <div class="trust-icon"><?= bb_icon('clock') ?></div>
                <div class="trust-title"><?= htmlspecialchars($t['trust2_title']) ?></div>
                <div class="trust-desc"><?= htmlspecialchars($t['trust2_desc']) ?></div>
            </div>
            <div class="trust-item">
                <div class="trust-icon"><?= bb_icon('monitor') ?></div>
                <div class="trust-title"><?= htmlspecialchars($t['trust3_title']) ?></div>
                <div class="trust-desc"><?= htmlspecialchars($t['trust3_desc']) ?></div>
            </div>
        </div>
    </div>
</div>

<div class="main bb-rise-3">
    <form id="createForm" autocomplete="off" onsubmit="return false;">
        <input type="text" name="website_url" class="ohnohoney" tabindex="-1" autocomplete="off">

        <div class="two-col">
            <!-- LEWA — edytor -->
            <div class="col-left">
                <div class="col-label"><?= htmlspecialchars($t['content_label']) ?></div>
                <div class="hint-bar">
                    <kbd>Ctrl+E</kbd>
                    <span class="hint-text"><?= $t['hint_text'] ?></span>
                </div>
                <div class="editor" id="editor" contenteditable="true" spellcheck="false" role="textbox" aria-multiline="true" aria-label="<?= htmlspecialchars($t['content_label']) ?>"></div>
                <button type="button" class="mark-secret-btn" onmousedown="event.preventDefault()" onclick="toggleSecret()"><?= bb_icon('lock') ?> <?= htmlspecialchars($t['mark_secret_btn']) ?></button>

                <!-- podgląd pod edytorem -->
                <div class="preview-section">
                    <div class="preview-bar">
                        <div class="col-label"><?= htmlspecialchars($t['preview_label']) ?></div>
                        <div class="preview-tabs">
                            <button type="button" class="preview-tab active" onclick="setPreview('expired', this)"><?= htmlspecialchars($t['preview_expired']) ?></button>
                            <button type="button" class="preview-tab" onclick="setPreview('active', this)"><?= htmlspecialchars($t['preview_active']) ?></button>
                        </div>
                    </div>
                    <div class="preview-box" id="preview"></div>
                </div>
            </div>

            <!-- PRAWA — konfiguracja -->
            <div class="col-right">
                <div class="col-label"><?= htmlspecialchars($t['settings_label']) ?></div>
                <div class="config-panel">
                    <div class="config-group">
                        <label><?= htmlspecialchars($t['expire_label']) ?></label>
                        <div class="config-row">
                            <input type="number" class="config-input" id="expireDays" value="<?= DEFAULT_EXPIRE_DAYS ?>" min="1" max="3650">
                            <span class="config-unit"><?= htmlspecialchars($t['expire_unit']) ?></span>
                        </div>
                    </div>

                    <div class="config-group">
                        <label><?= htmlspecialchars($t['views_label']) ?></label>
                        <div class="config-row">
                            <input type="number" class="config-input" id="maxViews" value="<?= DEFAULT_MAX_VIEWS ?>" min="1" max="10000">
                            <span class="config-unit"><?= htmlspecialchars($t['views_unit']) ?></span>
                        </div>
                    </div>

                    <div class="config-group">
                        <label><?= htmlspecialchars($t['delete_label']) ?></label>
                        <div class="config-row">
                            <input type="number" class="config-input" id="deleteDays" value="<?= DEFAULT_DELETE_DAYS ?>" min="0" max="3650">
                            <span class="config-unit"><?= htmlspecialchars($t['delete_unit']) ?></span>
                        </div>
                    </div>

                    <div class="config-group">
                        <label><?= htmlspecialchars($t['password_label']) ?></label>
                        <div class="config-row">
                            <input type="text" class="config-input" id="linkPassword" style="width:100%;text-align:left;" placeholder="<?= htmlspecialchars($t['password_placeholder_config']) ?>" autocomplete="off">
                        </div>
                    </div>

                    <hr class="config-sep">

                    <div class="config-group">
                        <label><?= htmlspecialchars($t['verify_label']) ?></label>
                        <div class="antibot-q" id="mathQuestion" aria-live="polite"></div>
                        <div class="antibot-options" id="mathOptions" role="group" aria-label="<?= htmlspecialchars($t['verify_label']) ?>"></div>
                    </div>

                    <button type="button" class="generate-btn" onclick="generateLink()"><?= htmlspecialchars($t['generate_btn']) ?></button>
                </div>
            </div>
        </div>
    </form>

    <div class="result" id="result">
        <div class="result-box bb-card bb-card-success bb-art bb-art-green">
            <div class="result-label"><?= htmlspecialchars($t['your_link']) ?></div>
            <div class="result-link">
                <input type="text" class="result-url" id="resultUrl" readonly>
                <button type="button" class="copy-btn" onclick="copyLink()"><?= htmlspecialchars($t['copy']) ?></button>
            </div>
            <div class="result-password" id="resultPassword"></div>
        </div>
    </div>

</div>

<div style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:var(--bb-bg);border-top:1px solid var(--bb-border-soft);padding:0.5rem 1rem;text-align:center;font-size:0.75rem;color:var(--bb-fg-5);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
    <a href="https://bitback.pl" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;"><strong>bitback.pl</strong></a>
    <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><?= htmlspecialchars($t['footer_tagline']) ?>
    <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span>Zbigniew Gralewski
    <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><a href="mailto:zbigniew.gralewski@bitback.pl" style="color:var(--bb-accent-link);text-decoration:none;">zbigniew.gralewski@bitback.pl</a>
    <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span>609 505 065
    <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><?= htmlspecialchars($t['footer_source']) ?> <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;">GitHub</a>
</div>

<script src="/crypto.js" integrity="sha384-lbGxH8AFxpkiMqDgkudynUSMoMFVnfMkcjN4XwCJHaTu9mLjvW4emijB7r3kh7MU"></script>
<script>
    const T = {
        error_empty: <?= json_encode($t['error_empty']) ?>,
        error_math_select: <?= json_encode($t['error_math_select']) ?>,
        error_ratelimit: <?= json_encode($t['error_ratelimit']) ?>,
        error_math: <?= json_encode($t['error_math']) ?>,
        error_server: <?= json_encode($t['error_server']) ?>,
        error_connection: <?= json_encode($t['error_connection']) ?>,
        your_password: <?= json_encode($t['your_password']) ?>,
        copied: <?= json_encode($t['copied']) ?>,
        copy: <?= json_encode($t['copy']) ?>,
        generate_btn: <?= json_encode($t['generate_btn']) ?>,
        generating: <?= json_encode($t['generating']) ?>,
        preview_empty: <?= json_encode($t['preview_empty']) ?>
    };
    const editor = document.getElementById('editor');
    let previewMode = 'expired';

    // --- MATH ANTYBOT ---
    // Challenge generowany serwerowo i podpisany HMAC - klient nie zna logiki
    // weryfikacji. Po wygenerowaniu linka pobieramy swiezy z /api/challenge.php.
    let CH = <?= json_encode($challenge) ?>;
    let selectedAnswer = null;

    function generateMath() {
        selectedAnswer = null;
        const correct = CH.a + CH.b;
        // 2 falszywe odpowiedzi to tylko UI (serwer i tak liczy sam)
        const fakes = new Set();
        while (fakes.size < 2) {
            const f = correct + (Math.floor(Math.random() * 7) - 3); // ±3
            if (f !== correct && f > 0) fakes.add(f);
        }

        const options = [correct, ...fakes];
        for (let i = options.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [options[i], options[j]] = [options[j], options[i]];
        }

        document.getElementById('mathQuestion').textContent = `${CH.a} + ${CH.b} = ?`;
        const container = document.getElementById('mathOptions');
        container.innerHTML = '';
        options.forEach(val => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'antibot-opt';
            btn.textContent = val;
            btn.addEventListener('click', () => {
                container.querySelectorAll('.antibot-opt').forEach(b => b.classList.remove('selected'));
                btn.classList.add('selected');
                selectedAnswer = val;
            });
            container.appendChild(btn);
        });
    }
    generateMath();

    async function refreshChallenge() {
        try {
            const r = await fetch('/api/challenge.php');
            CH = await r.json();
        } catch (e) { /* zostaje stary - token wazny 15 min */ }
        generateMath();
    }

    // --- TOGGLE SECRET (oznacz / odznacz) ---
    function unwrapSecret(secretEl, sel) {
        const marker = document.createElement('span');
        marker.setAttribute('data-cursor', '1');
        secretEl.parentNode.insertBefore(marker, secretEl.nextSibling);

        const parent = secretEl.parentNode;
        while (secretEl.firstChild) {
            parent.insertBefore(secretEl.firstChild, secretEl);
        }
        parent.removeChild(secretEl);
        parent.normalize();

        const r = document.createRange();
        r.setStartBefore(marker);
        r.collapse(true);
        marker.remove();
        sel.removeAllRanges();
        sel.addRange(r);
        editor.focus();
        updatePreview();
    }

    function toggleSecret() {
        const sel = window.getSelection();
        if (!sel.rangeCount) return;

        // sprawdź czy kursor/zaznaczenie jest wewnątrz .secret
        const anchorParent = sel.anchorNode.nodeType === 3 ? sel.anchorNode.parentElement : sel.anchorNode;
        const secretEl = anchorParent ? anchorParent.closest('.secret') : null;

        if (secretEl && editor.contains(secretEl)) {
            unwrapSecret(secretEl, sel);
            return;
        }

        // sprawdź czy zaznaczenie obejmuje lub dotyka .secret (odznacz)
        if (!sel.isCollapsed) {
            const range = sel.getRangeAt(0);
            if (!editor.contains(range.commonAncestorContainer)) return;

            const startParent = range.startContainer.nodeType === 3 ? range.startContainer.parentElement : range.startContainer;
            const endParent = range.endContainer.nodeType === 3 ? range.endContainer.parentElement : range.endContainer;
            const startSecret = startParent ? startParent.closest('.secret') : null;
            const endSecret = endParent ? endParent.closest('.secret') : null;

            // cały zaznaczony tekst jest wewnątrz jednego .secret
            if (startSecret && startSecret === endSecret && editor.contains(startSecret)) {
                unwrapSecret(startSecret, sel);
                return;
            }

            // zaznaczenie obejmuje .secret elementy - odznacz je
            const fragment = range.cloneContents();
            if (fragment.querySelector('.secret')) {
                // znajdź .secret elementy w faktycznym DOM (nie w klonie)
                const container = range.commonAncestorContainer;
                const searchRoot = container.nodeType === 3 ? container.parentElement : container;
                const secrets = searchRoot.querySelectorAll('.secret');
                const toUnwrap = [];
                for (const s of secrets) {
                    if (range.intersectsNode(s)) toUnwrap.push(s);
                }
                if (toUnwrap.length > 0) {
                    toUnwrap.forEach(s => {
                        const parent = s.parentNode;
                        while (s.firstChild) parent.insertBefore(s.firstChild, s);
                        parent.removeChild(s);
                    });
                    editor.normalize();
                    editor.focus();
                    updatePreview();
                    return;
                }
            }

            // blokuj zagnieżdżanie
            if (startSecret) return;
            if (endSecret) return;
        }

        // --- OZNACZ ---
        if (sel.isCollapsed) return; // nic nie zaznaczono
        const range = sel.getRangeAt(0);
        if (!editor.contains(range.commonAncestorContainer)) return;

        const mark = document.createElement('span');
        mark.className = 'secret';

        try {
            range.surroundContents(mark);
        } catch(e) {
            // surroundContents nie działa gdy zaznaczenie przecina granicę elementu
            // (np. obejmuje <br> lub <div>) - użyj extractContents + appendChild
            try {
                const contents = range.extractContents();
                mark.appendChild(contents);
                range.insertNode(mark);
            } catch(e2) {
                return;
            }
        }

        // postaw kursor za nowym spanem
        const r = document.createRange();
        r.setStartAfter(mark);
        r.collapse(true);
        sel.removeAllRanges();
        sel.addRange(r);
        editor.focus();
        updatePreview();
    }

    function markSecret() { toggleSecret(); }
    function clearSecret() { toggleSecret(); }

    // --- SKRÓT Ctrl+E ---
    editor.addEventListener('keydown', function(e) {
        if (e.ctrlKey && e.key === 'e') {
            e.preventDefault();
            toggleSecret();
        }
    });

    // --- PODGLĄD ---
    function updatePreview() {
        const previewBox = document.getElementById('preview');
        const html = editor.innerHTML;
        const isEmpty = editor.textContent.trim().length === 0;

        if (isEmpty) {
            previewBox.innerHTML = '<span class="preview-empty">' + (T.preview_empty || '') + '</span>';
            return;
        }

        if (previewMode === 'expired') {
            // DOM-based replacement - safe for any content inside .secret
            const clone = editor.cloneNode(true);
            clone.querySelectorAll('.secret').forEach(el => {
                const masked = document.createElement('span');
                masked.className = 'masked';
                masked.textContent = '●●●●●●';
                el.replaceWith(masked);
            });
            previewBox.innerHTML = clone.innerHTML;
        } else {
            previewBox.innerHTML = html;
        }
    }

    function setPreview(mode, btn) {
        previewMode = mode;
        document.querySelectorAll('.preview-tab').forEach(t => t.classList.remove('active'));
        btn.classList.add('active');
        updatePreview();
    }

    editor.addEventListener('input', updatePreview);

    // --- EKSTRAKCJA DANYCH Z EDYTORA ---
    function extractSections() {
        const sections = [];

        function getTextWithBreaks(el) {
            let text = '';
            el.childNodes.forEach(child => {
                if (child.nodeType === 3) {
                    text += child.textContent;
                } else if (child.nodeType === 1) {
                    if (child.tagName === 'BR') {
                        text += '\n';
                    } else if (child.tagName === 'DIV') {
                        text += '\n';
                        text += getTextWithBreaks(child);
                    } else {
                        text += getTextWithBreaks(child);
                    }
                }
            });
            return text;
        }

        function parseNode(node) {
            if (node.nodeType === 3) {
                sections.push({ type: 'text', content: node.textContent });
            } else if (node.nodeType === 1) {
                if (node.classList && node.classList.contains('secret')) {
                    sections.push({ type: 'secret', content: getTextWithBreaks(node) });
                } else if (node.tagName === 'BR') {
                    sections.push({ type: 'text', content: '\n' });
                } else if (node.tagName === 'DIV') {
                    sections.push({ type: 'text', content: '\n' });
                    node.childNodes.forEach(child => parseNode(child));
                } else {
                    node.childNodes.forEach(child => parseNode(child));
                }
            }
        }

        editor.childNodes.forEach(node => parseNode(node));

        // scal sąsiednie tego samego typu
        const merged = [];
        sections.forEach(s => {
            const last = merged[merged.length - 1];
            if (last && last.type === s.type) {
                last.content += s.content;
            } else {
                merged.push({ ...s });
            }
        });

        return merged.filter(s => s.content.length > 0);
    }

    // --- GENERUJ LINK ---
    async function generateLink() {
        // honeypot
        const honeypot = document.querySelector('.ohnohoney').value;

        // treść
        const text = editor.textContent.trim();
        if (!text) {
            alert(T.error_empty);
            return;
        }

        // math — sprawdź czy wybrano odpowiedź
        if (selectedAnswer === null) {
            alert(T.error_math_select);
            return;
        }

        const sections = extractSections();

        // --- CLIENT-SIDE ENCRYPTION ---
        const hexKey = generateHexKey();

        // Rozdziel na text + secrets (z zachowaniem idx)
        const textSections = [];
        const secretSections = [];
        sections.forEach((s, idx) => {
            const entry = { idx: idx, content: s.content };
            if (s.type === 'secret') {
                secretSections.push(entry);
            } else {
                textSections.push(entry);
            }
        });

        const btn = document.querySelector('.generate-btn');
        const btnOriginalHTML = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span>' + (T.generating || 'Szyfrowanie...');

        try {
            // Szyfruj w przeglądarce
            const encryptedText = await encryptBlob(textSections, hexKey);
            const encryptedSecrets = secretSections.length > 0
                ? await encryptBlob(secretSections, hexKey)
                : null;

            // timeout - zawieszone polaczenie nie zostawia spinnera na zawsze
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), 15000);
            let resp;
            try {
                resp = await fetch('/api/create.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    signal: ctrl.signal,
                    body: JSON.stringify({
                        website_url: honeypot,
                        encrypted_text: encryptedText,
                        encrypted_secrets: encryptedSecrets,
                        total_sections: sections.length,
                        expire_days: parseInt(document.getElementById('expireDays').value) || <?= DEFAULT_EXPIRE_DAYS ?>,
                        max_views: parseInt(document.getElementById('maxViews').value) || <?= DEFAULT_MAX_VIEWS ?>,
                        delete_after_days: parseInt(document.getElementById('deleteDays').value) || <?= DEFAULT_DELETE_DAYS ?>,
                        password: document.getElementById('linkPassword').value.trim() || '',
                        math_a: CH.a,
                        math_b: CH.b,
                        math_exp: CH.exp,
                        math_token: CH.token,
                        math_answer: selectedAnswer,
                    }),
                });
            } finally {
                clearTimeout(timer);
            }

            const result = await resp.json();

            if (result.ok) {
                // Serwer zwraca URL bez klucza — klucz dodajemy po stronie klienta
                document.getElementById('resultUrl').value = result.url + '#' + hexKey;
                document.getElementById('result').classList.add('show');
                // pokaż hasło jeśli było ustawione
                const pwdEl = document.getElementById('resultPassword');
                const pwd = document.getElementById('linkPassword').value.trim();
                if (pwd) {
                    pwdEl.innerHTML = T.your_password + ' <strong>' + pwd.replace(/</g, '&lt;') + '</strong>';
                    pwdEl.classList.add('show');
                } else {
                    pwdEl.classList.remove('show');
                    pwdEl.innerHTML = '';
                }
                refreshChallenge();
            } else if (result.error === 'ratelimit') {
                alert(T.error_ratelimit);
            } else if (result.error === 'math') {
                alert(T.error_math);
                refreshChallenge();
            } else {
                alert(result.error || T.error_server);
            }
        } catch (e) {
            alert(T.error_connection);
        } finally {
            btn.disabled = false;
            btn.innerHTML = btnOriginalHTML;
        }
    }

    function copyLink() {
        const input = document.getElementById('resultUrl');
        input.select();
        input.setSelectionRange(0, input.value.length); // mobile Safari

        const showCopied = () => {
            const btn = document.querySelector('.copy-btn');
            const original = btn.innerHTML;
            btn.innerHTML = '<svg data-lucide="check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:1em;height:1em;vertical-align:-0.15em;margin-right:0.3em;" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>' + T.copied;
            btn.classList.add('copied');
            setTimeout(() => {
                btn.innerHTML = original;
                btn.classList.remove('copied');
            }, 1800);
        };

        // navigator.clipboard wymaga secure context (HTTPS) i uprawnien -
        // fallback do execCommand, a gdy i to padnie, tekst i tak jest zaznaczony.
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(input.value).then(showCopied).catch(() => {
                try { document.execCommand('copy'); showCopied(); } catch (e) {}
            });
        } else {
            try { document.execCommand('copy'); showCopied(); } catch (e) {}
        }
    }

    // init
    updatePreview();
</script>

</body>
</html>
