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

        /* logo do lewej (z wcieciem), podtytul do prawej - jedna linia
           wypelnia szerokosc, tresc apki wedruje w gore */
        .header {
            max-width: 1100px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            justify-content: space-between;
            gap: 0.4rem 1.6rem;
            padding: 1.3rem 2.4rem 1rem;
        }
        .header .bb-logo svg { width: 214px; height: auto; }
        .header h1 {
            font-size: 1.6rem;
            font-weight: 300;
            letter-spacing: 0.08em;
            color: var(--bb-fg);
        }
        .header p {
            color: var(--bb-teal);
            font-size: 1rem; /* twarda regula: nie mniejsze niz obecne */
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.24em;
        }

        /* ====== TRUST BAR ====== */
        .trust {
            max-width: 1100px;
            margin: 0 auto 1.5rem;
            padding: 0 1rem;
        }
        /* trust bar (m01): neon ramka + ciemne wnetrze, corner streaks
           przez bb-art (aurora prawy rog) i bb-art-left (magenta lewy).
           Stonowane: na ciemnym tle screen blend mocno pcha jasnosc,
           a tekst musi zostac czytelny (mockup: akcenty przy krawedziach). */
        .trust-box {
            padding: 1rem;
            background: var(--bb-surface-sunk);
            border: 1px solid var(--bb-neon-border);
            box-shadow: var(--bb-neon-glow);
        }
        /* smugi od GORNEJ krawedzi: pionowe lustro kanonicznej bitmapy
           (maska flipuje sie razem z transformem) */
        .trust-box.bb-art::after {
            width: 36%;
            opacity: 0.45;
            transform: scaleY(-1);
            -webkit-mask-image: radial-gradient(120% 130% at 100% 100%, #000 18%, transparent 58%);
            mask-image: radial-gradient(120% 130% at 100% 100%, #000 18%, transparent 58%);
        }
        .trust-box.bb-art-left::before {
            width: 24%;
            opacity: 0.32;
            transform: scale(-1, -1);
            -webkit-mask-image: radial-gradient(120% 130% at 100% 100%, #000 18%, transparent 58%);
            mask-image: radial-gradient(120% 130% at 100% 100%, #000 18%, transparent 58%);
        }
        .trust-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1rem;
        }
        @media (max-width: 768px) {
            .trust-grid { grid-template-columns: 1fr; }
        }
        /* item trust bara (m01): chip inline po lewej tytulu,
           opis pod spodem na calej szerokosci */
        .trust-item {
            display: grid;
            grid-template-columns: auto 1fr;
            column-gap: 0.65rem;
            row-gap: 0.45rem;
            align-items: center;
            padding: 0.4rem;
        }
        .trust-item .trust-desc { grid-column: 1 / -1; }
        .trust-title {
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--bb-fg);
        }
        .trust-desc {
            font-size: 0.8rem;
            color: var(--bb-fg-3);
            line-height: 1.55;
        }

        /* ====== HINT BAR - bez wlasnego boxa, siedzi w neonowej ramce ====== */
        .hint-bar {
            padding: 0.1rem 0 0.7rem;
            display: flex;
            align-items: center;
            gap: 0.6rem;
            font-size: 0.85rem;
            color: var(--bb-fg-3);
        }
        /* chip Ctrl+E (m01): neonowy teal box ze scietymi rogami.
           Zewnetrzny kbd = teal "ramka" przycieta clip-pathem, wewnetrzny
           span = ciemne wnetrze przyciete tym samym wielokatem (1px mniej)
           - ramka widoczna takze na diagonalach. drop-shadow podaza za
           clip-path (box-shadow by nie podazal). */
        .hint-bar kbd {
            display: inline-block;
            padding: 1px;
            background: rgba(37, 194, 168, 0.65);
            clip-path: polygon(9px 0, 100% 0, 100% calc(100% - 9px), calc(100% - 9px) 100%, 0 100%, 0 9px);
            filter: drop-shadow(0 0 5px rgba(37, 194, 168, 0.35));
            white-space: nowrap;
        }
        .hint-bar kbd span {
            display: block;
            padding: 0.35em 0.8em;
            background: #0b1612;
            clip-path: polygon(9px 0, 100% 0, 100% calc(100% - 9px), calc(100% - 9px) 100%, 0 100%, 0 9px);
            font-family: var(--bb-font-mono);
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--bb-teal);
        }
        .hint-bar .hint-text { color: var(--bb-fg-3); }
        .hint-bar .hint-text strong { color: var(--bb-fg); font-weight: 600; }
        /* inline akcenty hinta (m01): skrot teal mono, "poufny" gold */
        .hint-bar .hint-text strong:first-of-type {
            color: var(--bb-teal);
            font-family: var(--bb-font-mono);
            font-weight: 500;
        }
        .hint-bar .hint-text strong:last-of-type { color: var(--bb-secret); }

        .main {
            max-width: 1100px;
            margin: 0 auto;
            padding: 0 1rem 3rem;
        }

        /* --- LAYOUT DWU-KOLUMNOWY --- */
        .two-col {
            display: grid;
            grid-template-columns: 1fr 340px; /* proporcja kolumn jak w mockupie m01 */
            gap: 1.5rem;
            align-items: stretch;
        }
        @media (max-width: 768px) {
            .two-col { grid-template-columns: 1fr; }
        }

        .col-label {
            display: flex;
            align-items: center;
            gap: 0.9em;
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.22em;
            color: var(--bb-fg-2);
            margin-bottom: 0.45rem;
        }
        /* m01: gradientowa linia za etykieta sekcji, konczy sie zagieciem
           45deg w dol (clip-path: pozioma belka 2px + diagonalny hak) */
        .col-label::after {
            content: '';
            flex: 1;
            height: 9px;
            background: linear-gradient(90deg, rgba(37, 194, 168, 0.45), rgba(155, 124, 232, 0.85));
            clip-path: polygon(0 0, calc(100% - 9px) 0, 100% 9px, calc(100% - 2px) 9px, calc(100% - 9px) 2px, 0 2px);
        }
        .preview-bar .col-label::after { content: none; }

        /* wnetrze neonowej ramki sekcji (bb-frame w tokens.css) */
        .frame-pad { padding: 0.85rem; }

        /* ====== LEWA KOLUMNA — EDYTOR ====== */
        .col-left { min-width: 0; }

        /* placeholder edytora */

        /* edytor contenteditable - flat sunken, akcent przez focus i secret highlight.
           Gutter z numerami linii (mockup m01): absolutny pas po lewej, JS liczy
           linie WIZUALNE (wysokosc tresci / line-height) - numeracja nigdy sie
           nie rozjezdza, takze przy zawinietych dlugich liniach. */
        .editor-wrap {
            position: relative;
        }
        .editor-gutter {
            position: absolute;
            top: 1px; left: 1px; bottom: 1px;
            width: 2.5rem;
            padding: 0.85rem 0.55rem 0.85rem 0;
            background: var(--bb-bg);
            border-right: 1px solid rgba(37, 194, 168, 0.25);
            font-family: var(--bb-font-mono);
            font-size: 0.95rem;
            line-height: 1.7;
            color: rgba(37, 194, 168, 0.70);
            text-align: right;
            white-space: pre-line;
            user-select: none;
            pointer-events: none;
            overflow: hidden;
        }
        .editor {
            width: 100%;
            min-height: 220px;
            padding: 0.85rem 0.85rem 0.85rem 3.3rem;
            background: var(--bb-surface-sunk);
            border: 1px solid var(--bb-neon-border);
            box-shadow: 0 0 10px rgba(37, 194, 168, 0.07);
            color: var(--bb-fg-2);
            font-family: var(--bb-font-mono);
            font-size: 0.95rem;
            line-height: 1.7;
            outline: none;
            white-space: pre-wrap;
            word-break: break-word;
            cursor: text;
            transition: border-color 0.15s;
        }
        .editor:focus { border-color: var(--bb-teal); box-shadow: 0 0 12px rgba(37, 194, 168, 0.20); }
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

        /* tabela zaimportowana z Excela (tryb bulk) */
        /* bulk: gutter ukryty - male, symetryczne wciecie tabeli od krawedzi edytora */
        .editor.editor-bulk { padding: 0.3rem; }
        .bb-import-table { width:100%; table-layout:auto; border-collapse:collapse; margin:0.3rem 0; font-family:var(--bb-font-mono); font-size:0.9rem; }
        .bb-import-table td, .bb-import-table th { border:1px solid var(--bb-success); padding:0.3rem 0.5rem; color:var(--bb-fg-2); vertical-align:top; }
        .bb-import-table tr:first-child td, .bb-import-table th { color:var(--bb-success); font-weight:700; }
        .bb-import-note { margin:0.4rem 0; font-size:0.8rem; color:var(--bb-success); }
        .bb-import-note .warn { color:var(--bb-secret); }
        .plain-text-toggle { display:inline-flex; align-items:center; gap:0.4rem; font-size:0.8rem; color:var(--bb-fg-3); cursor:pointer; margin-left:0.75rem; }
        .plain-text-toggle input { cursor:pointer; }
        .bulk-preview-note { font-size:0.78rem; color:var(--bb-fg-5); margin-bottom:0.6rem; }

        /* lista wynikow bulk (osobny kontener od #result) - JEDNA duza tabela:
           kolumny wartosci wyrownuja sie same wg tresci (nie plywaja per rekord),
           wiersz linku zmergeowany (colspan), puste wiersze-odstepy miedzy rekordami */
        .bulk-results { margin-top:1rem; }
        .bulk-note { font-size:0.78rem; color:var(--bb-secret); margin-bottom:0.6rem; }
        .bulk-results-table { width:100%; table-layout:auto; border-collapse:collapse; font-size:0.8rem; }
        .bulk-results-table td { border:1px solid var(--bb-border); }
        .bulk-values-row td { padding:0.4rem 0.6rem; color:var(--bb-fg-3); }
        .bulk-link-row td { padding:0; border-top:none; }
        .bulk-link-cell { display:flex; align-items:stretch; }
        .bulk-link-cell input { flex:1; font-family:var(--bb-font-mono); font-size:0.8rem; background:var(--bb-surface-sunk); color:var(--bb-fg-2); border:none; padding:0.4rem 0.6rem; }
        .bulk-link-cell button { background:var(--bb-accent); color:#fff; border:none; padding:0 1rem; font-weight:700; cursor:pointer; }
        .bulk-spacer-row td { border:none; height:1.25rem; }

        /* ====== PRAWA KOLUMNA — KONFIG ====== */
        .col-right {
            position: sticky;
            top: 1.5rem;
            display: flex;
            flex-direction: column;
        }

        .config-panel {
            padding: 1rem;
            flex: 1 1 auto;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        /* wiersz ustawien (m01): uppercase label, input + unit */
        .config-group {
            display: grid;
            grid-template-columns: 1fr;
            row-gap: 0.35rem;
            margin-bottom: 1.05rem;
        }
        .config-group:last-child { margin-bottom: 0; }
        /* separator miedzy wierszami ustawien (m01): cienka teal linia */
        .config-group + .config-group {
            border-top: 1px solid rgba(37, 194, 168, 0.14);
            padding-top: 1.05rem;
        }

        /* weryfikacja: osobna ramka pod panelem ustawien; col-right jest
           flex-kolumna, config-panel flex:1 - dol ramki rowna sie z dolem
           podgladu w lewej kolumnie */
        .verify-panel {
            padding: 1rem;
        }
        .verify-panel label { margin-bottom: 0.45rem; }

        .config-group label,
        .verify-panel label {
            display: block;
            font-size: 0.76rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--bb-fg-2);
        }

        .config-row {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        /* pola ustawien (m01): teal ramka + delikatny glow jak ramki sekcji */
        .config-input {
            width: 70px;
            padding: 0.45rem 0.5rem;
            background: var(--bb-surface-sunk);
            border: 1px solid var(--bb-neon-border);
            color: var(--bb-fg);
            font-size: 0.92rem;
            text-align: center;
            outline: none;
            box-shadow: 0 0 10px rgba(37, 194, 168, 0.08);
        }
        .config-input:focus { border-color: var(--bb-teal); box-shadow: 0 0 12px rgba(37, 194, 168, 0.22); }

        .config-unit {
            font-size: 0.8rem;
            color: var(--bb-fg-5);
        }

        /* antybot */
        .antibot-q {
            font-size: 0.9rem;
            color: var(--bb-fg-3);
            margin-bottom: 0.4rem;
        }
        .antibot-options {
            display: flex;
            gap: 0.5rem;
        }
        .antibot-opt {
            flex: 1;
            padding: 0.6rem 0.5rem;
            border: 1px solid var(--bb-border-mid);
            background: var(--bb-surface-sunk);
            color: var(--bb-fg-3);
            font-family: var(--bb-font-mono);
            font-size: 0.92rem;
            text-align: center;
            cursor: pointer;
            transition: all 0.15s;
            user-select: none;
        }
        .antibot-opt:hover {
            border-color: var(--bb-violet);
            color: var(--bb-fg-body);
        }
        /* wybrana odpowiedz = violet (mockup m01) */
        .antibot-opt.selected {
            border-color: var(--bb-violet);
            background: rgba(155, 124, 232, 0.10);
            color: #fff;
            box-shadow: 0 0 10px rgba(155, 124, 232, 0.25);
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

        /* CTA: jedyny dozwolony gradient na stronie. Struktura plaska
           (innerHTML swap spinnera - patrz handoff gotchas). */
        .generate-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.7em;
            width: 100%;
            padding: 0.95rem 1rem;
            margin-top: 1rem;
            border: 2px solid transparent;
            background: linear-gradient(90deg, #1b1233 0%, #0a0e15 50%, #0b2127 100%) padding-box,
                        linear-gradient(90deg, var(--bb-teal) 0%, var(--bb-accent) 50%, var(--bb-violet) 100%) border-box;
            color: #fff;
            font-size: 0.95rem;
            font-weight: 800;
            cursor: pointer;
            transition: filter 140ms var(--bb-ease);
            text-transform: uppercase;
            letter-spacing: 0.16em;
            filter: drop-shadow(0 0 9px rgba(122, 92, 230, 0.45));
        }
        .generate-btn [data-lucide] { width: 19px; height: 19px; stroke-width: 2.2; }
        /* hover ujednolicony z mark-secret: bez ruchu, mocniejszy glow,
           jasniejsze wnetrze */
        .generate-btn:hover {
            filter: drop-shadow(0 0 15px rgba(122, 92, 230, 0.80)) brightness(1.15);
            background: linear-gradient(90deg, #2b1d50 0%, #141a2b 50%, #123640 100%) padding-box,
                        linear-gradient(90deg, var(--bb-teal) 0%, var(--bb-accent) 50%, var(--bb-violet) 100%) border-box;
        }
        .generate-btn:active { filter: brightness(0.92); }

        /* guide: pulsuje sam glow, ramka i grubosc bez zmian.
           drop-shadow zamiast box-shadow - bb-frame trzyma box-shadow
           z !important, animacja by przegrala */
        @keyframes bb-guide-verify {
            0%, 100% { filter: drop-shadow(0 0 2px rgba(37, 194, 168, 0.10)); }
            50% { filter: drop-shadow(0 0 14px rgba(37, 194, 168, 0.65)); }
        }
        .config-verify.bb-guide { animation: bb-guide-verify 1.1s ease-in-out infinite; }
        @keyframes bb-guide-cta {
            0%, 100% { filter: drop-shadow(0 0 4px rgba(122, 92, 230, 0.30)); }
            50% { filter: drop-shadow(0 0 16px rgba(122, 92, 230, 0.85)); }
        }
        .generate-btn.bb-guide { animation: bb-guide-cta 1.1s ease-in-out infinite; }
        /* brak tresci przy GENERUJ: edytor blyska 2 pulsami (iteration 2) */
        @keyframes bb-guide-editor {
            0%, 100% { box-shadow: 0 0 10px rgba(37, 194, 168, 0.07); }
            50% { box-shadow: 0 0 20px rgba(37, 194, 168, 0.60); }
        }
        .editor.bb-flash { animation: bb-guide-editor 0.55s ease-in-out 2; }
        /* OZNACZ bez zaznaczenia: hint "Zaznacz fragment..." zapala sie 2x.
           Animacja na .hint-text, nie na .hint-bar - dzieci z wlasnym color
           ignoruja animacje koloru rodzica */
        @keyframes bb-guide-hint {
            0%, 100% { color: var(--bb-fg-3); text-shadow: 0 0 0 rgba(37, 194, 168, 0); }
            50% { color: #eaf6f3; text-shadow: 0 0 10px rgba(37, 194, 168, 0.45); }
        }
        .hint-bar.bb-flash .hint-text { animation: bb-guide-hint 0.55s ease-in-out 2; }
        /* przygaszony dopoki brak tresci + oznaczonego poufnego (po bb-guide,
           zeby dimmed wygrywal i wylaczal puls) */
        .generate-btn.dimmed {
            opacity: 0.4;
            filter: none;
            animation: none;
        }
        .generate-btn:disabled { opacity: 0.65; cursor: not-allowed; }
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

        /* przycisk oznaczania poufnych - wariant z mockupu m01: ciemny box
           z gradientowa ramka teal->violet i bialym uppercase tekstem.
           Nested clip-path jak chip Ctrl+E: zewnetrzna warstwa = gradient
           przyciety wielokatem ze scietymi rogami, wewnetrzny span = ciemne
           wnetrze tym samym wielokatem (1px mniej); drop-shadow podaza
           za ksztaltem. */
        .mark-secret-btn {
            display: inline-flex;
            padding: 2px;
            margin-top: 0.6rem;
            border: none;
            background: linear-gradient(90deg, var(--bb-secret), var(--bb-secret-ink));
            clip-path: polygon(13px 0, 100% 0, 100% calc(100% - 13px), calc(100% - 13px) 100%, 0 100%, 0 13px);
            filter: drop-shadow(0 0 9px rgba(240, 192, 96, 0.42));
            cursor: pointer;
            transition: filter 140ms var(--bb-ease);
        }
        .mark-secret-btn .inner {
            display: inline-flex;
            flex: 1;
            align-items: center;
            justify-content: center;
            gap: 0.6em;
            padding: 0.6rem 1rem;
            background: linear-gradient(90deg, #1c1508 0%, #0a0e15 50%, #1c1508 100%);
            /* notch 12px (zewnetrzny 13) - diagonal trzyma ~2px jak boki */
            clip-path: polygon(12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%, 0 12px);
            color: #fff;
            font-size: 0.86rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        /* wiersz przycisku + dekoracyjne sciezki circuit po prawej (m01) */
        .mark-row { display: flex; margin-top: 0.6rem; }
        .mark-row .mark-secret-btn { margin-top: 0; }
        /* akcje: weryfikacja + generuj obok siebie; generuj rosnie na wysokosc panelu.
           DOM order content->settings->verify->generate->result->preview = poprawny
           flow tez na mobile (gdzie wszystko stackuje sie w jedna kolumne) */
        .action-row { display: flex; align-items: stretch; gap: 1.5rem; margin-top: 1.5rem; }
        .action-row .verify-panel { flex: 1.25; }
        .action-row .generate-btn { flex: 1; margin-top: 0; width: auto; white-space: nowrap; }
        @media (max-width: 768px) { .action-row { flex-direction: column; } }

        .mark-secret-btn:hover {
            filter: drop-shadow(0 0 15px rgba(240, 192, 96, 0.80)) brightness(1.15);
        }
        .mark-secret-btn:hover .inner {
            background: linear-gradient(90deg, #382a0d 0%, #18130a 50%, #382a0d 100%);
        }
        .mark-secret-btn:active { filter: drop-shadow(0 0 5px rgba(240, 192, 96, 0.3)) brightness(0.92); }
        .mark-secret-btn [data-lucide] { width: 18px; height: 18px; stroke-width: 2; color: var(--bb-secret); }

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
        /* taby podgladu (m01): bordered, aktywny = teal z tintem i glow */
        .preview-tab {
            padding: 0.35rem 0.85rem;
            border: 1px solid var(--bb-border);
            background: transparent;
            color: var(--bb-fg-6);
            font-size: 0.72rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            cursor: pointer;
            transition: all 0.15s;
        }
        .preview-tab:hover { border-color: var(--bb-teal); color: var(--bb-fg-3); }
        .preview-tab.active {
            border-color: var(--bb-teal);
            color: var(--bb-teal);
            background: rgba(37, 194, 168, 0.08);
            box-shadow: 0 0 10px rgba(37, 194, 168, 0.18);
        }
        .preview-box {
            padding: 0.85rem;
            min-height: 90px;
            font-family: var(--bb-font-mono);
            font-size: 0.92rem;
            line-height: 1.7;
            white-space: pre-wrap;
            word-break: break-word;
            min-height: 60px;
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
            font-size: 0.85rem;
        }

        /* ====== WYNIK ====== */
        .result {
            margin-top: 1.5rem;
            display: none;
            /* scrollIntoView nie moze schowac boxa pod fixed footerem */
            scroll-margin-bottom: 3.5rem;
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
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--bb-success);
            font-weight: 700;
            margin-bottom: 0.4rem;
        }
        .result-link {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .result-url {
            flex: 1;
            padding: 0.5rem 0.65rem;
            background: var(--bb-surface-sunk);
            border: 1px solid var(--bb-border-mid);
            border-radius: 4px;
            color: var(--bb-success-light);
            font-family: var(--bb-font-mono);
            font-size: 0.875rem;
            outline: none;
        }
        /* kopiuj - FLAT solid green (sukces) */
        .copy-btn {
            padding: 0.5rem 1rem;
            border-radius: 8px;
            border: none;
            background: var(--bb-success);
            color: var(--bb-success-ink);
            font-size: 0.85rem;
            font-weight: 700;
            cursor: pointer;
            transition: filter 140ms var(--bb-ease), transform 140ms var(--bb-ease);
            white-space: nowrap;
        }
        .copy-btn:hover { filter: brightness(1.08); transform: translateY(-1px); }
        .copy-btn:active { filter: brightness(0.92); transform: translateY(0); }

        .result-password {
            margin-top: 0.6rem;
            padding: 0.5rem 0.7rem;
            background: var(--bb-success-bg-2);
            border: 1px solid var(--bb-success-border);
            border-radius: 4px;
            font-size: 0.85rem;
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

<div class="bb-page-art bb-page-art-tl" aria-hidden="true"></div>
<div class="bb-page-art bb-page-art-tr" aria-hidden="true"></div>
<div class="bb-page-art bb-page-art-br" aria-hidden="true"></div>
<div class="bb-page-art bb-page-art-bl" aria-hidden="true"></div>

<div class="header bb-rise-1">
    <?= render_logo('bitback.one', 'https://bitback.one') ?>
    <p><?= htmlspecialchars($t['subtitle']) ?></p>
</div>

<div class="trust bb-rise-2">
    <div class="trust-box bb-art bb-art-aurora bb-art-left bb-art-left-magenta">
        <div class="trust-grid">
            <div class="trust-item">
                <div class="bb-chip bb-chip-violet"><?= bb_icon('lock') ?></div>
                <div class="trust-title"><?= htmlspecialchars($t['trust1_title']) ?></div>
                <div class="trust-desc"><?= htmlspecialchars($t['trust1_desc']) ?></div>
            </div>
            <div class="trust-item">
                <div class="bb-chip bb-chip-violet"><?= bb_icon('clock') ?></div>
                <div class="trust-title"><?= htmlspecialchars($t['trust2_title']) ?></div>
                <div class="trust-desc"><?= htmlspecialchars($t['trust2_desc']) ?></div>
            </div>
            <div class="trust-item">
                <div class="bb-chip bb-chip-violet"><?= bb_icon('monitor') ?></div>
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
                <div class="bb-frame frame-pad">
                    <div class="hint-bar">
                        <kbd><span>Ctrl+E</span></kbd>
                        <span class="hint-text"><?= $t['hint_text'] ?></span>
                    </div>
                    <div class="editor-wrap">
                        <div class="editor-gutter" id="editorGutter" aria-hidden="true">1</div>
                        <div class="editor" id="editor" contenteditable="true" spellcheck="false" role="textbox" aria-multiline="true" aria-label="<?= htmlspecialchars($t['content_label']) ?>"></div>
                    </div>
                    <div class="mark-row">
                        <button type="button" class="mark-secret-btn" onmousedown="event.preventDefault()" onclick="toggleSecret()"><span class="inner"><?= bb_icon('lock') ?> <?= htmlspecialchars($t['mark_secret_btn']) ?></span></button>
                        <label id="plainTextToggleWrap" class="plain-text-toggle" style="display:none;">
                            <input type="checkbox" id="plainTextToggle"> <?= htmlspecialchars($t['plain_text_toggle']) ?>
                        </label>
                    </div>
                </div>
            </div>

            <!-- PRAWA — konfiguracja -->
            <div class="col-right">
                <div class="col-label"><?= htmlspecialchars($t['settings_label']) ?></div>
                <div class="config-panel bb-frame">
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
                            <button type="button" class="copy-btn" style="padding:0.45rem 0.7rem;font-size:0.78rem;" onclick="generatePassword()"><?= htmlspecialchars($t['password_generate']) ?></button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- AKCJE: weryfikacja + generuj obok siebie -->
        <div class="action-row">
            <div class="verify-panel bb-frame config-verify">
                <label><?= htmlspecialchars($t['verify_label']) ?></label>
                <div class="antibot-q" id="mathQuestion" aria-live="polite"></div>
                <div class="antibot-options" id="mathOptions" role="group" aria-label="<?= htmlspecialchars($t['verify_label']) ?>"></div>
            </div>
            <button type="button" class="generate-btn dimmed" onclick="generateLink()"><span><?= htmlspecialchars($t['generate_btn']) ?></span><?= bb_icon('arrow-right') ?></button>
        </div>

        <!-- LINK WYJŚCIOWY -->
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

        <!-- WYNIK BULK (osobny kontener - nie rusza #result pojedynczego linku) -->
        <div id="bulkResult" class="bulk-results" style="display:none;"></div>

        <!-- PODGLĄD na dole -->
        <div class="preview-section">
            <div class="preview-bar">
                <div class="col-label"><?= htmlspecialchars($t['preview_label']) ?></div>
                <div class="preview-tabs">
                    <button type="button" class="preview-tab active" onclick="setPreview('expired', this)"><?= htmlspecialchars($t['preview_expired']) ?></button>
                    <button type="button" class="preview-tab" onclick="setPreview('active', this)"><?= htmlspecialchars($t['preview_active']) ?></button>
                </div>
            </div>
            <div class="preview-box bb-frame" id="preview"></div>
        </div>
    </form>

</div>

<div style="position:fixed;bottom:0;left:0;right:0;z-index:100;background:var(--bb-bg);border-top:1px solid var(--bb-border-soft);padding:0.5rem 1rem;text-align:center;font-size:0.8rem;color:var(--bb-fg-5);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
    <a href="https://bitback.pl" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;"><strong>bitback.pl</strong></a>
    <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><?= htmlspecialchars($t['footer_tagline']) ?>
    <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span>Zbigniew Gralewski
    <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><a href="mailto:zbigniew.gralewski@bitback.pl" style="color:var(--bb-accent-link);text-decoration:none;">zbigniew.gralewski@bitback.pl</a>
    <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span>609 505 065
    <span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><?= htmlspecialchars($t['footer_source']) ?> <a href="https://github.com/bitback/bitback.one" target="_blank" rel="noopener" style="color:var(--bb-accent-link);text-decoration:none;">GitHub</a><span style="color:var(--bb-fg-8);margin:0 0.5rem;">|</span><strong style="color:var(--bb-accent-link);"><?= htmlspecialchars($t['footer_commercial']) ?></strong>
</div>

<script src="/crypto.js?v=<?= filemtime(__DIR__ . '/crypto.js') ?>" integrity="sha384-4BY47Z9e+fuHtuSztPUqLut6qM8DMIDJsVMAutU/wlrPqn2vo+ZHbxJlH6ymu/d0"></script>
<script>
    const T = {
        error_ratelimit: <?= json_encode($t['error_ratelimit']) ?>,
        error_math: <?= json_encode($t['error_math']) ?>,
        error_server: <?= json_encode($t['error_server']) ?>,
        error_connection: <?= json_encode($t['error_connection']) ?>,
        your_password: <?= json_encode($t['your_password']) ?>,
        password_unrecoverable: <?= json_encode($t['password_unrecoverable']) ?>,
        password_generate: <?= json_encode($t['password_generate']) ?>,
        copied: <?= json_encode($t['copied']) ?>,
        copy: <?= json_encode($t['copy']) ?>,
        generate_btn: <?= json_encode($t['generate_btn']) ?>,
        generating: <?= json_encode($t['generating']) ?>,
        preview_empty: <?= json_encode($t['preview_empty']) ?>,
        import_detected: <?= json_encode($t['import_detected']) ?>,
        import_multi_tables: <?= json_encode($t['import_multi_tables']) ?>,
        bulk_preview_note: <?= json_encode($t['bulk_preview_note']) ?>,
        error_batch_too_many: <?= json_encode($t['error_batch_too_many']) ?>,
        error_batch: <?= json_encode($t['error_batch']) ?>
    };
    const editor = document.getElementById('editor');
    let previewMode = 'expired';

    // --- GUTTER NUMERACJI LINII ---
    // Liczy linie WIZUALNE (wysokosc wyrenderowanej tresci / line-height),
    // wiec numery sa zawsze wyrownane z trescia - takze gdy dluga linia
    // sie zawija. Pusty edytor: numeruje linie placeholdera (::before).
    const gutter = document.getElementById('editorGutter');
    const PLACEHOLDER_LINES = <?= count(explode("\n", $t['editor_placeholder'])) ?>;
    function updateGutter() {
        // bulk: numeracja linii dla tabeli bezsensowna - ukryj gutter i zredukuj
        // wciecie edytora (bez gutter 3.3rem lewego paddingu tabela sie odsuwa)
        if (isBulkMode()) { gutter.style.display = 'none'; editor.classList.add('editor-bulk'); return; }
        gutter.style.display = ''; editor.classList.remove('editor-bulk');
        const lh = parseFloat(getComputedStyle(editor).lineHeight);
        let lines;
        if (editor.textContent.length === 0 && !editor.querySelector('br,div')) {
            lines = PLACEHOLDER_LINES;
        } else {
            const r = document.createRange();
            r.selectNodeContents(editor);
            const h = r.getBoundingClientRect().height;
            lines = Math.max(1, Math.round(h / lh));
        }
        let out = '';
        for (let i = 1; i <= lines; i++) out += i + '\n';
        gutter.textContent = out;
    }
    window.addEventListener('resize', updateGutter);

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
                updateGuide();
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

    function flashHint() {
        const hint = document.querySelector('.hint-bar');
        hint.classList.remove('bb-flash');
        void hint.offsetWidth;
        hint.classList.add('bb-flash');
    }

    function toggleSecret() {
        const sel = window.getSelection();
        if (!sel.rangeCount) { flashHint(); return; }

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
            if (!editor.contains(range.commonAncestorContainer)) { flashHint(); return; }

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
        if (sel.isCollapsed) { flashHint(); return; } // nic nie zaznaczono
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

    // --- GUIDE: co pulsuje w danym stanie (pulsuje sam glow, ramki bez zmian) ---
    // oznaczenie poufnego -> pulsuje WERYFIKACJA; wybor odpowiedzi -> zapala sie GENERUJ
    function updateGuide() {
        // bulk: poufnosc syntetyzowana dopiero przy generowaniu (brak .secret w
        // edytorze), wiec content/secret spelnione gdy jest tabela bulk
        const bulk = isBulkMode();
        const hasContent = bulk ? true : (editor.textContent.trim().length > 0);
        const hasSecret = bulk ? true : !!editor.querySelector('.secret');
        const hasAnswer = selectedAnswer !== null;
        const ready = hasContent && hasSecret && hasAnswer;
        const gen = document.querySelector('.generate-btn');
        gen.classList.toggle('dimmed', !ready);
        gen.classList.toggle('bb-guide', ready);
        document.querySelector('.config-verify').classList.toggle('bb-guide', hasContent && hasSecret && !hasAnswer);
    }

    // --- PODGLĄD ---
    function updatePreview() {
        updateGutter();
        // pokaz przelacznik plain tylko gdy tabela obecna; sprzataj note gdy znikla
        const hasImportTable = !!editor.querySelector(':scope > table.bb-import-table');
        const toggleWrap = document.getElementById('plainTextToggleWrap');
        if (toggleWrap) toggleWrap.style.display = hasImportTable ? '' : 'none';
        if (!hasImportTable) { const n = document.getElementById('importNote'); if (n) n.remove(); }
        const previewBox = document.getElementById('preview');
        const html = editor.innerHTML;
        const isEmpty = editor.textContent.trim().length === 0;
        updateGuide();

        if (isEmpty) {
            previewBox.innerHTML = '<span class="preview-empty">' + (T.preview_empty || '') + '</span>';
            return;
        }

        // bulk: tabela to WEJSCIE, nie prawdziwy output. Pokaz interpretacje
        // jednego rekordu tak jak zobaczy go odbiorca (expired -> zamaskowany).
        if (isBulkMode()) {
            const recs = collectBulkRecords();
            previewBox.innerHTML = '';
            const pnote = document.createElement('div');
            pnote.className = 'bulk-preview-note';
            pnote.textContent = (T.bulk_preview_note || '').replace('{n}', recs.length);
            previewBox.appendChild(pnote);
            if (recs[0]) previewBox.appendChild(buildBulkPreview(recs[0], previewMode === 'expired'));
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
    (function(){ const pt = document.getElementById('plainTextToggle'); if (pt) pt.addEventListener('change', updatePreview); })();

    // --- IMPORT TABELI (WKLEJKA Z EXCELA) ---
    // Buduje gola kopie tabeli: zostawia tylko table/thead/tbody/tr/td/th/br +
    // wezly tekstowe, zdejmuje wszystkie atrybuty. Tagi spoza whitelisty sa
    // UNWRAP - ich dzieci sa doklejane do rodzica (tekst z <b>/<span> nie ginie).
    function cleanPastedTable(html) {
        const ALLOWED = { TABLE:1, THEAD:1, TBODY:1, TR:1, TD:1, TH:1, BR:1 };
        const doc = new DOMParser().parseFromString(html, 'text/html');
        const src = doc.querySelector('table');
        if (!src) return null;

        function clean(node, parent) {
            if (node.nodeType === 3) { parent.appendChild(document.createTextNode(node.textContent)); return; }
            if (node.nodeType !== 1) return;
            if (ALLOWED[node.tagName]) {
                const el = document.createElement(node.tagName.toLowerCase());
                node.childNodes.forEach(ch => clean(ch, el));
                parent.appendChild(el);
            } else {
                node.childNodes.forEach(ch => clean(ch, parent));
            }
        }
        const frag = document.createDocumentFragment();
        clean(src, frag);
        const table = frag.querySelector('table');
        if (!table) return null;
        table.className = 'bb-import-table';
        return { table, tableCount: doc.querySelectorAll('table').length };
    }

    editor.addEventListener('paste', function(e) {
        const html = e.clipboardData ? e.clipboardData.getData('text/html') : '';
        if (!html || html.indexOf('<table') === -1) return;
        const res = cleanPastedTable(html);
        if (!res) return;
        e.preventDefault();
        const sel = window.getSelection();
        if (sel.rangeCount) {
            const range = sel.getRangeAt(0);
            range.deleteContents();
            range.insertNode(res.table);
            range.setStartAfter(res.table);
            range.collapse(true);
            sel.removeAllRanges(); sel.addRange(range);
        } else {
            editor.appendChild(res.table);
        }
        hoistTableToEditor(res.table);
        showImportNote(res.table, res.tableCount);
        updatePreview();
    });

    // Rozbija kazdy wrapper miedzy tabela a #editor, przenoszac WSZYSTKIE jego
    // dzieci (tabele oraz ewentualny naglowek/stopke w tym samym wrapperze) o
    // poziom wyzej z zachowaniem kolejnosci. Wyjmowanie samej tabeli zostawiloby
    // stopke w wrapperze PRZED tabela - rozbicie wrappera to naprawia.
    function hoistTableToEditor(table) {
        while (table.parentNode && table.parentNode !== editor) {
            const p = table.parentNode;
            const grand = p.parentNode;
            while (p.firstChild) grand.insertBefore(p.firstChild, p);
            grand.removeChild(p);
        }
    }

    function showImportNote(table, tableCount) {
        const rows = table.querySelectorAll('tr').length;
        const firstRow = table.querySelector('tr');
        const cols = firstRow ? firstRow.children.length : 0;
        let note = document.getElementById('importNote');
        if (!note) {
            note = document.createElement('div');
            note.id = 'importNote'; note.className = 'bb-import-note';
            editor.parentNode.insertBefore(note, editor.nextSibling);
        }
        note.textContent = (T.import_detected || '').replace('{rows}', rows).replace('{cols}', cols);
        // ostrzez o wielu tabelach: z jednej wklejki (tableCount) LUB juz obecnych
        // w edytorze (osobne wklejenia) - uzywana jest tylko pierwsza
        const editorTables = editor.querySelectorAll('table.bb-import-table').length;
        const effective = Math.max(tableCount, editorTables);
        if (effective > 1) {
            const w = document.createElement('div'); w.className = 'warn';
            w.textContent = (T.import_multi_tables || '').replace('{n}', effective);
            note.appendChild(w);
        }
    }

    // --- TRYB BULK: DETEKCJA + PARSER KORESPONDENCJI SERYJNEJ ---
    // Bulk = tabela bezposrednim dzieckiem #editor, >=3 wiersze (naglowek + >=2
    // dane), przelacznik "zwykly tekst" wylaczony.
    function isBulkMode() {
        const cb = document.getElementById('plainTextToggle');
        if (cb && cb.checked) return false;
        const table = editor.querySelector(':scope > table.bb-import-table');
        if (!table) return false;
        return table.querySelectorAll('tr').length >= 3;
    }

    // Tekst komorki: wszystkie biale znaki (entery, taby, wielokrotne spacje,
    // <br>) -> pojedyncza spacja + trim. Czysci smieci wklejone z Excela/kodu.
    function cellText(td) {
        let s = '';
        (function walk(node) {
            node.childNodes.forEach(n => {
                if (n.nodeType === 3) s += n.textContent;
                else if (n.nodeType === 1) { if (n.tagName === 'BR') s += ' '; else walk(n); }
            });
        })(td);
        return s.replace(/\s+/g, ' ').trim();
    }

    // Konwersja tabeli na TSV - tryb plain (przelacznik ON lub 1 wiersz danych).
    function tableToPlainText(table) {
        return Array.from(table.querySelectorAll('tr')).map(tr =>
            Array.from(tr.children).map(td => cellText(td)).join('\t')
        ).join('\n');
    }

    // Tekst wezla z konwersja <br>/<div> na \n - inaczej filtr '---' pudluje na
    // wieloliniowych naglowkach.
    function nodeTextBr(n) {
        if (n.nodeType === 3) return n.textContent;
        if (n.nodeType !== 1) return '';
        if (n.tagName === 'BR') return '\n';
        // inna tabela NIE jest czescia naglowka/stopki - nie sklejaj jej komorek
        // do jawnego tekstu (wyciek danych do stopki kazdego rekordu)
        if (n.tagName === 'TABLE') return '';
        let s = '';
        n.childNodes.forEach(ch => { s += nodeTextBr(ch); });
        return s + (n.tagName === 'DIV' ? '\n' : '');
    }
    // Naglowek = wezly PRZED tabela; stopka = wezly PO tabeli. Linie '---'
    // (separator wizualny) usuwane z tresci rekordu.
    function domTextBefore(root, table) {
        let s = '';
        for (const n of Array.from(root.childNodes)) { if (n === table) break; s += nodeTextBr(n); }
        return s.split('\n').filter(l => l.trim() !== '---').join('\n').trim();
    }
    function domTextAfter(root, table) {
        let s = '', seen = false;
        for (const n of Array.from(root.childNodes)) { if (n === table) { seen = true; continue; } if (seen) s += nodeTextBr(n); }
        return s.split('\n').filter(l => l.trim() !== '---').join('\n').trim();
    }
    // Rekord: naglowek(jawny) + per NIEpusta komorka [etykieta: (text) + wartosc
    // (secret) + \n(text)] + stopka(jawny). Iteruje po KOMORKACH (nie labels) -
    // wiersz szerszy niz naglowek (scalone komorki Excela) nie gubi wartosci;
    // brak etykiety -> sama wartosc. Pusta komorka -> linia pominieta.
    function buildRecordSections(header, labels, cells, footer) {
        const out = [];
        // '---' (separator naglowek/stopka) -> pusty wiersz (jeden Enter) w renderze:
        // naglowek, PUSTA LINIA, rekord, PUSTA LINIA, stopka.
        if (header) out.push({ type:'text', content: header + '\n\n' });
        for (let k = 0; k < cells.length; k++) {
            const val = cells[k];
            if (!val) continue;
            const label = (labels[k] || '').trim();
            if (label) out.push({ type:'text', content: label + ': ' });
            out.push({ type:'secret', content: val });
            out.push({ type:'text', content: '\n' });
        }
        if (footer) out.push({ type:'text', content: '\n' + footer });
        return out;
    }
    function collectBulkRecords() {
        const table = editor.querySelector(':scope > table.bb-import-table');
        const rows = Array.from(table.querySelectorAll('tr'));
        const labels = Array.from(rows[0].children).map(c => cellText(c));
        const header = domTextBefore(editor, table);
        const footer = domTextAfter(editor, table);
        const records = [];
        for (let i = 1; i < rows.length; i++) {
            const cells = Array.from(rows[i].children).map(c => cellText(c));
            if (cells.every(c => !c)) continue; // pomin calkowicie pusty wiersz (ogon zaznaczenia z Excela)
            records.push({ sections: buildRecordSections(header, labels, cells, footer), values: cells });
        }
        return records;
    }

    // Podglad JEDNEGO rekordu tak jak zobaczy go odbiorca (etykieta: wartosc) -
    // z sekcji, ktore realnie ida do szyfrowania. expired -> wartosci zamaskowane.
    // Tabela to WEJSCIE, nie output; maskowanie komorek tabeli wprowadzaloby w blad.
    function buildBulkPreview(record, expired) {
        const container = document.createElement('div');
        record.sections.forEach(s => {
            if (s.type === 'secret') {
                const span = document.createElement('span');
                if (expired) { span.className = 'masked'; span.textContent = '●●●●●●'; }
                else { span.className = 'secret'; span.textContent = s.content; }
                container.appendChild(span);
            } else {
                const parts = s.content.split('\n');
                parts.forEach((part, i) => {
                    if (i > 0) container.appendChild(document.createElement('br'));
                    if (part) container.appendChild(document.createTextNode(part));
                });
            }
        });
        return container;
    }

    // --- EKSTRAKCJA DANYCH Z EDYTORA ---
    // root domyslnie #editor; mozna podac klon (tryb plain nie mutuje edytora).
    function extractSections(root) {
        root = root || editor;
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

        root.childNodes.forEach(node => parseNode(node));

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

    // --- WSPOLNY PAYLOAD (pojedynczy link + bulk) ---
    // Filtr pustych, przydzial gestego idx 0..N-1, podzial na text/secret,
    // szyfrowanie oboma blobami. WYMAGA hexKey (encryptBlob go wymaga).
    // total_sections MUSI = liczba sekcji po filtrze - view.php fillMasked
    // maskuje po tej numeracji, rozjazd zepsulby maskowanie u odbiorcy.
    async function sectionsToPayload(sections, aesKey) {
        const filtered = sections.filter(s => s.content.length > 0);
        const textSections = [];
        const secretSections = [];
        filtered.forEach((s, idx) => {
            const entry = { idx: idx, content: s.content };
            if (s.type === 'secret') {
                secretSections.push(entry);
            } else {
                textSections.push(entry);
            }
        });
        const encrypted_text = await encryptBlobV3(textSections, aesKey);
        const encrypted_secrets = secretSections.length > 0
            ? await encryptBlobV3(secretSections, aesKey)
            : null;
        return { encrypted_text, encrypted_secrets, total_sections: filtered.length };
    }

    // Generator hasla: 14 znakow z alfabetu bez homoglifow (a-z bez l, 2-9) ~ 65 bitow.
    // Znaki z crypto.getRandomValues; wartosci >= 231 (7*33) odrzucane = zero modulo-bias.
    function generatePassword() {
        const alphabet = 'abcdefghijkmnopqrstuvwxyz23456789'; // 33 znaki, bez l/0/1
        let out = '';
        while (out.length < 14) {
            const b = crypto.getRandomValues(new Uint8Array(1))[0];
            if (b < 231) out += alphabet[b % 33]; // 231 = 7*33 -> zero modulo-bias
        }
        document.getElementById('linkPassword').value = out;
        updateGuide();
    }

    // v3: klucze per link. Z haslem: PBKDF2(haslo, salt="bb3|"+hexKey) -> master
    // -> {aesKey (enc), authTag (do serwera)}. Bez hasla: HKDF z SHA-256("bb3|"+hexKey).
    async function buildV3Keys(pwd, hexKey) {
        if (pwd) {
            const master = await deriveMasterV3(pwd, hexKey, V3_ITER);
            return { aesKey: await aesKeyFromMaster(master), authTag: await authTagFromMaster(master) };
        }
        return { aesKey: await aesKeyNoPassV3(hexKey), authTag: null };
    }

    // --- GENERUJ LINK ---
    async function generateLink() {
        // honeypot
        const honeypot = document.querySelector('.ohnohoney').value;

        // treść
        const text = editor.textContent.trim();
        if (!text) {
            document.querySelector('.config-verify').classList.remove('bb-guide');
            editor.classList.remove('bb-flash');
            void editor.offsetWidth;
            editor.classList.add('bb-flash');
            return;
        }

        // math - brak wyboru: zamiast alertu glow prowadzi do weryfikacji
        if (selectedAnswer === null) {
            document.querySelector('.config-verify').classList.add('bb-guide');
            return;
        }
        document.querySelector('.generate-btn').classList.remove('bb-guide');

        // --- GALAZ BULK (korespondencja seryjna): N kluczy, jeden POST, N linkow ---
        // NIE uzywa extractSections - ma wlasny spinner/timeout/finally i return.
        if (isBulkMode()) {
            const recs = collectBulkRecords();
            // limit po stronie klienta - nie szyfruj nadmiaru zeby dostac 400 z serwera
            const BATCH_MAX = <?= defined('BATCH_MAX_RECORDS') ? BATCH_MAX_RECORDS : 200 ?>;
            if (recs.length < 1) return; // same puste wiersze - nic do wygenerowania
            if (recs.length > BATCH_MAX) { alert((T.error_batch_too_many || '').replace('{max}', BATCH_MAX)); return; }
            const btn = document.querySelector('.generate-btn');
            const btnOriginalHTML = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span>' + (T.generating || 'Encrypting...');
            try {
                // osobny klucz AES-256 per rekord (zero-trust) - serwer nie widzi kluczy.
                // v3: PBKDF2 per rekord (salt=hexKey_i - anty-prekomputacja). crypto.subtle liczy
                // poza watkiem UI; chunki po 8 daja rownoleglosc bez zalewania pamieci.
                const pwd = document.getElementById('linkPassword').value.trim();
                const keys = new Array(recs.length), payloads = new Array(recs.length);
                const CONC = 8;
                let kdone = 0;
                for (let i = 0; i < recs.length; i += CONC) {
                    await Promise.all(recs.slice(i, i + CONC).map(async (rec, j) => {
                        const idx = i + j;
                        const key = generateHexKey();
                        const v3 = await buildV3Keys(pwd, key);
                        const p = await sectionsToPayload(rec.sections, v3.aesKey);
                        keys[idx] = key;
                        payloads[idx] = { encrypted_text: p.encrypted_text, encrypted_secrets: p.encrypted_secrets, total_sections: p.total_sections, auth_tag: v3.authTag };
                        kdone++;
                    }));
                    btn.innerHTML = '<span class="spinner"></span>' + (T.generating || '') + ' ' + kdone + '/' + recs.length;
                }
                const ctrl = new AbortController();
                const timer = setTimeout(() => ctrl.abort(), 15000);
                let resp;
                try {
                    resp = await fetch('/api/create-batch.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        signal: ctrl.signal,
                        body: JSON.stringify({
                            website_url: honeypot,
                            expire_days: parseInt(document.getElementById('expireDays').value) || <?= DEFAULT_EXPIRE_DAYS ?>,
                            max_views: parseInt(document.getElementById('maxViews').value) || <?= DEFAULT_MAX_VIEWS ?>,
                            delete_after_days: parseInt(document.getElementById('deleteDays').value) || <?= DEFAULT_DELETE_DAYS ?>,
                            kdf: pwd ? { alg: 'PBKDF2-SHA256', iter: V3_ITER } : null,
                            math_a: CH.a, math_b: CH.b, math_exp: CH.exp, math_token: CH.token, math_answer: selectedAnswer,
                            records: payloads,
                        }),
                    });
                } finally {
                    clearTimeout(timer);
                }
                const result = await resp.json();
                if (result.ok) {
                    document.getElementById('result').classList.remove('show'); // ukryj wynik pojedynczego linku
                    renderBulkResults(recs, result.links, keys);
                    refreshChallenge();
                } else if (result.error === 'ratelimit') {
                    alert(T.error_ratelimit); refreshChallenge();
                } else if (result.error === 'math') {
                    alert(T.error_math); refreshChallenge();
                } else if (result.error === 'batch_size' || result.error === 'too_large') {
                    alert(T.error_batch || T.error_server); refreshChallenge();
                } else {
                    alert(T.error_server); refreshChallenge();
                }
            } catch (e) {
                alert(T.error_connection);
            } finally {
                btn.disabled = false; btn.innerHTML = btnOriginalHTML;
            }
            return;
        }

        // tryb plain (przelacznik ON lub 1 wiersz danych): zamien tabele na TSV
        // na KOPII, nie mutuj edytora - gdy request padnie user nie traci tabeli.
        let extractRoot = editor;
        const plainTable = editor.querySelector(':scope > table.bb-import-table');
        if (plainTable && !isBulkMode()) {
            extractRoot = editor.cloneNode(true);
            const t = extractRoot.querySelector(':scope > table.bb-import-table');
            t.parentNode.replaceChild(document.createTextNode(tableToPlainText(t)), t);
        }

        const sections = extractSections(extractRoot);

        // --- CLIENT-SIDE ENCRYPTION ---
        const hexKey = generateHexKey();
        const pwd = document.getElementById('linkPassword').value.trim();

        const btn = document.querySelector('.generate-btn');
        const btnOriginalHTML = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span>' + (T.generating || 'Encrypting...');

        try {
            // Szyfruj w przeglądarce (wspolna funkcja - spojnosc idx z bulk)
            const v3 = await buildV3Keys(pwd, hexKey);
            const payload = await sectionsToPayload(sections, v3.aesKey);

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
                        encrypted_text: payload.encrypted_text,
                        encrypted_secrets: payload.encrypted_secrets,
                        total_sections: payload.total_sections,
                        expire_days: parseInt(document.getElementById('expireDays').value) || <?= DEFAULT_EXPIRE_DAYS ?>,
                        max_views: parseInt(document.getElementById('maxViews').value) || <?= DEFAULT_MAX_VIEWS ?>,
                        delete_after_days: parseInt(document.getElementById('deleteDays').value) || <?= DEFAULT_DELETE_DAYS ?>,
                        format: 3,
                        kdf: v3.authTag ? { alg: 'PBKDF2-SHA256', iter: V3_ITER } : null,
                        auth_tag: v3.authTag,
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
                if (pwd) {
                    pwdEl.innerHTML = T.your_password + ' <strong>' + pwd.replace(/</g, '&lt;') + '</strong><br><small>' + T.password_unrecoverable + '</small>';
                    pwdEl.classList.add('show');
                } else {
                    pwdEl.classList.remove('show');
                    pwdEl.innerHTML = '';
                }
                document.getElementById('result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
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

    // Lista wynikow bulk: JEDNA tabela zeby kolumny wartosci wyrownaly sie same
    // wg tresci (nie plywaly per rekord). Per rekord: wiersz wartosci (wszystkie
    // kolumny, puste td dla wyrownania) + wiersz linku (colspan, URL+Kopiuj) +
    // pusty wiersz-odstep. Dane z przegladarki SPRZED szyfrowania (nic nie deszyfrujemy).
    function renderBulkResults(records, links, keys) {
        const box = document.getElementById('bulkResult');
        box.innerHTML = ''; box.style.display = 'block';
        // notka o wspolnym hasle jesli ustawione (spec: jawny kompromis MVP)
        const pwd = document.getElementById('linkPassword');
        if (pwd && pwd.value) {
            const n = document.createElement('div'); n.className = 'bulk-note';
            n.textContent = (T.your_password || '') + ' ' + pwd.value + ' - ' + (T.password_unrecoverable || '');
            box.appendChild(n);
        }
        const shown = [];
        records.forEach((rec, i) => { if (links && links[i]) shown.push({ rec: rec, url: links[i].url + '#' + keys[i] }); });
        let cols = 1;
        shown.forEach(x => { cols = Math.max(cols, x.rec.values.length); });
        const table = document.createElement('table'); table.className = 'bulk-results-table';
        shown.forEach((x, idx) => {
            // wiersz wartosci - wszystkie kolumny (puste td dla wyrownania szerokosci)
            const vtr = document.createElement('tr'); vtr.className = 'bulk-values-row';
            for (let c = 0; c < cols; c++) {
                const cell = document.createElement('td');
                cell.textContent = x.rec.values[c] || '';
                vtr.appendChild(cell);
            }
            table.appendChild(vtr);
            // wiersz linku - kolumny zmergeowane (colspan)
            const ltr = document.createElement('tr'); ltr.className = 'bulk-link-row';
            const ltd = document.createElement('td'); ltd.colSpan = cols;
            const cell = document.createElement('div'); cell.className = 'bulk-link-cell';
            const inp = document.createElement('input'); inp.readOnly = true; inp.value = x.url;
            const btn = document.createElement('button'); btn.type = 'button'; btn.textContent = T.copy || 'Copy';
            btn.addEventListener('click', () => {
                const done = () => { btn.textContent = T.copied || 'OK'; setTimeout(() => btn.textContent = T.copy || 'Copy', 2000); };
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(x.url).then(done).catch(() => { inp.select(); try { document.execCommand('copy'); done(); } catch (e) {} });
                } else { inp.select(); try { document.execCommand('copy'); done(); } catch (e) {} }
            });
            cell.appendChild(inp); cell.appendChild(btn); ltd.appendChild(cell); ltr.appendChild(ltd);
            table.appendChild(ltr);
            // pusty wiersz-odstep miedzy rekordami (nie po ostatnim)
            if (idx < shown.length - 1) {
                const str = document.createElement('tr'); str.className = 'bulk-spacer-row';
                const std = document.createElement('td'); std.colSpan = cols; str.appendChild(std);
                table.appendChild(str);
            }
        });
        box.appendChild(table);
        box.scrollIntoView({ block: 'nearest' });
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
