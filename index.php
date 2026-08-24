<?php
require_once __DIR__ . '/inc/config.php';
require_once __DIR__ . '/inc/i18n.php';
require_once __DIR__ . '/inc/logo.php';
require_once __DIR__ . '/inc/antibot.php';
require_once __DIR__ . '/inc/icons.php';
require_once __DIR__ . '/inc/assets.php';
require_once __DIR__ . '/inc/footer.php';
$lang = detect_lang();
$t = get_strings($lang);
$challenge = antibot_challenge();

/** Dane, ktore skrypty strony glownej dostaja z serwera (wyspa #bb-config). */
function bb_config_data(array $t, array $challenge): array {
    $jsKeys = [
        'error_ratelimit', 'error_math', 'error_server', 'error_connection',
        'your_password', 'password_unrecoverable', 'password_generate',
        'copied', 'copy', 'generate_btn', 'generating', 'preview_empty',
        'import_detected', 'import_multi_tables', 'bulk_preview_note',
        'error_batch_too_many', 'error_batch',
    ];
    $strings = [];
    foreach ($jsKeys as $k) {
        $strings[$k] = $t[$k];
    }

    return [
        't' => $strings,
        // Liczba linii placeholdera edytora: gutter numeruje je, gdy pole jest puste.
        'placeholderLines' => count(explode("\n", $t['editor_placeholder'])),
        'challenge' => $challenge,
        'batchMax'  => defined('BATCH_MAX_RECORDS') ? BATCH_MAX_RECORDS : 200,
        'defaults'  => [
            'expireDays' => DEFAULT_EXPIRE_DAYS,
            'maxViews'   => DEFAULT_MAX_VIEWS,
            'deleteDays' => DEFAULT_DELETE_DAYS,
        ],
    ];
}
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
    <?= asset_css(
        'assets/fonts.css',
        'assets/tokens.css',
        'assets/css/home-base.css',
        'assets/css/home-editor.css',
        'assets/css/home-config.css',
        'assets/css/home-result.css',
        'assets/css/editor-demo.css',
        'assets/css/footer.css'
    ) ?>
</head>
<body class="bb-landing">


<div class="header bb-rise-1">
    <?= render_logo('bitback.one', 'https://bitback.one') ?>
    <p><?= htmlspecialchars($t['subtitle']) ?></p>
</div>

<div class="main bb-rise-3">
    <form id="createForm" autocomplete="off">
        <input type="text" name="website_url" class="ohnohoney" tabindex="-1" autocomplete="off">

        <div class="two-col">
            <!-- LEWA — edytor -->
            <div class="col-left">
                <div class="col-label"><span class="step-badge" aria-hidden="true">1</span><?= htmlspecialchars($t['content_label']) ?></div>
                <div class="content-col">
                    <div class="hint-bar">
                        <span class="hint-text"><?= $t['hint_text'] ?></span>
                    </div>
                    <div class="editor-wrap">
                        <div class="editor-gutter" id="editorGutter" aria-hidden="true">1</div>
                        <div class="editor" id="editor" contenteditable="true" spellcheck="false" role="textbox" aria-multiline="true" aria-label="<?= htmlspecialchars($t['content_label']) ?>" data-ph="<?= htmlspecialchars($t['editor_placeholder']) ?>"></div>
                    </div>
                    <div class="mark-row">
                        <button type="button" class="mark-secret-btn" data-bb-action="toggle-secret" data-bb-keep-selection><span class="inner"><?= bb_icon('lock') ?> <?= htmlspecialchars($t['mark_secret_btn']) ?></span></button>
                        <label id="plainTextToggleWrap" class="plain-text-toggle" style="display:none;">
                            <input type="checkbox" id="plainTextToggle"> <?= htmlspecialchars($t['plain_text_toggle']) ?>
                        </label>
                        <p class="mark-note"><?= htmlspecialchars($t['mark_note']) ?></p>
                    </div>
                </div>
            </div>

            <!-- PRAWA — konfiguracja -->
            <div class="col-right">
                <div class="col-label"><span class="step-badge" aria-hidden="true">2</span><?= htmlspecialchars($t['settings_label']) ?><span class="step-optional">(<?= htmlspecialchars($t['optional_tag']) ?>)</span></div>
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
                            <input type="text" class="config-input config-input-full" id="linkPassword" placeholder="<?= htmlspecialchars($t['password_placeholder_config']) ?>" autocomplete="off">
                            <button type="button" class="copy-btn copy-btn-sm" data-bb-action="generate-password"><?= htmlspecialchars($t['password_generate']) ?></button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- AKCJE: kroki 3 i 4, na tej samej siatce co kolumny wyzej -->
        <div class="action-row">
            <div class="act-cell">
                <div class="col-label"><span class="step-badge" aria-hidden="true">3</span><?= htmlspecialchars($t['verify_label']) ?></div>
                <div class="verify-panel bb-frame config-verify">
                    <div class="antibot-q" id="mathQuestion" aria-live="polite"></div>
                    <div class="antibot-options" id="mathOptions" role="group" aria-label="<?= htmlspecialchars($t['verify_label']) ?>"></div>
                </div>
            </div>
            <div class="act-cell act-cell-gen">
                <div class="col-label"><span class="step-badge" aria-hidden="true">4</span><?= htmlspecialchars($t['generate_label']) ?></div>
                <button type="button" class="generate-btn dimmed" data-bb-action="generate-link"><span><?= htmlspecialchars($t['generate_btn']) ?></span><?= bb_icon('arrow-right') ?></button>
            </div>
        </div>

        <!-- LINK WYJŚCIOWY -->
        <div class="result" id="result">
            <div class="result-box bb-card bb-card-success">
                <div class="result-label"><?= htmlspecialchars($t['your_link']) ?></div>
                <div class="result-link">
                    <input type="text" class="result-url" id="resultUrl" readonly>
                    <button type="button" class="copy-btn" data-bb-action="copy-link"><?= htmlspecialchars($t['copy']) ?></button>
                </div>
                <div class="result-password" id="resultPassword"></div>
            </div>
        </div>

        <!-- WYNIK BULK (osobny kontener - nie rusza #result pojedynczego linku) -->
        <div id="bulkResult" class="bulk-results" style="display:none;"></div>

        <!-- PODGLĄD na dole -->
        <div class="preview-section">
            <div class="preview-bar">
                <div class="col-label"><?= htmlspecialchars($t['preview_label'] . ' ' . $t['preview_expired']) ?></div>
            </div>
            <div class="preview-box bb-frame" id="preview"></div>
        </div>
    </form>

</div>

<div class="security bb-rise-4">
    <div class="col-label"><?= htmlspecialchars($t['security_label']) ?></div>
    <div class="security-grid">
        <?php for ($i = 1; $i <= 6; $i++): ?>
        <div>
            <h2 class="security-h"><?= htmlspecialchars($t['security_h' . $i]) ?></h2>
            <p class="security-prose"><?= htmlspecialchars($t['security_p' . $i]) ?></p>
        </div>
        <?php endfor; ?>
    </div>
</div>

<?= site_footer_html() ?>

<script src="/crypto.js?v=<?= filemtime(__DIR__ . '/crypto.js') ?>" integrity="sha384-RQoDrUypIasRu3YH/1KbhpaEtfmzmQlvafmSuNpL1E3zl8rpuvHzLF/C9jqmsD53"></script>
<?= json_island('bb-config', bb_config_data($t, $challenge)) ?>
<?= asset_js(
    'assets/js/home-editor.js',
    'assets/js/home-bulk.js',
    'assets/js/home-generate.js',
    'assets/js/home-wire.js',
    'assets/js/editor-demo.js'
) ?>

</body>
</html>
