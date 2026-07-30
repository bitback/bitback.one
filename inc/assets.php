<?php
/**
 * Tagi <link>/<script> dla lokalnych plikow statycznych.
 *
 * Cache-bust `?v=<filemtime>` jest OBOWIAZKOWY, nie kosmetyczny: Cloudflare
 * cache'uje pliki statyczne agresywnie, a przy skrypcie z atrybutem `integrity`
 * stary plik z cache nie zgadza sie z nowym hashem w HTML - przegladarka wtedy
 * ODMAWIA wykonania skryptu (bialy ekran, nie degradacja).
 */

/** Sciezka publiczna assetu z cache-bustem. $rel liczone od korzenia projektu. */
function asset_url(string $rel): string {
    $abs = dirname(__DIR__) . '/' . $rel;
    // is_file zamiast samego filemtime: brakujacy plik nie ma sypac warningiem
    // w środek dokumentu HTML.
    $ver = is_file($abs) ? filemtime($abs) : 0;
    return '/' . $rel . '?v=' . $ver;
}

/** Arkusze stylow. Kolejnosc argumentow = kolejnosc kaskady. */
function asset_css(string ...$rel): string {
    $out = [];
    foreach ($rel as $r) {
        $out[] = '<link rel="stylesheet" href="' . asset_url($r) . '">';
    }
    return implode("\n    ", $out);
}

/**
 * Skrypty klasyczne (BEZ type="module"). Kolejnosc argumentow = kolejnosc
 * wykonania.
 *
 * Klasyczne, nie moduly, i to jest wymog twardy: deklaracje `function` na
 * najwyzszym poziomie musza wyladowac na `window`, bo tak je widzi
 * tests/harness.html (wola realne funkcje strony, zeby testy nie driftowaly
 * od kodu). Modul zamknalby je w swoim zakresie i suita padla by na
 * sanity-checku.
 *
 * Bez atrybutu `integrity`: hash pinowany w zrodle ma sens dla crypto.js,
 * ktory jest publikowany do niezaleznej weryfikacji (README). Dla wlasnych
 * plikow UI z tego samego origin co HTML nie wnosi ochrony - kto podmieni
 * plik, podmieni i hash w HTML - a wymusza recznie utrzymywany hash, ktory
 * przy rozjezdzie blokuje wykonanie skryptu.
 */
function asset_js(string ...$rel): string {
    $out = [];
    foreach ($rel as $r) {
        $out[] = '<script src="' . asset_url($r) . '"></script>';
    }
    return implode("\n", $out);
}
