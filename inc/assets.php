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
