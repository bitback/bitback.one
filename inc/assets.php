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
 * Wyspa danych dla skryptow strony: wartosci z PHP jada JSON-em, a nie
 * interpolacja do kodu. Dzieki temu pliki .js sa w pelni statyczne
 * (cache'owalne) i zaden tekst z serwera nie trafia do kontekstu
 * wykonywalnego.
 *
 * JSON_HEX_TAG jest tu istotny: bez niego wartosc zawierajaca sekwencje
 * zamykajaca tag script rozerwalaby wyspe, a reszta JSON-a wyladowalaby
 * w HTML jako tresc.
 */
function json_island(string $id, array $data): string {
    return '<script type="application/json" id="' . htmlspecialchars($id) . '">'
        . json_encode($data, JSON_HEX_TAG | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
        . '</script>';
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
