<?php
/**
 * Logo bitback.one - inline SVG.
 *
 * Uzywamy inline SVG (nie <img src>) bo SVG w <img> nie dziedziczy
 * fontow strony - Geist z Google Fonts nie dochodzi do izolowanego SVG,
 * przegladarka uzywa fallback system fontu ktory ma inna szerokosc
 * i rozwala odstep "bitback    .one".
 */

function render_logo(string $alt = 'bitback.one', string $href = '/'): string {
    $altEsc = htmlspecialchars($alt);
    $hrefEsc = htmlspecialchars($href);
    $svg = <<<SVG
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 158 56" width="158" height="56" role="img" aria-label="$altEsc">
  <text x="0" y="38" font-family="Manrope, -apple-system, 'Segoe UI', sans-serif" font-size="26" font-weight="400" letter-spacing="-0.4" fill="#eef1f6">bitback</text>
  <text x="91" y="38" font-family="Manrope, -apple-system, 'Segoe UI', sans-serif" font-size="26" font-weight="700" fill="#25c2a8">.one</text>
</svg>
SVG;
    return '<h1 class="bb-logo"><a href="' . $hrefEsc . '">' . $svg . '</a></h1>';
}
