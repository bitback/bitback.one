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
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 220 56" width="220" height="56" role="img" aria-label="$altEsc">
  <rect x="4" y="8" width="44" height="44" rx="22" fill="#f0c060"/>
  <g transform="translate(14,18) scale(0.83)" fill="none" stroke="#241500" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
    <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </g>
  <text x="60" y="38" font-family="Manrope, -apple-system, 'Segoe UI', sans-serif" font-size="26" font-weight="400" letter-spacing="-0.4" fill="#eef1f6">bitback</text>
  <text x="151" y="38" font-family="Manrope, -apple-system, 'Segoe UI', sans-serif" font-size="26" font-weight="700" fill="#25c2a8">.one</text>
</svg>
SVG;
    return '<h1 class="bb-logo"><a href="' . $hrefEsc . '">' . $svg . '</a></h1>';
}
