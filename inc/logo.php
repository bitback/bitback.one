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
  <defs>
    <linearGradient id="bbGold" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#ffe48a"/>
      <stop offset="55%" stop-color="#f0c060"/>
      <stop offset="100%" stop-color="#c8902e"/>
    </linearGradient>
    <linearGradient id="bbWord" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#ffffff"/>
      <stop offset="100%" stop-color="#cccccc"/>
    </linearGradient>
  </defs>
  <rect x="4" y="8" width="44" height="44" rx="11" fill="#0a0a0a" stroke="#252520"/>
  <g transform="translate(14,18) scale(0.83)" fill="none" stroke="url(#bbGold)" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round">
    <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </g>
  <text x="60" y="38" font-family="Geist, -apple-system, 'Segoe UI', sans-serif" font-size="26" font-weight="300" letter-spacing="-0.4" fill="url(#bbWord)">bitback</text>
  <text x="149" y="38" font-family="Geist, -apple-system, 'Segoe UI', sans-serif" font-size="26" font-weight="400" fill="url(#bbGold)">.one</text>
</svg>
SVG;
    return '<h1 class="bb-logo"><a href="' . $hrefEsc . '">' . $svg . '</a></h1>';
}
