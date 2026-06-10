<?php
/**
 * Inline SVG ikony (Lucide, licencja ISC) - zero zaleznosci zewnetrznych.
 *
 * Wczesniej ikony renderowal lucide.min.js z unpkg CDN (402 KB JS dla
 * 5 ikon + supply-chain hole: @latest bez SRI na stronie deszyfrujacej
 * sekrety). Inline SVG = zero requestow, zero flash-of-no-icons.
 *
 * Atrybut data-lucide zostaje na <svg>, wiec caly istniejacy CSS
 * ([data-lucide] { ... }) dziala identycznie jak po lucide.createIcons().
 */

function bb_icon(string $name): string {
    static $paths = [
        'lock'    => '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
        'clock'   => '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
        'monitor' => '<rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>',
        'check'   => '<path d="M20 6 9 17l-5-5"/>',
        'ghost'   => '<path d="M9 10h.01"/><path d="M15 10h.01"/><path d="M12 2a8 8 0 0 0-8 8v12l3-3 2.5 2.5L12 19l2.5 2.5L17 19l3 3V10a8 8 0 0 0-8-8z"/>',
    ];
    if (!isset($paths[$name])) {
        return '';
    }
    return '<svg data-lucide="' . $name . '" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        . 'fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" '
        . 'aria-hidden="true">' . $paths[$name] . '</svg>';
}
