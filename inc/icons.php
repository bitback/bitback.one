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
        'arrow-right' => '<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>',
        'eye'     => '<path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/>',
        'trash'   => '<path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/>',
        'shield-check' => '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
        'ghost'   => '<path d="M9 10h.01"/><path d="M15 10h.01"/><path d="M12 2a8 8 0 0 0-8 8v12l3-3 2.5 2.5L12 19l2.5 2.5L17 19l3 3V10a8 8 0 0 0-8-8z"/>',
    ];
    if (!isset($paths[$name])) {
        return '';
    }
    return '<svg data-lucide="' . $name . '" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        . 'fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" '
        . 'aria-hidden="true">' . $paths[$name] . '</svg>';
}
