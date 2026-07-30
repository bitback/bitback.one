<?php
/**
 * Audyt palety: wszystkie kolory z CSS przeliczone na HSL i pogrupowane po
 * odcieniu (hue).
 *
 * Usage: php tools/audit-colors.php
 *
 * Po co: "za duzo zielonych" to nie kwestia gustu, tylko mierzalny fakt - dwa
 * zielone o roznym nasyceniu czytaja sie jako dwa niespokrewnione kolory.
 * Narzedzie pokazuje rozrzut nasycenia i jasnosci W OBREBIE jednego odcienia;
 * to on odpowiada za wrazenie balaganu, nie sama liczba odcieni.
 */

$root = dirname(__DIR__);

function hex_to_rgb(string $h): array {
    $h = ltrim($h, '#');
    if (strlen($h) === 3) { $h = $h[0].$h[0].$h[1].$h[1].$h[2].$h[2]; }
    return [hexdec(substr($h,0,2)), hexdec(substr($h,2,2)), hexdec(substr($h,4,2))];
}

/** RGB 0-255 -> HSL (h 0-360, s 0-100, l 0-100). */
function rgb_to_hsl(int $r, int $g, int $b): array {
    $r /= 255; $g /= 255; $b /= 255;
    $max = max($r,$g,$b); $min = min($r,$g,$b);
    $l = ($max + $min) / 2;
    $d = $max - $min;
    if ($d == 0) { return [0, 0, round($l*100)]; }
    $s = $l > 0.5 ? $d / (2 - $max - $min) : $d / ($max + $min);
    if ($max == $r)      { $h = fmod((($g - $b) / $d + ($g < $b ? 6 : 0)), 6); }
    elseif ($max == $g)  { $h = ($b - $r) / $d + 2; }
    else                 { $h = ($r - $g) / $d + 4; }
    return [round($h * 60), round($s*100), round($l*100)];
}

/** Nazwa rodziny odcienia - zeby raport czytal sie bez patrzenia na stopnie. */
function hue_name(int $h, int $s): string {
    if ($s < 12) { return 'neutralny (szarosc)'; }
    if ($h < 15 || $h >= 345) return 'czerwony';
    if ($h < 45)  return 'pomaranczowy / zloty';
    if ($h < 70)  return 'zolty';
    if ($h < 100) return 'zielony-zolty';
    if ($h < 150) return 'zielony';
    if ($h < 175) return 'zielony-turkus';
    if ($h < 200) return 'turkus / cyan';
    if ($h < 250) return 'niebieski';
    if ($h < 290) return 'fiolet';
    return 'magenta / roz';
}

$files = array_merge(glob($root.'/assets/css/*.css'), glob($root.'/assets/*.css'));
$found = [];   // hex => ['hsl'=>..., 'places'=>[]]

foreach ($files as $f) {
    $css = preg_replace('!/\*.*?\*/!s', ' ', file_get_contents($f));
    $name = basename($f);

    // #rrggbb / #rgb
    if (preg_match_all('/#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b/', $css, $m)) {
        foreach ($m[0] as $hex) {
            $k = strtolower($hex);
            $found[$k]['places'][$name] = ($found[$k]['places'][$name] ?? 0) + 1;
        }
    }
    // rgba(r, g, b, a) - alpha ignorowana, liczy sie odcien
    if (preg_match_all('/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/', $css, $m, PREG_SET_ORDER)) {
        foreach ($m as $s) {
            $k = sprintf('#%02x%02x%02x', (int)$s[1], (int)$s[2], (int)$s[3]);
            $found[$k]['places'][$name] = ($found[$k]['places'][$name] ?? 0) + 1;
        }
    }
}

// grupuj po rodzinie odcienia
$fam = [];
foreach ($found as $hex => $d) {
    [$r,$g,$b] = hex_to_rgb($hex);
    [$h,$s,$l] = rgb_to_hsl($r,$g,$b);
    $total = array_sum($d['places']);
    $fam[hue_name($h,$s)][] = ['hex'=>$hex,'h'=>$h,'s'=>$s,'l'=>$l,'n'=>$total,'gdzie'=>$d['places']];
}
uasort($fam, fn($a,$b) => count($b) <=> count($a));

echo "PALETA: kolory z CSS pogrupowane po odcieniu (HSL)\n";
echo str_repeat('=', 74) . "\n";

$hueCount = 0;
foreach ($fam as $family => $cols) {
    usort($cols, fn($a,$b) => $a['h'] <=> $b['h'] ?: $a['l'] <=> $b['l']);
    $hues = array_unique(array_column($cols, 'h'));
    $sats = array_column($cols, 's');
    if ($family !== 'neutralny (szarosc)') { $hueCount++; }

    printf("\n%s  - %d kolorow, hue %s, nasycenie %d-%d%%\n",
        strtoupper($family), count($cols),
        (count($hues) > 1 ? min($hues).'-'.max($hues).' st.' : reset($hues).' st.'),
        min($sats), max($sats));
    echo str_repeat('-', 74) . "\n";
    foreach ($cols as $c) {
        printf("  %-8s H%-4d S%-4d L%-4d  x%-3d %s\n",
            $c['hex'], $c['h'], $c['s'], $c['l'], $c['n'], implode(', ', array_keys($c['gdzie'])));
    }
}

echo "\n" . str_repeat('=', 74) . "\n";
printf("Kolorow razem: %d. Rodzin odcieni (bez szarosci): %d.\n", count($found), $hueCount);
echo "Sygnal balaganu: duzy rozrzut nasycenia w JEDNEJ rodzinie - te kolory\n";
echo "czytaja sie jako niespokrewnione, mimo tego samego odcienia.\n";
