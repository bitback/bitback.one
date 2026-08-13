<?php
/**
 * Audyt palety: wszystkie kolory ze wszystkich źródeł, przeliczone na HSL
 * i pogrupowane po odcieniu.
 *
 * Usage: php tools/audit-colors.php [--all]
 *
 * Po co: "za dużo zielonych" to nie kwestia gustu, tylko mierzalny fakt - dwa
 * zielone o różnym nasyceniu czytają się jako dwa niespokrewnione kolory.
 * Narzędzie pokazuje rozrzut nasycenia i jasności W OBRĘBIE jednego odcienia;
 * to on odpowiada za wrażenie bałaganu, nie sama liczba odcieni.
 *
 * ZAKRES: parsuje KAŻDĄ notację koloru CSS (hex 3/4/6/8, rgb/rgba, hsl/hsla,
 * obie składnie separatorów, nazwy kolorów) i rozwiązuje odwołania var() do
 * tokenów. Skanuje rekurencyjnie css/php/js/svg/html, nie samą listę arkuszy.
 * Powód takiego zakresu: paleta projektu jest zapisana w hsl() z kompozycją
 * tokenów (`hsl(var(--bb-h-secret) var(--bb-s-signal) 62%)`), a poprzednia
 * wersja narzędzia czytała wyłącznie hex i rgb z przecinkami - raportowała
 * 6 kolorów przy 68 zapisach hsl w arkuszach, czyli mierzyła resztki po
 * starej palecie zamiast palety obowiązującej.
 *
 * NIE OBEJMUJE (świadomie): kolorów rysowanych w czasie działania przez
 * bibliotekę kodu QR (canvas, czerń i biel), kolorów systemowych przeglądarki
 * oraz nazw kolorów użytych w komentarzach.
 */

$root = dirname(__DIR__);
$showAll = in_array('--all', $argv ?? [], true);

/* ------------------------------------------------------------------ kotwice */

/**
 * Elementy poza narzędziem, których zmiana unieważnia jego wynik. Sprawdzane
 * przy każdym uruchomieniu; rozjazd wypisuje instrukcję z chwili budowy.
 */
function anchors(string $root): array {
    return [
        [
            'co'      => 'plik tokenów jest źródłem palety',
            'jak'     => fn() => is_file($root.'/assets/tokens.css') ? 'jest' : 'BRAK',
            'oczek'   => 'jest',
            'gdy'     => 'Paleta przeniesiona gdzie indziej. Zaktualizuj listę źródeł tokenów.',
        ],
        [
            'co'      => 'notacja palety w tokenach',
            'jak'     => function () use ($root) {
                $css = @file_get_contents($root.'/assets/tokens.css');
                return $css !== false && preg_match('/hsl\(/i', $css) ? 'hsl' : 'inna';
            },
            'oczek'   => 'hsl',
            'gdy'     => 'Zmieniła się notacja palety (np. na oklch albo color()). Parser kolorów niżej trzeba rozszerzyć, inaczej narzędzie znowu oślepnie.',
        ],
        [
            'co'      => 'katalog arkuszy',
            'jak'     => fn() => is_dir($root.'/assets/css') ? 'jest' : 'BRAK',
            'oczek'   => 'jest',
            'gdy'     => 'Przeniesiono arkusze. Popraw korzeń skanowania.',
        ],
    ];
}

/* ------------------------------------------------- konwersje i nazewnictwo */

function clamp_num(float $v, float $lo, float $hi): float { return max($lo, min($hi, $v)); }

/** RGB 0-255 -> HSL (h 0-360, s 0-100, l 0-100). */
function rgb_to_hsl(int $r, int $g, int $b): array {
    $r /= 255; $g /= 255; $b /= 255;
    $max = max($r, $g, $b); $min = min($r, $g, $b);
    $l = ($max + $min) / 2;
    $d = $max - $min;
    if ($d == 0) { return [0, 0, (int)round($l * 100)]; }
    $s = $l > 0.5 ? $d / (2 - $max - $min) : $d / ($max + $min);
    if ($max == $r)      { $h = fmod((($g - $b) / $d + ($g < $b ? 6 : 0)), 6); }
    elseif ($max == $g)  { $h = ($b - $r) / $d + 2; }
    else                 { $h = ($r - $g) / $d + 4; }
    return [(int)round($h * 60), (int)round($s * 100), (int)round($l * 100)];
}

/** HSL (h 0-360, s/l 0-100) -> RGB 0-255. */
function hsl_to_rgb(float $h, float $s, float $l): array {
    $h = fmod(fmod($h, 360) + 360, 360) / 360; $s /= 100; $l /= 100;
    if ($s == 0) { $v = (int)round($l * 255); return [$v, $v, $v]; }
    $q = $l < 0.5 ? $l * (1 + $s) : $l + $s - $l * $s;
    $p = 2 * $l - $q;
    $conv = function ($t) use ($p, $q) {
        if ($t < 0) { $t += 1; } if ($t > 1) { $t -= 1; }
        if ($t < 1/6) { return $p + ($q - $p) * 6 * $t; }
        if ($t < 1/2) { return $q; }
        if ($t < 2/3) { return $p + ($q - $p) * (2/3 - $t) * 6; }
        return $p;
    };
    return [
        (int)round($conv($h + 1/3) * 255),
        (int)round($conv($h) * 255),
        (int)round($conv($h - 1/3) * 255),
    ];
}

/**
 * Odcień neutralny projektu czytany z tokenów. Powierzchnie, tekst i ramki
 * stoją na nim celowo i mają SZEROKI rozrzut nasycenia - bez tego wyjątku
 * rampa powierzchni wygląda jak bałagan i alarm dzwoni na stałe, przez co
 * przestaje cokolwiek znaczyć.
 */
function neutral_hue(array $vars): ?int {
    $v = $vars['--bb-h-neutral'] ?? null;
    return ($v !== null && preg_match('/-?\d+/', $v, $m)) ? (int)$m[0] : null;
}

function hue_name(int $h, int $s, ?int $neutral = null): string {
    if ($s < 12) { return 'neutralny (szarość)'; }
    if ($neutral !== null && abs($h - $neutral) <= 8) { return 'neutralny (powierzchnie)'; }
    if ($h < 15 || $h >= 345) return 'czerwony';
    if ($h < 45)  return 'pomarańczowy / złoty';
    if ($h < 70)  return 'żółty';
    if ($h < 100) return 'zielony-żółty';
    if ($h < 150) return 'zielony';
    if ($h < 175) return 'zielony-turkus';
    if ($h < 200) return 'turkus / cyan';
    if ($h < 250) return 'niebieski';
    if ($h < 290) return 'fiolet';
    return 'magenta / róż';
}

/** Nazwy kolorów CSS realnie spotykane w projektach tego typu. */
function named_colors(): array {
    return [
        'black' => [0,0,0], 'white' => [255,255,255], 'red' => [255,0,0],
        'green' => [0,128,0], 'blue' => [0,0,255], 'yellow' => [255,255,0],
        'orange' => [255,165,0], 'purple' => [128,0,128], 'gray' => [128,128,128],
        'grey' => [128,128,128], 'silver' => [192,192,192], 'gold' => [255,215,0],
        'teal' => [0,128,128], 'navy' => [0,0,128], 'lime' => [0,255,0],
        'aqua' => [0,255,255], 'cyan' => [0,255,255], 'magenta' => [255,0,255],
        'fuchsia' => [255,0,255], 'maroon' => [128,0,0], 'olive' => [128,128,0],
        'pink' => [255,192,203], 'brown' => [165,42,42], 'coral' => [255,127,80],
    ];
}

/* ------------------------------------------------------------------ źródła */

/** Rekurencyjny spis plików, w których może wystąpić kolor. */
function source_files(string $root): array {
    $out = [];
    // Poza paletą interfejsu z definicji: narzędzia (mają własne tablice barw),
    // testy (atrapy i znaczniki), dane runtime. Granica jest wypisywana
    // w wyniku, żeby nie była cichym założeniem.
    $skipDirs = ['tests', 'tools', 'data', 'trash', '.git', 'node_modules'];
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($it as $f) {
        if (!$f->isFile()) { continue; }
        $rel = ltrim(str_replace($root, '', $f->getPathname()), DIRECTORY_SEPARATOR);
        foreach ($skipDirs as $s) { if (str_starts_with($rel, $s)) { continue 2; } }
        $ext = strtolower($f->getExtension());
        if (!in_array($ext, ['css', 'php', 'js', 'svg', 'html'], true)) { continue; }
        $out[$rel] = $f->getPathname();
    }
    ksort($out);
    return $out;
}

/** Zdejmuje komentarze, żeby kolor wymieniony w komentarzu nie liczył się do palety. */
function strip_comments(string $src, string $ext): string {
    // Ogranicznik ~ celowo: wzorzec zawiera "!" w konstrukcji (?<! , a przy
    // ograniczniku "!" PHP ucina wzorzec w tym miejscu i zwraca null.
    $out = preg_replace('~/\*.*?\*/~s', ' ', $src);
    $src = $out ?? $src;
    if (in_array($ext, ['js', 'php'], true)) {
        // "//" tylko gdy nie jest częścią adresu (http://, //serwer)
        $out = preg_replace('~(?<![:/])//[^\n]*~', ' ', $src);
        $src = $out ?? $src;
    }
    if ($ext === 'php') {
        $out = preg_replace('~#[^\n]*~', ' ', $src);
        $src = $out ?? $src;
    }
    return $src;
}

/* ---------------------------------------------------------------- parsery */

/** Deklaracje zmiennych CSS ze WSZYSTKICH arkuszy, nie tylko z pliku tokenów. */
function collect_vars(array $files): array {
    $vars = [];
    foreach ($files as $rel => $path) {
        if (!str_ends_with($rel, '.css')) { continue; }
        $css = strip_comments((string)file_get_contents($path), 'css');
        if (preg_match_all('/(--[a-z0-9-]+)\s*:\s*([^;}]+)/i', $css, $m, PREG_SET_ORDER)) {
            foreach ($m as $s) { $vars[strtolower(trim($s[1]))] = trim($s[2]); }
        }
    }
    return $vars;
}

/** Rozwija var(--x, fallback) rekurencyjnie. */
function resolve_vars(string $value, array $vars, int $depth = 0): string {
    if ($depth > 8 || stripos($value, 'var(') === false) { return $value; }
    $out = preg_replace_callback('/var\(\s*(--[a-z0-9-]+)\s*(?:,([^()]*(?:\([^()]*\)[^()]*)*))?\)/i',
        function ($m) use ($vars) {
            $name = strtolower($m[1]);
            if (isset($vars[$name])) { return $vars[$name]; }
            return isset($m[2]) ? trim($m[2]) : 'currentColor';
        }, $value);
    return resolve_vars((string)$out, $vars, $depth + 1);
}

/**
 * Wyciąga wszystkie kolory z tekstu. Zwraca listę [r,g,b].
 * Obsługuje: #rgb #rgba #rrggbb #rrggbbaa, rgb()/rgba() i hsl()/hsla()
 * w obu składniach separatorów (przecinki oraz spacje z ukośnikiem), nazwy.
 */
function extract_colors(string $text, array $vars): array {
    $text = resolve_vars($text, $vars);
    $out = [];
    $num = '[-+]?[0-9]*\.?[0-9]+';

    if (preg_match_all('/#([0-9a-f]{3,8})\b/i', $text, $m)) {
        foreach ($m[1] as $h) {
            $len = strlen($h);
            if ($len === 3 || $len === 4) { $h = $h[0].$h[0].$h[1].$h[1].$h[2].$h[2]; }
            elseif ($len === 6 || $len === 8) { $h = substr($h, 0, 6); }
            else { continue; }
            $out[] = [hexdec(substr($h,0,2)), hexdec(substr($h,2,2)), hexdec(substr($h,4,2))];
        }
    }

    // rgb(R G B / a) oraz rgb(R, G, B, a); wartości też procentowe
    $re = '/rgba?\(\s*('.$num.')(%?)[\s,]+('.$num.')(%?)[\s,]+('.$num.')(%?)/i';
    if (preg_match_all($re, $text, $m, PREG_SET_ORDER)) {
        foreach ($m as $s) {
            $c = [];
            for ($i = 1; $i <= 5; $i += 2) {
                $v = (float)$s[$i];
                $c[] = (int)round(clamp_num($s[$i+1] === '%' ? $v * 2.55 : $v, 0, 255));
            }
            $out[] = $c;
        }
    }

    // hsl(H S% L% / a) oraz hsl(H, S%, L%, a)
    $re = '/hsla?\(\s*('.$num.')(?:deg)?[\s,]+('.$num.')%?[\s,]+('.$num.')%?/i';
    if (preg_match_all($re, $text, $m, PREG_SET_ORDER)) {
        foreach ($m as $s) {
            $out[] = hsl_to_rgb((float)$s[1], clamp_num((float)$s[2], 0, 100), clamp_num((float)$s[3], 0, 100));
        }
    }

    foreach (named_colors() as $name => $rgb) {
        if (preg_match_all('/(?<![-\w#])'.$name.'(?![-\w(])/i', $text, $mm)) {
            foreach ($mm[0] as $_) { $out[] = $rgb; }
        }
    }

    return $out;
}

/* ------------------------------------------------------------------ przebieg */

$files = source_files($root);
$vars  = collect_vars($files);

$found   = [];   // "r,g,b" => ['places' => [plik => n]]
$skipped = [];

foreach ($files as $rel => $path) {
    $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
    if (str_contains($rel, 'qrcode.min.js')) {
        $skipped[$rel] = 'biblioteka kodu QR - rysuje na canvasie, poza paletą interfejsu';
        continue;
    }
    if ($rel === 'browser.php') {
        $skipped[$rel] = 'lokalne narzędzie deweloperskie, wykluczone z wdrożenia - user tego nie ogląda';
        continue;
    }
    $src = strip_comments((string)file_get_contents($path), $ext);
    foreach (extract_colors($src, $vars) as $rgb) {
        $k = implode(',', $rgb);
        $found[$k]['places'][$rel] = ($found[$k]['places'][$rel] ?? 0) + 1;
    }
}

$fam = [];
foreach ($found as $key => $d) {
    [$r, $g, $b] = array_map('intval', explode(',', $key));
    [$h, $s, $l] = rgb_to_hsl($r, $g, $b);
    $fam[hue_name($h, $s, neutral_hue($vars))][] = [
        'hex'   => sprintf('#%02x%02x%02x', $r, $g, $b),
        'h' => $h, 's' => $s, 'l' => $l,
        'n'     => array_sum($d['places']),
        'gdzie' => $d['places'],
    ];
}
uasort($fam, fn($a, $b) => count($b) <=> count($a));

echo "PALETA: kolory ze wszystkich źródeł, pogrupowane po odcieniu (HSL)\n";
echo str_repeat('=', 74) . "\n";

if (!$found) {
    echo "\n0 kolorów znalezionych w " . count($files) . " plikach.\n";
    echo "To nie jest wynik neutralny: projekt z interfejsem MUSI mieć kolory,\n";
    echo "więc zero znaczy najpewniej zepsuty parser albo zły korzeń skanowania.\n";
}

$hueCount = 0;
$alarms = [];
foreach ($fam as $family => $cols) {
    usort($cols, fn($a, $b) => $a['h'] <=> $b['h'] ?: $a['l'] <=> $b['l']);
    $hues = array_unique(array_column($cols, 'h'));
    $sats = array_column($cols, 's');
    $spread = max($sats) - min($sats);
    $isGray = str_starts_with($family, 'neutralny');
    if (!$isGray) { $hueCount++; }
    if (!$isGray && $spread > 25 && count($cols) > 1) {
        $alarms[] = sprintf('%s: rozrzut nasycenia %d punktów (%d-%d%%) przy %d kolorach',
            $family, $spread, min($sats), max($sats), count($cols));
    }

    if (!$showAll && $isGray && count($cols) > 12) {
        printf("\n%s  - %d kolorów (pominięte w wykazie, --all pokazuje wszystkie)\n",
            $family, count($cols));
        continue;
    }

    printf("\n%s  - %d kolorów, hue %s, nasycenie %d-%d%%\n",
        $family, count($cols),
        (count($hues) > 1 ? min($hues) . '-' . max($hues) . ' st.' : reset($hues) . ' st.'),
        min($sats), max($sats));
    echo str_repeat('-', 74) . "\n";
    foreach ($cols as $c) {
        printf("  %-8s H%-4d S%-4d L%-4d  x%-3d %s\n",
            $c['hex'], $c['h'], $c['s'], $c['l'], $c['n'],
            implode(', ', array_slice(array_keys($c['gdzie']), 0, 4)));
    }
}

echo "\n" . str_repeat('=', 74) . "\n";
printf("Kolorów razem: %d. Rodzin odcieni (bez szarości): %d. Plików: %d.\n",
    count($found), $hueCount, count($files));

if ($alarms) {
    echo "\nSYGNAŁ BAŁAGANU - duży rozrzut nasycenia w JEDNEJ rodzinie.\n";
    echo "Te kolory czytają się jako niespokrewnione mimo tego samego odcienia:\n";
    foreach ($alarms as $a) { echo "  - $a\n"; }
} else {
    echo "\nRozrzut nasycenia w rodzinach: w normie.\n";
}

echo "\nPOMINIĘTE (granice zakresu, nie przeoczenia):\n";
echo "  - katalogi tests\\ i tools\\: atrapy testowe i własne tablice barw narzędzi\n";
foreach ($skipped as $rel => $why) { echo "  - $rel: $why\n"; }

$anchorProblems = [];
foreach (anchors($root) as $a) {
    $now = ($a['jak'])();
    if ($now !== $a['oczek']) {
        $anchorProblems[] = sprintf("  - %s: jest \"%s\", oczekiwano \"%s\"\n    %s", $a['co'], $now, $a['oczek'], $a['gdy']);
    }
}
if ($anchorProblems) {
    echo "\nUWAGA - ZAŁOŻENIA NARZĘDZIA SIĘ ROZJECHAŁY, wynik powyżej może kłamać:\n";
    echo implode("\n", $anchorProblems) . "\n";
}
