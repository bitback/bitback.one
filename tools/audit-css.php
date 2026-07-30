<?php
/**
 * Audyt CSS: co jest martwe i ile wagi zjada warstwa dekoracyjna.
 *
 * Usage: php tools/audit-css.php
 *
 * Po co: przy upraszczaniu wygladu trzeba wiedziec, ktore reguly mozna skasowac
 * bez ryzyka, a ktore tylko wygladaja na nieuzywane, bo dotycza stanu, ktory
 * pojawia sie po interakcji (wynik generowania, wklejona tabela, oznaczony
 * sekret). Przegladarkowe "unused CSS" tego nie rozroznia i klamie.
 *
 * Metoda: klasa uznana za martwa, gdy jej nazwa NIE wystepuje w zadnym zrodle,
 * ktore moze ja nadac - szablonach PHP ani skryptach. Szukamy nazwy, nie
 * atrybutu class, bo klasy sa nadawane tez dynamicznie (classList, sklejany HTML).
 */

$root = dirname(__DIR__);

$cssFiles = array_merge(
    glob($root . '/assets/css/*.css'),
    glob($root . '/assets/*.css')
);
sort($cssFiles);

$srcFiles = array_merge(
    glob($root . '/*.php'),
    glob($root . '/inc/*.php'),
    glob($root . '/api/*.php'),
    glob($root . '/assets/js/*.js'),
    glob($root . '/*.js')
);
$src = '';
foreach ($srcFiles as $f) {
    $src .= file_get_contents($f) . "\n";
}

/** Czysci arkusz z tego, co nie jest selektorem: komentarze i url(). */
function css_selectors_only(string $css): string {
    $css = preg_replace('!/\*.*?\*/!s', ' ', $css);
    $css = preg_replace('/url\([^)]*\)/i', ' ', $css);
    return $css;
}

$deadTotal = 0;
$declTotal = 0;
$rows = [];
$deadPerFile = [];

foreach ($cssFiles as $cssFile) {
    $clean = css_selectors_only(file_get_contents($cssFile));
    preg_match_all('/\.(-?[_a-zA-Z][_a-zA-Z0-9-]*)/', $clean, $m);
    $classes = array_values(array_unique($m[1]));

    $dead = [];
    foreach ($classes as $c) {
        // Granica znakiem niedozwolonym w nazwie klasy: samo \b nie wystarcza,
        // bo nazwa z myslnikiem jest podciagiem dluzszej (bb-card w bb-card-secret).
        $re = '/(?<![-_a-zA-Z0-9])' . preg_quote($c, '/') . '(?![-_a-zA-Z0-9])/';
        if (!preg_match($re, $src)) {
            $dead[] = $c;
        }
    }

    $declTotal += count($classes);
    $deadTotal += count($dead);
    $rows[] = [basename($cssFile), count($classes), count($dead), round(filesize($cssFile) / 1024, 1)];
    if ($dead) {
        $deadPerFile[basename($cssFile)] = $dead;
    }
}

echo "MARTWE KLASY (zadeklarowane w arkuszu, nieuzywane w zadnym zrodle)\n";
echo str_repeat('-', 60) . "\n";
printf("%-20s %6s %9s %7s\n", 'arkusz', 'klas', 'martwych', 'KB');
foreach ($rows as $r) {
    printf("%-20s %6d %9d %7s\n", $r[0], $r[1], $r[2], $r[3]);
}
echo str_repeat('-', 60) . "\n";
printf("RAZEM %d klas, %d martwych (%.0f%%)\n\n",
    $declTotal, $deadTotal, $declTotal ? 100 * $deadTotal / $declTotal : 0);

foreach ($deadPerFile as $file => $dead) {
    echo "  $file: " . implode(', ', $dead) . "\n";
}

// --- ile wagi to dekoracja ---
$all = '';
foreach ($cssFiles as $f) { $all .= file_get_contents($f) . "\n"; }

$features = [
    'bloki @keyframes'          => '@keyframes',
    'animation / transition'    => 'animation:|animation-|transition:',
    'box-shadow (poswiaty)'     => 'box-shadow',
    'gradienty'                 => 'gradient',
    'filter / blur'             => 'filter:|blur\(',
    'bb-art (bitmapy naroznikow)' => 'bb-art',
    'bb-chip (ikony w kolach)'  => 'bb-chip',
    'clip-path (lamane ramki)'  => 'clip-path',
    'bb-rise (wjazdy)'          => 'bb-rise',
];

// --- zmienne: ile ich jest, ile realnie roznych wartosci, co nieuzywane ---
$tokens = $root . '/assets/tokens.css';
if (is_file($tokens)) {
    $tok = css_selectors_only(file_get_contents($tokens));
    preg_match_all('/(--bb-[a-z0-9-]+)\s*:\s*([^;]+);/i', $tok, $vm, PREG_SET_ORDER);

    $decl = [];
    foreach ($vm as $v) { $decl[$v[1]] = trim($v[2]); }

    // uzycia liczone w CALYM CSS (tokens tez - zmienna moze budowac inna)
    $useIn = '';
    foreach ($cssFiles as $f) { $useIn .= file_get_contents($f); }
    $unused = $usedOnce = [];
    foreach ($decl as $name => $val) {
        $n = preg_match_all('/var\(\s*' . preg_quote($name, '/') . '\s*[,)]/i', $useIn);
        if ($n === 0) { $unused[] = $name; }
        elseif ($n === 1) { $usedOnce[] = $name; }
    }

    // te same wartosci pod roznymi nazwami = zbedne aliasy
    $byVal = [];
    foreach ($decl as $name => $val) { $byVal[strtolower($val)][] = $name; }
    $dupes = array_filter($byVal, fn($names) => count($names) > 1);

    echo "\nZMIENNE (assets/tokens.css)\n";
    echo str_repeat('-', 60) . "\n";
    printf("%-34s %d\n", 'zadeklarowanych', count($decl));
    printf("%-34s %d\n", 'roznych wartosci', count($byVal));
    printf("%-34s %d\n", 'nieuzywanych w zadnym arkuszu', count($unused));
    printf("%-34s %d\n", 'uzytych DOKLADNIE raz', count($usedOnce));
    printf("%-34s %d\n", 'grup o identycznej wartosci', count($dupes));

    if ($dupes) {
        echo "\n  Ta sama wartosc pod roznymi nazwami (kandydaci na jeden token):\n";
        foreach ($dupes as $val => $names) {
            echo '    ' . $val . '  <-  ' . implode(', ', $names) . "\n";
        }
    }
    if ($unused) {
        echo "\n  Nieuzywane: " . implode(', ', $unused) . "\n";
    }
    if ($usedOnce) {
        echo "\n  Uzyte raz (kandydaci do wpisania wprost albo scalenia):\n    "
            . implode(', ', $usedOnce) . "\n";
    }
}

echo "\nWARSTWA DEKORACYJNA (liczba wystapien)\n";
echo str_repeat('-', 60) . "\n";
printf("%-30s %s\n", 'linii CSS razem', substr_count($all, "\n"));
foreach ($features as $label => $re) {
    printf("%-30s %d\n", $label, preg_match_all('/' . $re . '/i', $all));
}
