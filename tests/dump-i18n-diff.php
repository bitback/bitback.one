<?php
/**
 * Zrzuca do pliku (argv[1], UTF-8, JSON) te wartosci PL ze slownika i18n,
 * ktore ROZNIA sie od odpowiednika EN - czyli realnie przetlumaczone frazy.
 * Uzywane przez verify-en.ps1 jako blocklist: zadna z nich nie moze wystapic
 * w renderze ?lang=en. Zapis do pliku (nie echo) omija psucie UTF-8 na stdout
 * PowerShell 5.1.
 */
require_once __DIR__ . '/../inc/i18n.php';

$pl = get_strings('pl');
$en = get_strings('en');
$out = [];
foreach ($pl as $k => $v) {
    if (!is_string($v)) continue;
    if (!isset($en[$k]) || $en[$k] !== $v) {
        $out[$k] = $v;
    }
}
$path = $argv[1] ?? (__DIR__ . '/output/i18n-pl-diff.json');
file_put_contents($path, json_encode($out, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
echo "wrote " . count($out) . " PL-only strings to $path\n";
