<?php
/**
 * Generator tokena API (wzorzec Stripe). Uruchamiany rzadko, recznie.
 *
 *   php tools/gen-api-token.php ["nazwa dla wlasnej referencji"]
 *
 * Drukuje:
 *   1) PELNY token do WRECZENIA osobie (raz, potem znika)
 *   2) jawne ID (do zmapowania osoba->id w LOKALNYCH docsach, NIE w pliku serwera)
 *   3) gotowa NAME-LESS linie do wklejenia do inc/api-tokens.txt: "id hash"
 *
 * ZERO-TRUST: plik serwera trzyma tylko "id  sha256(sekret)" - ZERO imion.
 * Imiona w pliku auth ujawnialyby, kto ma dostep (wyciek pliku = mapa tozsamosci).
 * Mapowanie osoba->id zyje osobno (lokalne docs / Keepass - id jest w tokenie).
 * Odwolanie tokena: skasuj jego linie z api-tokens.txt (niezalezne od innych).
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("Tylko CLI\n");
}

/*
 * Tryb bez wydruku tokena (dla sesji AI):
 *   php tools/gen-api-token.php --save-bb <klucz-bb-cs> ["nazwa"]
 * Token trafia prosto do `bb cs save <klucz>` (typ generic) i NIE jest drukowany;
 * drukuje sie tylko jawne ID i linia do inc/api-tokens.txt.
 */
$saveKey = null;
if (($argv[1] ?? '') === '--save-bb') {
    $saveKey = trim($argv[2] ?? '');
    if (!preg_match('/^[a-z0-9-]+$/', $saveKey)) exit("Podaj klucz bb cs [a-z0-9-] po --save-bb\n");
    array_splice($argv, 1, 2);
}
$note = trim($argv[1] ?? '');  // opcjonalna nazwa - tylko do wydruku, NIE do pliku

$id     = bin2hex(random_bytes(4));  // 8 znakow hex, jawny handle
$secret = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');  // 256-bit base64url
$token  = "bbk_{$id}_{$secret}";
$hash   = hash('sha256', $secret);

if ($saveKey !== null) {
    $cmd = 'bb cs save ' . escapeshellarg($saveKey) . ' ' . escapeshellarg($token) . ' --type generic';
    exec($cmd . ' 2>&1', $out, $rc);
    if ($rc !== 0) exit("bb cs save nie powiodl sie (kod $rc); token nie zapisany\n");
    echo "Token zapisany w bb cs pod kluczem $saveKey (nie drukowany).\n";
    echo "ID publiczne: $id\n";
    echo "LINIA do inc/api-tokens.txt: $id  $hash\n";
    echo "Odwolanie: skasuj te linie z inc/api-tokens.txt.\n";
    exit(0);
}

echo "\n";
if ($note !== '') echo "# dla: $note   (NIE zapisujemy tego w pliku serwera)\n\n";
echo "=== TOKEN (wrecz osobie / do Keepass, zapisz teraz - nie da sie odtworzyc) ===\n";
echo "$token\n\n";
echo "=== ID publiczne (do mapy osoba->id w LOKALNYCH docsach) ===\n";
echo "$id\n\n";
echo "=== LINIA do inc/api-tokens.txt (name-less, wklej) ===\n";
echo "$id  $hash\n\n";
echo "Odwolanie: skasuj te linie z inc/api-tokens.txt.\n";
