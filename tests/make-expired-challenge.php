<?php
/**
 * Fixture dla test-endpoint.ps1: wypisuje JSON z POPRAWNIE podpisanym, ale juz
 * przeterminowanym challenge. Sekret HMAC pochodzi z inc/config.php, wiec token
 * jest wazny dla tego samego serwera, ktory obsluguje testy.
 *
 * Po co osobny plik: PowerShell nie zna soli, a przepisanie HMAC-a do testu
 * duplikowaloby logike serwera i przestaloby wykrywac jej zmiane.
 */

require_once __DIR__ . '/../inc/config.php';
require_once __DIR__ . '/../inc/antibot.php';

$a = 3;
$b = 4;
$exp = time() - 1; // wygaslo sekunde temu
echo json_encode([
    'a' => $a,
    'b' => $b,
    'exp' => $exp,
    'token' => hash_hmac('sha256', "$a|$b|$exp", antibot_secret()),
    'answer' => $a + $b,
]);
