<?php
/**
 * Math antibot - challenge generowany i weryfikowany SERWEROWO.
 *
 * Poprzednia wersja ufala klientowi (klient wysylal math_expected
 * i math_answer, serwer tylko je porownywal) - bot mogl wyslac 5/5
 * i przejsc bez liczenia. Teraz serwer podpisuje challenge HMAC-em:
 * bot musi najpierw pobrac challenge (round-trip), a token wygasa.
 *
 * Stateless (bez sesji/plikow): token = HMAC(a|b|exp, secret).
 * To nadal speed bump, nie CAPTCHA - swiadomie. Rate limit robi reszte.
 */

define('ANTIBOT_TTL', 900); // 15 min waznosci challenge
// Po tylu sekundach klient traktuje pytanie jako stare i pobiera nowe w tle.
// Zapas do ANTIBOT_TTL jest celowy: user ma czas odpowiedziec na swieze pytanie.
define('ANTIBOT_REFRESH_AFTER', 600); // 10 min

function antibot_secret(): string {
    // Klucz HMAC pochodny od IP_HASH_SALT - bez nowej stalej w config.php
    return hash('sha256', IP_HASH_SALT . '|antibot-v1');
}

function antibot_challenge(): array {
    $a = random_int(1, 15);
    $b = random_int(1, 15);
    $exp = time() + ANTIBOT_TTL;
    $token = hash_hmac('sha256', "$a|$b|$exp", antibot_secret());
    return ['a' => $a, 'b' => $b, 'exp' => $exp, 'token' => $token];
}

/**
 * Powod odmowy, nie samo tak/nie. Klient rozni komunikat: wygasle pytanie to
 * nie jest blad usera i nie wolno mu mowic "nieprawidlowa odpowiedz".
 *
 * Zwraca: 'ok' | 'expired' (podpis dobry, ale czas minal) |
 *         'invalid' (brak/falszywy podpis) | 'wrong' (zla suma).
 * Rozroznienie 'invalid' od 'wrong' zostaje w serwerze - klient dostaje
 * jeden komunikat, zeby bot nie odczytal ktory element podrobil zle.
 */
function antibot_reason($a, $b, $exp, $token, $answer): string {
    $a = (int)$a;
    $b = (int)$b;
    $exp = (int)$exp;
    if (!is_string($token) || $token === '') return 'invalid';
    if ($exp > time() + ANTIBOT_TTL + 60) return 'invalid'; // exp z przyszlosci = falszerstwo
    $expected = hash_hmac('sha256', "$a|$b|$exp", antibot_secret());
    if (!hash_equals($expected, $token)) return 'invalid';
    // Kolejnosc ma znaczenie: 'expired' orzekamy dopiero po sprawdzeniu podpisu,
    // inaczej bot dostalby potwierdzenie waznosci dowolnego zmyslonego exp.
    if ($exp < time()) return 'expired';
    return ((int)$answer === $a + $b) ? 'ok' : 'wrong';
}

function antibot_verify($a, $b, $exp, $token, $answer): bool {
    return antibot_reason($a, $b, $exp, $token, $answer) === 'ok';
}
