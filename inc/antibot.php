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

function antibot_verify($a, $b, $exp, $token, $answer): bool {
    $a = (int)$a;
    $b = (int)$b;
    $exp = (int)$exp;
    if (!is_string($token) || $token === '') return false;
    if ($exp < time()) return false;                  // token wygasl
    if ($exp > time() + ANTIBOT_TTL + 60) return false; // exp z przyszlosci = falszerstwo
    $expected = hash_hmac('sha256', "$a|$b|$exp", antibot_secret());
    if (!hash_equals($expected, $token)) return false;
    return (int)$answer === $a + $b;
}
