<?php
/**
 * API: nowy challenge antybotowy (math + HMAC token).
 * Uzywane przez index.php do odswiezenia pytania po wygenerowaniu linka
 * bez przeladowania strony.
 */

header('Content-Type: application/json; charset=utf-8');

require_once __DIR__ . '/../inc/config.php';
require_once __DIR__ . '/../inc/antibot.php';

echo json_encode(antibot_challenge());
