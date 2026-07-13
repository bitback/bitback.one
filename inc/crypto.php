<?php
/**
 * Crypto utilities
 *
 * ZERO-TRUST: szyfrowanie odbywa się wyłącznie w przeglądarce (Web Crypto API).
 * Serwer NIGDY nie widzi plaintextu ani klucza.
 *
 * Ten plik zawiera tylko:
 * - decrypt_* (do ewentualnego debugowania / migracji)
 * - generate_uuid
 */

function decrypt_secret(string $blob, string $hexKey): ?string {
    $key = hash('sha256', $hexKey, true);
    $raw = base64_decode($blob);
    if ($raw === false || strlen($raw) < 17) return null;
    $iv = substr($raw, 0, 16);
    $encrypted = substr($raw, 16);
    $decrypted = openssl_decrypt($encrypted, CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);
    return $decrypted === false ? null : $decrypted;
}

function decrypt_payload(string $blob, string $hexKey): ?array {
    $json = decrypt_secret($blob, $hexKey);
    if ($json === null) return null;
    $data = json_decode($json, true);
    return is_array($data) ? $data : null;
}

function generate_uuid(): string {
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // version 4
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // variant
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}
