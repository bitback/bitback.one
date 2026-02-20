<?php
/**
 * Szyfrowanie AES-256-CBC
 * Klucz = hex string z URL (32 znaki = 16 bajtów, rozszerzamy SHA-256)
 */

function encrypt_secret(string $plaintext, string $hexKey): string {
    $key = hash('sha256', $hexKey, true); // 32 bajty
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($plaintext, CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);
    // iv + encrypted → base64
    return base64_encode($iv . $encrypted);
}

function decrypt_secret(string $blob, string $hexKey): ?string {
    $key = hash('sha256', $hexKey, true);
    $raw = base64_decode($blob);
    if ($raw === false || strlen($raw) < 17) return null;
    $iv = substr($raw, 0, 16);
    $encrypted = substr($raw, 16);
    $decrypted = openssl_decrypt($encrypted, CIPHER_METHOD, $key, OPENSSL_RAW_DATA, $iv);
    return $decrypted === false ? null : $decrypted;
}

/**
 * Szyfruj cały payload (JSON sections array) jednym kluczem
 */
function encrypt_payload(array $sections, string $hexKey): string {
    $json = json_encode($sections, JSON_UNESCAPED_UNICODE);
    return encrypt_secret($json, $hexKey);
}

/**
 * Deszyfruj cały payload → array sections
 */
function decrypt_payload(string $blob, string $hexKey): ?array {
    $json = decrypt_secret($blob, $hexKey);
    if ($json === null) return null;
    $data = json_decode($json, true);
    return is_array($data) ? $data : null;
}

function generate_key(): string {
    return bin2hex(random_bytes(16)); // 32 hex znaków
}

function generate_uuid(): string {
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // version 4
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // variant
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}
