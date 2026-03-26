/**
 * bitback.one - Client-side cryptographic functions
 *
 * This file contains ALL encryption and decryption logic.
 * It is loaded with Subresource Integrity (SRI) to guarantee
 * that no deployment serves modified cryptographic code.
 *
 * Verify this file against the official hash published at:
 * https://github.com/bitback/bitback.one#crypto-integrity-verification
 *
 * Quick check:
 *   curl -s https://YOUR-DEPLOYMENT/crypto.js | openssl dgst -sha384 -binary | openssl base64 -A
 *   Compare with the hash in the GitHub README.
 */

/**
 * Generate a random 128-bit hex key (32 hex chars).
 * Used as the encryption key, placed in URL #fragment.
 */
function generateHexKey() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * SHA-256 hash of arbitrary data.
 * Used for key derivation (hex string -> 256-bit key).
 */
async function sha256(data) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

/**
 * Encrypt an array of sections into a base64 blob.
 * Format: IV (16 bytes) + AES-256-CBC ciphertext -> base64
 *
 * @param {Array} sections - Array of {content, secret} objects
 * @param {string} hexKey - 32-char hex key from generateHexKey()
 * @returns {string} Base64-encoded encrypted blob
 */
async function encryptBlob(sections, hexKey) {
    const json = JSON.stringify(sections);
    const plaintext = new TextEncoder().encode(json);
    const keyBytes = await sha256(new TextEncoder().encode(hexKey));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const cryptoKey = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']
    );
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-CBC', iv: iv }, cryptoKey, plaintext
    );
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return btoa(String.fromCharCode(...combined));
}

/**
 * Decrypt a base64 blob back into an array of sections.
 *
 * @param {string} base64Blob - Base64-encoded IV+ciphertext
 * @param {string} hexKey - 32-char hex key from URL #fragment
 * @returns {Array} Array of {content, secret} objects
 * @throws {Error} If payload is invalid or decryption fails
 */
async function decryptBlob(base64Blob, hexKey) {
    const keyBytes = await sha256(new TextEncoder().encode(hexKey));
    const raw = Uint8Array.from(atob(base64Blob), c => c.charCodeAt(0));
    if (raw.length < 17) throw new Error('Invalid payload');

    const iv = raw.slice(0, 16);
    const ciphertext = raw.slice(16);

    const cryptoKey = await crypto.subtle.importKey(
        'raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv: iv }, cryptoKey, ciphertext
    );

    const json = new TextDecoder().decode(decrypted);
    const items = JSON.parse(json);
    if (!Array.isArray(items)) throw new Error('Invalid data');
    return items;
}
