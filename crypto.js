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

/* ============================================================
 * v3 (format 3): haslo otwarcia bez plaintextu do serwera.
 * Lancuch: master = PBKDF2-HMAC-SHA256(NFC(password), "bb3|"+hexKey, iter)
 *          aesKey = HKDF(master, info="bb3-enc")   -> AES-256-GCM
 *          authTag= HKDF(master, info="bb3-auth")  -> jedyne co idzie do serwera
 * Bez hasla: aesKey = HKDF(SHA-256("bb3|"+hexKey), info="bb3-enc").
 * Serwer przechowuje sha256(authTag); z authTag nie da sie cofnac do master,
 * wiec serwer nigdy nie ma materialu klucza.
 * ============================================================ */

// var, nie const: w classic script tylko `var` laduje jako wlasciwosc window,
// a stala musi byc czytelna z zewnatrz (harness testowy przez contentWindow).
var V3_ITER = 600000;

function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

async function hkdf256(ikmBytes, infoStr) {
    const key = await crypto.subtle.importKey('raw', ikmBytes, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(infoStr) },
        key, 256
    );
    return new Uint8Array(bits);
}

async function deriveMasterV3(password, hexKey, iterations) {
    const pw = new TextEncoder().encode(password.normalize('NFC'));
    const salt = new TextEncoder().encode('bb3|' + hexKey.toLowerCase());
    const key = await crypto.subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iterations },
        key, 256
    );
    return new Uint8Array(bits);
}

async function authTagFromMaster(master) {
    return bytesToHex(await hkdf256(master, 'bb3-auth'));
}

async function aesKeyFromMaster(master) {
    const keyBytes = await hkdf256(master, 'bb3-enc');
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function aesKeyNoPassV3(hexKey) {
    const ikm = await sha256(new TextEncoder().encode('bb3|' + hexKey.toLowerCase()));
    const keyBytes = await hkdf256(ikm, 'bb3-enc');
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptBlobV3(sections, aesKey) {
    const plaintext = new TextEncoder().encode(JSON.stringify(sections));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, plaintext);
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return btoa(String.fromCharCode(...combined));
}

async function decryptBlobV3(base64Blob, aesKey) {
    const raw = Uint8Array.from(atob(base64Blob), c => c.charCodeAt(0));
    if (raw.length < 29) throw new Error('Invalid payload'); // iv12 + tag16 + min 1B
    const iv = raw.slice(0, 12);
    const ciphertext = raw.slice(12);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, aesKey, ciphertext);
    const items = JSON.parse(new TextDecoder().decode(decrypted));
    if (!Array.isArray(items)) throw new Error('Invalid data');
    return items;
}
