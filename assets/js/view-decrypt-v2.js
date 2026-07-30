// Dane z serwera przychodza wyspa JSON w HTML (patrz json_island()).
const V = JSON.parse(document.getElementById('bb-view').textContent);
const ENCRYPTED_PAYLOAD = V.payload;
const TOTP_STRINGS = V.totp;
const SECRETS_EXPIRED = V.secretsExpired;

(async function() {
    const loadingBox = document.getElementById('loadingBox');
    const contentBox = document.getElementById('contentBox');
    const errorBox = document.getElementById('errorBox');
    try {
        const hexKey = window.location.hash.substring(1);
        if (!hexKey || !/^[0-9a-f]{32}$/i.test(hexKey)) {
            throw new Error(V.noKeyError);
        }
        const keyBytes = await sha256(new TextEncoder().encode(hexKey));
        const raw = Uint8Array.from(atob(ENCRYPTED_PAYLOAD), c => c.charCodeAt(0));
        const iv = raw.slice(0, 16);
        const ciphertext = raw.slice(16);
        const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, cryptoKey, ciphertext);
        const sections = JSON.parse(new TextDecoder().decode(decrypted));
        let html = '';
        for (const s of sections) {
            const escaped = escapeHtml(s.content);
            if (s.type === 'secret') {
                html += SECRETS_EXPIRED ? '<span class="s-masked">●●●●●●</span>' : '<span class="s-secret">' + linkify(escaped) + '</span>';
            } else {
                html += '<span class="s-text">' + linkify(escaped) + '</span>';
            }
        }
        loadingBox.style.display = 'none';
        contentBox.innerHTML = html;
        contentBox.style.display = 'block';
        if (window.BBTotp) BBTotp.scan(contentBox, document.getElementById('totpZone'), TOTP_STRINGS);
    } catch (err) {
        loadingBox.style.display = 'none';
        errorBox.textContent = err.message;
        errorBox.style.display = 'block';
    }
})();
