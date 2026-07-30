// Dane z serwera przychodza wyspa JSON w HTML (patrz json_island()).
const G = JSON.parse(document.getElementById('bb-gate').textContent);
// v3: haslo NIE opuszcza przegladarki. Liczymy master (PBKDF2, ~0.3-1s),
// wysylamy tylko authTag; master laduje w sessionStorage dla strony widoku
// (kasowany tam natychmiast po odczycie).
const SLUG = G.slug;
const ITER = G.iter;
const form = document.getElementById('pwdForm');
form.addEventListener('submit', async function(ev) {
    ev.preventDefault();
    const btn = document.getElementById('pwdBtn');
    const errBox = document.getElementById('jsError');
    errBox.style.display = 'none';
    const hexKey = window.location.hash.substring(1);
    if (!/^[0-9a-f]{32}$/i.test(hexKey)) {
        errBox.textContent = G.t.wrongOrCorrupt;
        errBox.style.display = 'block';
        return;
    }
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = G.t.checking;
    try {
        const master = await deriveMasterV3(document.getElementById('pwdInput').value.trim(), hexKey, ITER);
        document.getElementById('authTag').value = await authTagFromMaster(master);
        try { sessionStorage.setItem('bb3m:' + SLUG, bytesToHex(master)); } catch (e) { /* tryb prywatny - fallback na stronie widoku */ }
        form.action = '/' + SLUG + window.location.hash;
        form.submit(); // programowy submit nie odpala tego handlera ponownie
    } catch (e) {
        btn.disabled = false;
        btn.textContent = originalText;
        errBox.textContent = G.t.wrongOrCorrupt;
        errBox.style.display = 'block';
    }
});
