// --- WSPOLNY PAYLOAD (pojedynczy link + bulk) ---
// Filtr pustych, przydzial gestego idx 0..N-1, podzial na text/secret,
// szyfrowanie oboma blobami. WYMAGA hexKey (encryptBlob go wymaga).
// total_sections MUSI = liczba sekcji po filtrze - view.php fillMasked
// maskuje po tej numeracji, rozjazd zepsulby maskowanie u odbiorcy.
async function sectionsToPayload(sections, aesKey) {
    const filtered = sections.filter(s => s.content.length > 0);
    const textSections = [];
    const secretSections = [];
    filtered.forEach((s, idx) => {
        const entry = { idx: idx, content: s.content };
        if (s.type === 'secret') {
            secretSections.push(entry);
        } else {
            textSections.push(entry);
        }
    });
    const encrypted_text = await encryptBlobV3(textSections, aesKey);
    const encrypted_secrets = secretSections.length > 0
        ? await encryptBlobV3(secretSections, aesKey)
        : null;
    return { encrypted_text, encrypted_secrets, total_sections: filtered.length };
}

// Generator hasla: 14 znakow z alfabetu bez homoglifow (a-z bez l, 2-9) ~ 65 bitow.
// Znaki z crypto.getRandomValues; wartosci >= 231 (7*33) odrzucane = zero modulo-bias.
function generatePassword() {
    const alphabet = 'abcdefghijkmnopqrstuvwxyz23456789'; // 33 znaki, bez l/0/1
    let out = '';
    while (out.length < 14) {
        const b = crypto.getRandomValues(new Uint8Array(1))[0];
        if (b < 231) out += alphabet[b % 33]; // 231 = 7*33 -> zero modulo-bias
    }
    document.getElementById('linkPassword').value = out;
    updateGuide();
}

// parseInt bezpieczne dla 0: "usun po 0 dni" (od razu) NIE moze wpasc w falsy || default.
function intOrDefault(id, def) {
    const v = parseInt(document.getElementById(id).value, 10);
    return Number.isNaN(v) ? def : v;
}

// v3: klucze per link. Z haslem: PBKDF2(haslo, salt="bb3|"+hexKey) -> master
// -> {aesKey (enc), authTag (do serwera)}. Bez hasla: HKDF z SHA-256("bb3|"+hexKey).
async function buildV3Keys(pwd, hexKey) {
    if (pwd) {
        const master = await deriveMasterV3(pwd, hexKey, V3_ITER);
        return { aesKey: await aesKeyFromMaster(master), authTag: await authTagFromMaster(master) };
    }
    return { aesKey: await aesKeyNoPassV3(hexKey), authTag: null };
}

// --- GENERUJ LINK ---
async function generateLink() {
    // honeypot
    const honeypot = document.querySelector('.ohnohoney').value;

    // treść
    const text = editor.textContent.trim();
    if (!text) {
        document.querySelector('.config-verify').classList.remove('bb-guide');
        editor.classList.remove('bb-flash');
        void editor.offsetWidth;
        editor.classList.add('bb-flash');
        return;
    }

    // math - brak wyboru: zamiast alertu glow prowadzi do weryfikacji
    if (selectedAnswer === null) {
        document.querySelector('.config-verify').classList.add('bb-guide');
        return;
    }
    document.querySelector('.generate-btn').classList.remove('bb-guide');

    // --- GALAZ BULK (korespondencja seryjna): N kluczy, jeden POST, N linkow ---
    // NIE uzywa extractSections - ma wlasny spinner/timeout/finally i return.
    if (isBulkMode()) {
        const recs = collectBulkRecords();
        // limit po stronie klienta - nie szyfruj nadmiaru zeby dostac 400 z serwera
        const BATCH_MAX = BB.batchMax;
        if (recs.length < 1) return; // same puste wiersze - nic do wygenerowania
        if (recs.length > BATCH_MAX) { alert((T.error_batch_too_many || '').replace('{max}', BATCH_MAX)); return; }
        const btn = document.querySelector('.generate-btn');
        const btnOriginalHTML = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span>' + (T.generating || 'Encrypting...');
        try {
            // osobny klucz AES-256 per rekord (zero-trust) - serwer nie widzi kluczy.
            // v3: PBKDF2 per rekord (salt=hexKey_i - anty-prekomputacja). crypto.subtle liczy
            // poza watkiem UI; chunki po 8 daja rownoleglosc bez zalewania pamieci.
            const pwd = document.getElementById('linkPassword').value.trim();
            const keys = new Array(recs.length), payloads = new Array(recs.length);
            const CONC = 8;
            let kdone = 0;
            for (let i = 0; i < recs.length; i += CONC) {
                await Promise.all(recs.slice(i, i + CONC).map(async (rec, j) => {
                    const idx = i + j;
                    const key = generateHexKey();
                    const v3 = await buildV3Keys(pwd, key);
                    const p = await sectionsToPayload(rec.sections, v3.aesKey);
                    keys[idx] = key;
                    payloads[idx] = { encrypted_text: p.encrypted_text, encrypted_secrets: p.encrypted_secrets, total_sections: p.total_sections, auth_tag: v3.authTag };
                    kdone++;
                }));
                btn.innerHTML = '<span class="spinner"></span>' + (T.generating || '') + ' ' + kdone + '/' + recs.length;
            }
            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), 15000);
            let resp;
            try {
                resp = await fetch('/api/create-batch.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    signal: ctrl.signal,
                    body: JSON.stringify({
                        website_url: honeypot,
                        expire_days: parseInt(document.getElementById('expireDays').value) || BB.defaults.expireDays,
                        max_views: parseInt(document.getElementById('maxViews').value) || BB.defaults.maxViews,
                        delete_after_days: intOrDefault('deleteDays', BB.defaults.deleteDays),
                        kdf: pwd ? { alg: 'PBKDF2-SHA256', iter: V3_ITER } : null,
                        math_a: CH.a, math_b: CH.b, math_exp: CH.exp, math_token: CH.token, math_answer: selectedAnswer,
                        records: payloads,
                    }),
                });
            } finally {
                clearTimeout(timer);
            }
            const result = await resp.json();
            if (result.ok) {
                document.getElementById('result').classList.remove('show'); // ukryj wynik pojedynczego linku
                renderBulkResults(recs, result.links, keys);
                refreshChallenge();
            } else if (result.error === 'ratelimit') {
                alert(T.error_ratelimit); refreshChallenge();
            } else if (result.error === 'math') {
                alert(T.error_math); refreshChallenge();
            } else if (result.error === 'batch_size' || result.error === 'too_large') {
                alert(T.error_batch || T.error_server); refreshChallenge();
            } else {
                alert(T.error_server); refreshChallenge();
            }
        } catch (e) {
            alert(T.error_connection);
        } finally {
            btn.disabled = false; btn.innerHTML = btnOriginalHTML;
        }
        return;
    }

    // tryb plain (przelacznik ON lub 1 wiersz danych): zamien tabele na TSV
    // na KOPII, nie mutuj edytora - gdy request padnie user nie traci tabeli.
    let extractRoot = editor;
    const plainTable = editor.querySelector(':scope > table.bb-import-table');
    if (plainTable && !isBulkMode()) {
        extractRoot = editor.cloneNode(true);
        const t = extractRoot.querySelector(':scope > table.bb-import-table');
        t.parentNode.replaceChild(document.createTextNode(tableToPlainText(t)), t);
    }

    const sections = extractSections(extractRoot);

    // --- CLIENT-SIDE ENCRYPTION ---
    const hexKey = generateHexKey();
    const pwd = document.getElementById('linkPassword').value.trim();

    const btn = document.querySelector('.generate-btn');
    const btnOriginalHTML = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>' + (T.generating || 'Encrypting...');

    try {
        // Szyfruj w przeglądarce (wspolna funkcja - spojnosc idx z bulk)
        const v3 = await buildV3Keys(pwd, hexKey);
        const payload = await sectionsToPayload(sections, v3.aesKey);

        // timeout - zawieszone polaczenie nie zostawia spinnera na zawsze
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 15000);
        let resp;
        try {
            resp = await fetch('/api/create.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                signal: ctrl.signal,
                body: JSON.stringify({
                    website_url: honeypot,
                    encrypted_text: payload.encrypted_text,
                    encrypted_secrets: payload.encrypted_secrets,
                    total_sections: payload.total_sections,
                    expire_days: parseInt(document.getElementById('expireDays').value) || BB.defaults.expireDays,
                    max_views: parseInt(document.getElementById('maxViews').value) || BB.defaults.maxViews,
                    delete_after_days: intOrDefault('deleteDays', BB.defaults.deleteDays),
                    format: 3,
                    kdf: v3.authTag ? { alg: 'PBKDF2-SHA256', iter: V3_ITER } : null,
                    auth_tag: v3.authTag,
                    math_a: CH.a,
                    math_b: CH.b,
                    math_exp: CH.exp,
                    math_token: CH.token,
                    math_answer: selectedAnswer,
                }),
            });
        } finally {
            clearTimeout(timer);
        }

        const result = await resp.json();

        if (result.ok) {
            // Serwer zwraca URL bez klucza — klucz dodajemy po stronie klienta
            document.getElementById('resultUrl').value = result.url + '#' + hexKey;
            document.getElementById('result').classList.add('show');
            // pokaż hasło jeśli było ustawione
            const pwdEl = document.getElementById('resultPassword');
            if (pwd) {
                const pwdEsc = pwd.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                pwdEl.innerHTML = T.your_password + ' <strong>' + pwdEsc + '</strong><br><small>' + T.password_unrecoverable + '</small>';
                pwdEl.classList.add('show');
            } else {
                pwdEl.classList.remove('show');
                pwdEl.innerHTML = '';
            }
            document.getElementById('result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            refreshChallenge();
        } else if (result.error === 'ratelimit') {
            alert(T.error_ratelimit);
        } else if (result.error === 'math') {
            alert(T.error_math);
            refreshChallenge();
        } else {
            alert(result.error || T.error_server);
        }
    } catch (e) {
        alert(T.error_connection);
    } finally {
        btn.disabled = false;
        btn.innerHTML = btnOriginalHTML;
    }
}

// Lista wynikow bulk: JEDNA tabela zeby kolumny wartosci wyrownaly sie same
// wg tresci (nie plywaly per rekord). Per rekord: wiersz wartosci (wszystkie
// kolumny, puste td dla wyrownania) + wiersz linku (colspan, URL+Kopiuj) +
// pusty wiersz-odstep. Dane z przegladarki SPRZED szyfrowania (nic nie deszyfrujemy).
function renderBulkResults(records, links, keys) {
    const box = document.getElementById('bulkResult');
    box.innerHTML = ''; box.style.display = 'block';
    // notka o wspolnym hasle jesli ustawione (spec: jawny kompromis MVP)
    const pwd = document.getElementById('linkPassword');
    if (pwd && pwd.value) {
        const n = document.createElement('div'); n.className = 'bulk-note';
        n.textContent = (T.your_password || '') + ' ' + pwd.value + ' - ' + (T.password_unrecoverable || '');
        box.appendChild(n);
    }
    const shown = [];
    records.forEach((rec, i) => { if (links && links[i]) shown.push({ rec: rec, url: links[i].url + '#' + keys[i] }); });
    let cols = 1;
    shown.forEach(x => { cols = Math.max(cols, x.rec.values.length); });
    const table = document.createElement('table'); table.className = 'bulk-results-table';
    shown.forEach((x, idx) => {
        // wiersz wartosci - wszystkie kolumny (puste td dla wyrownania szerokosci)
        const vtr = document.createElement('tr'); vtr.className = 'bulk-values-row';
        for (let c = 0; c < cols; c++) {
            const cell = document.createElement('td');
            cell.textContent = x.rec.values[c] || '';
            vtr.appendChild(cell);
        }
        table.appendChild(vtr);
        // wiersz linku - kolumny zmergeowane (colspan)
        const ltr = document.createElement('tr'); ltr.className = 'bulk-link-row';
        const ltd = document.createElement('td'); ltd.colSpan = cols;
        const cell = document.createElement('div'); cell.className = 'bulk-link-cell';
        const inp = document.createElement('input'); inp.readOnly = true; inp.value = x.url;
        const btn = document.createElement('button'); btn.type = 'button'; btn.textContent = T.copy || 'Copy';
        btn.addEventListener('click', () => {
            const done = () => { btn.textContent = T.copied || 'OK'; setTimeout(() => btn.textContent = T.copy || 'Copy', 2000); };
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(x.url).then(done).catch(() => { inp.select(); try { document.execCommand('copy'); done(); } catch (e) {} });
            } else { inp.select(); try { document.execCommand('copy'); done(); } catch (e) {} }
        });
        cell.appendChild(inp); cell.appendChild(btn); ltd.appendChild(cell); ltr.appendChild(ltd);
        table.appendChild(ltr);
        // pusty wiersz-odstep miedzy rekordami (nie po ostatnim)
        if (idx < shown.length - 1) {
            const str = document.createElement('tr'); str.className = 'bulk-spacer-row';
            const std = document.createElement('td'); std.colSpan = cols; str.appendChild(std);
            table.appendChild(str);
        }
    });
    box.appendChild(table);
    box.scrollIntoView({ block: 'nearest' });
}

function copyLink() {
    const input = document.getElementById('resultUrl');
    input.select();
    input.setSelectionRange(0, input.value.length); // mobile Safari

    const showCopied = () => {
        const btn = document.querySelector('.copy-btn');
        const original = btn.innerHTML;
        btn.innerHTML = '<svg data-lucide="check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:1em;height:1em;vertical-align:-0.15em;margin-right:0.3em;" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>' + T.copied;
        btn.classList.add('copied');
        setTimeout(() => {
            btn.innerHTML = original;
            btn.classList.remove('copied');
        }, 1800);
    };

    // navigator.clipboard wymaga secure context (HTTPS) i uprawnien -
    // fallback do execCommand, a gdy i to padnie, tekst i tak jest zaznaczony.
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(input.value).then(showCopied).catch(() => {
            try { document.execCommand('copy'); showCopied(); } catch (e) {}
        });
    } else {
        try { document.execCommand('copy'); showCopied(); } catch (e) {}
    }
}

// init
updatePreview();
