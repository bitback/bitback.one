// Dane z serwera przychodza wyspa JSON w HTML (patrz json_island()).
const V = JSON.parse(document.getElementById('bb-view').textContent);
// === ZERO-TRUST CLIENT-SIDE DECRYPTION ===
// Dwa osobne bloby: tekst (zawsze) + sekrety (null jeśli wygasłe — fizycznie usunięte z serwera)

const ENC_TEXT = V.encText;
const ENC_SECRETS = V.encSecrets;  // null = sekrety fizycznie usunięte
const TOTAL_SECTIONS = V.totalSections;
const HAD_SECRETS = V.hadSecrets;
const TOTP_STRINGS = V.totp;
const FORMAT = V.format;
const KDF_ITER = V.kdfIter;
const HAS_VERIFIER = V.hasVerifier;
const UUID = V.uuid;
const T_WRONG = V.t.wrong;
const T_REENTER = V.t.reenter;
const T_CHECKING = V.t.checking;
const T_SUBMIT = V.t.submit;

// Deklaracja MUSI stac przed IIFE: inline prompt bywa wolany z jego
// SYNCHRONICZNEGO prefiksu (przed pierwszym await), gdy brak mastera w
// sessionStorage. `let` nizej bylby wtedy w temporal dead zone i zamiast
// pytania o haslo leciałby ReferenceError.
let inlineWrap = null, inlineErr = null;

(async function() {
    const loadingBox = document.getElementById('loadingBox');
    const contentBox = document.getElementById('contentBox');
    const errorBox = document.getElementById('errorBox');

    try {
        const hexKey = window.location.hash.substring(1);
        if (!hexKey || !/^[0-9a-f]{32}$/i.test(hexKey)) {
            throw new Error(V.noKeyError);
        }

        let textItems, secretItems = [];
        if (FORMAT === 3) {
            const dec = await decryptV3(hexKey);
            textItems = dec.text; secretItems = dec.secrets;
        } else {
            textItems = await decryptBlob(ENC_TEXT, hexKey);
            if (ENC_SECRETS) secretItems = await decryptBlob(ENC_SECRETS, hexKey);
        }
        if (inlineWrap) inlineWrap.style.display = 'none';

        // Scal oba bloby wg idx (oryginalna kolejność)
        const all = [];
        for (const item of textItems) {
            all.push({ idx: item.idx, type: 'text', content: item.content });
        }
        for (const item of secretItems) {
            all.push({ idx: item.idx, type: 'secret', content: item.content });
        }
        all.sort((a, b) => a.idx - b.idx);

        // Jeśli sekrety wygasły, wstaw maskowniki w miejsce brakujących idx
        if (!ENC_SECRETS) {
            const filled = fillMasked(all);
            renderSections(filled, true);
        } else {
            renderSections(all, false);
        }

        loadingBox.style.display = 'none';
        contentBox.style.display = 'block';

        if (window.BBTotp) BBTotp.scan(contentBox, document.getElementById('totpZone'), TOTP_STRINGS);

    } catch (err) {
        loadingBox.style.display = 'none';
        // GCM nie odroznia zlego klucza od uszkodzonego blobu - komunikat laczony.
        errorBox.textContent = (err && err.name === 'OperationError') ? T_WRONG : err.message;
        errorBox.style.display = 'block';
    }
})();

async function tryDecryptV3(aesKey) {
    const text = await decryptBlobV3(ENC_TEXT, aesKey);
    const secrets = ENC_SECRETS ? await decryptBlobV3(ENC_SECRETS, aesKey) : [];
    return { text: text, secrets: secrets };
}

async function decryptV3(hexKey) {
    // 1. link bez hasla
    if (!HAS_VERIFIER) {
        return tryDecryptV3(await aesKeyNoPassV3(hexKey));
    }
    // 2. master przekazany z formularza hasla (sessionStorage, kasowany od razu)
    let masterHex = null;
    try {
        const k = 'bb3m:' + UUID;
        masterHex = sessionStorage.getItem(k);
        sessionStorage.removeItem(k);
    } catch (e) {}
    if (masterHex && /^[0-9a-f]{64}$/.test(masterHex)) {
        try {
            return await tryDecryptV3(await aesKeyFromMaster(hexToBytes(masterHex)));
        } catch (e) { /* spadnij do re-promptu */ }
    }
    // 3. fallback: inline haslo. Blob JUZ w pamieci - retry hasla bez refetch,
    //    bez spalania kolejnego view (bramke przeszlismy).
    while (true) {
        const pwd = await promptPasswordInline();
        const master = await deriveMasterV3(pwd, hexKey, KDF_ITER);
        try {
            return await tryDecryptV3(await aesKeyFromMaster(master));
        } catch (e) {
            showInlineError(T_WRONG);
        }
    }
}

// Inline formularz hasla w miejscu loadera; resolve po kliknieciu/enterze.
function promptPasswordInline() {
    return new Promise(function(resolve) {
        const loadingBox = document.getElementById('loadingBox');
        loadingBox.style.display = 'none';
        if (!inlineWrap) {
            inlineWrap = document.createElement('div');
            inlineWrap.style.cssText = 'text-align:center;padding:1.5rem 0;';
            inlineWrap.innerHTML =
                '<div style="color:var(--bb-fg-3);font-size:0.88rem;margin-bottom:0.6rem;">' + escapeHtml(T_REENTER) + '</div>' +
                '<input type="password" id="inlinePwd" class="pwd-input" style="max-width:300px;width:100%;padding:0.6rem;background:var(--bb-surface-sunk);border:1px solid var(--bb-border-mid);border-radius:8px;color:var(--bb-fg);text-align:center;font-family:var(--bb-font-mono);outline:none;">' +
                '<br><button type="button" id="inlinePwdBtn" style="margin-top:0.6rem;padding:0.6rem 1.6rem;border-radius:8px;border:none;background:var(--bb-accent);color:#fff;font-weight:700;cursor:pointer;">' + escapeHtml(T_SUBMIT) + '</button>' +
                '<div id="inlinePwdErr" style="color:var(--bb-danger-light);font-size:0.84rem;margin-top:0.5rem;display:none;"></div>';
            document.getElementById('errorBox').parentNode.insertBefore(inlineWrap, document.getElementById('loadingBox'));
            inlineErr = inlineWrap.querySelector('#inlinePwdErr');
        }
        inlineWrap.style.display = '';
        const input = inlineWrap.querySelector('#inlinePwd');
        const btn = inlineWrap.querySelector('#inlinePwdBtn');
        input.value = ''; input.focus();
        function go() {
            btn.disabled = true; btn.textContent = T_CHECKING;
            // trim spojnie z tworzeniem (index.php: linkPassword.value.trim()) - inaczej
            // spacja wiodaca/koncowa daje inny authTag niz przy tworzeniu -> falszywy blad hasla.
            resolve(input.value.trim());
        }
        btn.onclick = go;
        input.onkeydown = function(e) { if (e.key === 'Enter') go(); };
    });
}
function showInlineError(msg) {
    const btn = inlineWrap.querySelector('#inlinePwdBtn');
    btn.disabled = false; btn.textContent = T_SUBMIT;
    inlineErr.textContent = msg; inlineErr.style.display = 'block';
}

function fillMasked(textItems) {
    // Wstaw maskowniki w miejsca brakujących idx (fizycznie usunięte sekrety)
    // TOTAL_SECTIONS = łączna liczba sekcji (text + secret) z momentu tworzenia
    let total = TOTAL_SECTIONS;

    if (!total) {
        // Fallback dla starych linków (bez total_sections w JSON)
        if (textItems.length > 0) {
            const maxIdx = Math.max(...textItems.map(i => i.idx));
            const hasGaps = textItems.length < (maxIdx + 1);
            // Jeśli wiemy że były sekrety, a max idx nie pokrywa wszystkiego — dodaj ekstra
            total = hasGaps ? maxIdx + 2 : maxIdx + 1;
            // Jeśli były sekrety ale nie ma dziur, to sekrety były na końcu
            if (!hasGaps && HAD_SECRETS) total = maxIdx + 2;
        } else if (HAD_SECRETS) {
            // Cała treść to sekrety (brak tekstu)
            total = 1;
        }
    }

    if (!total) return textItems;

    // Serwer clampuje total_sections do 1000; gdyby realny najwyzszy idx tekstu
    // byl wiekszy (link z >1000 sekcjami), petla nizej urwalaby te sekcje.
    // Nigdy nie renderuj mniej pozycji niz faktycznie mamy.
    if (textItems.length > 0) {
        const maxIdx = Math.max(...textItems.map(i => i.idx));
        if (maxIdx + 1 > total) total = maxIdx + 1;
    }

    const byIdx = {};
    for (const item of textItems) byIdx[item.idx] = item;

    const result = [];
    for (let i = 0; i < total; i++) {
        if (byIdx[i]) {
            result.push(byIdx[i]);
        } else {
            result.push({ idx: i, type: 'masked', content: '\u25CF\u25CF\u25CF\u25CF\u25CF\u25CF' });
        }
    }
    return result;
}

function renderSections(sections, expired) {
    const contentBox = document.getElementById('contentBox');
    let html = '';
    for (const s of sections) {
        const escaped = escapeHtml(s.content);
        if (s.type === 'masked') {
            html += '<span class="s-masked">' + escaped + '</span>';
        } else if (s.type === 'secret') {
            html += '<span class="s-secret">' + linkify(escaped) + '</span>';
        } else {
            html += '<span class="s-text">' + linkify(escaped) + '</span>';
        }
    }
    contentBox.innerHTML = html;
}
