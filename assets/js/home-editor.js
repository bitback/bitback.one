// Dane z serwera (i18n, challenge antybota, defaulty formularza) przychodza
// wyspa JSON #bb-config w HTML. Strona nie zawiera zadnego wykonywalnego JS,
// wiec nie da sie w niej niczego wstrzyknac przez interpolacje wartosci.
const BB = JSON.parse(document.getElementById('bb-config').textContent);
const T = BB.t;
const editor = document.getElementById('editor');
let previewMode = 'expired';

// --- GUTTER NUMERACJI LINII ---
// Liczy linie WIZUALNE (wysokosc wyrenderowanej tresci / line-height),
// wiec numery sa zawsze wyrownane z trescia - takze gdy dluga linia
// sie zawija. Pusty edytor: numeruje linie placeholdera (::before).
const gutter = document.getElementById('editorGutter');
const PLACEHOLDER_LINES = BB.placeholderLines;
function updateGutter() {
    // bulk: numeracja linii dla tabeli bezsensowna - ukryj gutter i zredukuj
    // wciecie edytora (bez gutter 3.3rem lewego paddingu tabela sie odsuwa)
    if (isBulkMode()) { gutter.style.display = 'none'; editor.classList.add('editor-bulk'); return; }
    gutter.style.display = ''; editor.classList.remove('editor-bulk');
    const lh = parseFloat(getComputedStyle(editor).lineHeight);
    let lines;
    if (editor.textContent.length === 0 && !editor.querySelector('br,div')) {
        lines = PLACEHOLDER_LINES;
    } else {
        const r = document.createRange();
        r.selectNodeContents(editor);
        const h = r.getBoundingClientRect().height;
        lines = Math.max(1, Math.round(h / lh));
    }
    let out = '';
    for (let i = 1; i <= lines; i++) out += i + '\n';
    gutter.textContent = out;
}
window.addEventListener('resize', updateGutter);

// --- MATH ANTYBOT ---
// Challenge generowany serwerowo i podpisany HMAC - klient nie zna logiki
// weryfikacji. Po wygenerowaniu linka pobieramy swiezy z /api/challenge.php.
let CH = BB.challenge;
let selectedAnswer = null;

function generateMath() {
    selectedAnswer = null;
    const correct = CH.a + CH.b;
    // 2 falszywe odpowiedzi to tylko UI (serwer i tak liczy sam)
    const fakes = new Set();
    while (fakes.size < 2) {
        const f = correct + (Math.floor(Math.random() * 7) - 3); // ±3
        if (f !== correct && f > 0) fakes.add(f);
    }

    const options = [correct, ...fakes];
    for (let i = options.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [options[i], options[j]] = [options[j], options[i]];
    }

    document.getElementById('mathQuestion').textContent = `${CH.a} + ${CH.b} = ?`;
    const container = document.getElementById('mathOptions');
    container.innerHTML = '';
    options.forEach(val => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'antibot-opt';
        btn.textContent = val;
        btn.addEventListener('click', () => {
            container.querySelectorAll('.antibot-opt').forEach(b => b.classList.remove('selected'));
            btn.classList.add('selected');
            selectedAnswer = val;
            updateGuide();
        });
        container.appendChild(btn);
    });
}
generateMath();

async function refreshChallenge() {
    try {
        const r = await fetch('/api/challenge.php');
        CH = await r.json();
    } catch (e) { /* zostaje stary - token wazny 15 min */ }
    generateMath();
}

// --- TOGGLE SECRET (oznacz / odznacz) ---
function unwrapSecret(secretEl, sel) {
    const marker = document.createElement('span');
    marker.setAttribute('data-cursor', '1');
    secretEl.parentNode.insertBefore(marker, secretEl.nextSibling);

    const parent = secretEl.parentNode;
    while (secretEl.firstChild) {
        parent.insertBefore(secretEl.firstChild, secretEl);
    }
    parent.removeChild(secretEl);
    parent.normalize();

    const r = document.createRange();
    r.setStartBefore(marker);
    r.collapse(true);
    marker.remove();
    sel.removeAllRanges();
    sel.addRange(r);
    editor.focus();
    updatePreview();
}

function flashHint() {
    const hint = document.querySelector('.hint-bar');
    hint.classList.remove('bb-flash');
    void hint.offsetWidth;
    hint.classList.add('bb-flash');
}

function toggleSecret() {
    const sel = window.getSelection();
    if (!sel.rangeCount) { flashHint(); return; }

    // sprawdź czy kursor/zaznaczenie jest wewnątrz .secret
    const anchorParent = sel.anchorNode.nodeType === 3 ? sel.anchorNode.parentElement : sel.anchorNode;
    const secretEl = anchorParent ? anchorParent.closest('.secret') : null;

    if (secretEl && editor.contains(secretEl)) {
        unwrapSecret(secretEl, sel);
        return;
    }

    // sprawdź czy zaznaczenie obejmuje lub dotyka .secret (odznacz)
    if (!sel.isCollapsed) {
        const range = sel.getRangeAt(0);
        if (!editor.contains(range.commonAncestorContainer)) { flashHint(); return; }

        const startParent = range.startContainer.nodeType === 3 ? range.startContainer.parentElement : range.startContainer;
        const endParent = range.endContainer.nodeType === 3 ? range.endContainer.parentElement : range.endContainer;
        const startSecret = startParent ? startParent.closest('.secret') : null;
        const endSecret = endParent ? endParent.closest('.secret') : null;

        // cały zaznaczony tekst jest wewnątrz jednego .secret
        if (startSecret && startSecret === endSecret && editor.contains(startSecret)) {
            unwrapSecret(startSecret, sel);
            return;
        }

        // zaznaczenie obejmuje .secret elementy - odznacz je
        const fragment = range.cloneContents();
        if (fragment.querySelector('.secret')) {
            // znajdź .secret elementy w faktycznym DOM (nie w klonie)
            const container = range.commonAncestorContainer;
            const searchRoot = container.nodeType === 3 ? container.parentElement : container;
            const secrets = searchRoot.querySelectorAll('.secret');
            const toUnwrap = [];
            for (const s of secrets) {
                if (range.intersectsNode(s)) toUnwrap.push(s);
            }
            if (toUnwrap.length > 0) {
                toUnwrap.forEach(s => {
                    const parent = s.parentNode;
                    while (s.firstChild) parent.insertBefore(s.firstChild, s);
                    parent.removeChild(s);
                });
                editor.normalize();
                editor.focus();
                updatePreview();
                return;
            }
        }

        // blokuj zagnieżdżanie
        if (startSecret) return;
        if (endSecret) return;
    }

    // --- OZNACZ ---
    if (sel.isCollapsed) { flashHint(); return; } // nic nie zaznaczono
    const range = sel.getRangeAt(0);
    if (!editor.contains(range.commonAncestorContainer)) return;

    const mark = document.createElement('span');
    mark.className = 'secret';

    try {
        range.surroundContents(mark);
    } catch(e) {
        // surroundContents nie działa gdy zaznaczenie przecina granicę elementu
        // (np. obejmuje <br> lub <div>) - użyj extractContents + appendChild
        try {
            const contents = range.extractContents();
            mark.appendChild(contents);
            range.insertNode(mark);
        } catch(e2) {
            return;
        }
    }

    // postaw kursor za nowym spanem
    const r = document.createRange();
    r.setStartAfter(mark);
    r.collapse(true);
    sel.removeAllRanges();
    sel.addRange(r);
    editor.focus();
    updatePreview();
}

// --- SKRÓT Ctrl+E ---
editor.addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.key === 'e') {
        e.preventDefault();
        toggleSecret();
    }
});

// --- GUIDE: co pulsuje w danym stanie (pulsuje sam glow, ramki bez zmian) ---
// oznaczenie poufnego -> pulsuje WERYFIKACJA; wybor odpowiedzi -> zapala sie GENERUJ
function updateGuide() {
    // bulk: poufnosc syntetyzowana dopiero przy generowaniu (brak .secret w
    // edytorze), wiec content/secret spelnione gdy jest tabela bulk
    const bulk = isBulkMode();
    const hasContent = bulk ? true : (editor.textContent.trim().length > 0);
    const hasSecret = bulk ? true : !!editor.querySelector('.secret');
    const hasAnswer = selectedAnswer !== null;
    const ready = hasContent && hasSecret && hasAnswer;
    const gen = document.querySelector('.generate-btn');
    gen.classList.toggle('dimmed', !ready);
    gen.classList.toggle('bb-guide', ready);
    document.querySelector('.config-verify').classList.toggle('bb-guide', hasContent && hasSecret && !hasAnswer);
}

// --- PODGLĄD ---
function updatePreview() {
    updateGutter();
    // pokaz przelacznik plain tylko gdy tabela obecna; sprzataj note gdy znikla
    const hasImportTable = !!editor.querySelector(':scope > table.bb-import-table');
    const toggleWrap = document.getElementById('plainTextToggleWrap');
    if (toggleWrap) toggleWrap.style.display = hasImportTable ? '' : 'none';
    if (!hasImportTable) { const n = document.getElementById('importNote'); if (n) n.remove(); }
    const previewBox = document.getElementById('preview');
    const html = editor.innerHTML;
    const isEmpty = editor.textContent.trim().length === 0;
    updateGuide();

    if (isEmpty) {
        previewBox.innerHTML = '<span class="preview-empty">' + (T.preview_empty || '') + '</span>';
        return;
    }

    // bulk: tabela to WEJSCIE, nie prawdziwy output. Pokaz interpretacje
    // jednego rekordu tak jak zobaczy go odbiorca (expired -> zamaskowany).
    if (isBulkMode()) {
        const recs = collectBulkRecords();
        previewBox.innerHTML = '';
        const pnote = document.createElement('div');
        pnote.className = 'bulk-preview-note';
        pnote.textContent = (T.bulk_preview_note || '').replace('{n}', recs.length);
        previewBox.appendChild(pnote);
        if (recs[0]) previewBox.appendChild(buildBulkPreview(recs[0], previewMode === 'expired'));
        return;
    }

    if (previewMode === 'expired') {
        // DOM-based replacement - safe for any content inside .secret
        const clone = editor.cloneNode(true);
        clone.querySelectorAll('.secret').forEach(el => {
            const masked = document.createElement('span');
            masked.className = 'masked';
            masked.textContent = '●●●●●●';
            el.replaceWith(masked);
        });
        previewBox.innerHTML = clone.innerHTML;
    } else {
        previewBox.innerHTML = html;
    }
}

function setPreview(mode, btn) {
    previewMode = mode;
    document.querySelectorAll('.preview-tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    updatePreview();
}

editor.addEventListener('input', updatePreview);
(function(){ const pt = document.getElementById('plainTextToggle'); if (pt) pt.addEventListener('change', updatePreview); })();

