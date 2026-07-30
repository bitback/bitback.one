// --- IMPORT TABELI (WKLEJKA Z EXCELA) ---
// Buduje gola kopie tabeli: zostawia tylko table/thead/tbody/tr/td/th/br +
// wezly tekstowe, zdejmuje wszystkie atrybuty. Tagi spoza whitelisty sa
// UNWRAP - ich dzieci sa doklejane do rodzica (tekst z <b>/<span> nie ginie).
function cleanPastedTable(html) {
    const ALLOWED = { TABLE:1, THEAD:1, TBODY:1, TR:1, TD:1, TH:1, BR:1 };
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const src = doc.querySelector('table');
    if (!src) return null;

    function clean(node, parent) {
        if (node.nodeType === 3) { parent.appendChild(document.createTextNode(node.textContent)); return; }
        if (node.nodeType !== 1) return;
        if (ALLOWED[node.tagName]) {
            const el = document.createElement(node.tagName.toLowerCase());
            node.childNodes.forEach(ch => clean(ch, el));
            parent.appendChild(el);
        } else {
            node.childNodes.forEach(ch => clean(ch, parent));
        }
    }
    const frag = document.createDocumentFragment();
    clean(src, frag);
    const table = frag.querySelector('table');
    if (!table) return null;
    table.className = 'bb-import-table';
    return { table, tableCount: doc.querySelectorAll('table').length };
}

editor.addEventListener('paste', function(e) {
    const html = e.clipboardData ? e.clipboardData.getData('text/html') : '';
    if (!html || html.indexOf('<table') === -1) return;
    const res = cleanPastedTable(html);
    if (!res) return;
    e.preventDefault();
    const sel = window.getSelection();
    if (sel.rangeCount) {
        const range = sel.getRangeAt(0);
        range.deleteContents();
        range.insertNode(res.table);
        range.setStartAfter(res.table);
        range.collapse(true);
        sel.removeAllRanges(); sel.addRange(range);
    } else {
        editor.appendChild(res.table);
    }
    hoistTableToEditor(res.table);
    showImportNote(res.table, res.tableCount);
    updatePreview();
});

// Rozbija kazdy wrapper miedzy tabela a #editor, przenoszac WSZYSTKIE jego
// dzieci (tabele oraz ewentualny naglowek/stopke w tym samym wrapperze) o
// poziom wyzej z zachowaniem kolejnosci. Wyjmowanie samej tabeli zostawiloby
// stopke w wrapperze PRZED tabela - rozbicie wrappera to naprawia.
function hoistTableToEditor(table) {
    while (table.parentNode && table.parentNode !== editor) {
        const p = table.parentNode;
        const grand = p.parentNode;
        while (p.firstChild) grand.insertBefore(p.firstChild, p);
        grand.removeChild(p);
    }
}

function showImportNote(table, tableCount) {
    const rows = table.querySelectorAll('tr').length;
    const firstRow = table.querySelector('tr');
    const cols = firstRow ? firstRow.children.length : 0;
    let note = document.getElementById('importNote');
    if (!note) {
        note = document.createElement('div');
        note.id = 'importNote'; note.className = 'bb-import-note';
        editor.parentNode.insertBefore(note, editor.nextSibling);
    }
    note.textContent = (T.import_detected || '').replace('{rows}', rows).replace('{cols}', cols);
    // ostrzez o wielu tabelach: z jednej wklejki (tableCount) LUB juz obecnych
    // w edytorze (osobne wklejenia) - uzywana jest tylko pierwsza
    const editorTables = editor.querySelectorAll('table.bb-import-table').length;
    const effective = Math.max(tableCount, editorTables);
    if (effective > 1) {
        const w = document.createElement('div'); w.className = 'warn';
        w.textContent = (T.import_multi_tables || '').replace('{n}', effective);
        note.appendChild(w);
    }
}

// --- TRYB BULK: DETEKCJA + PARSER KORESPONDENCJI SERYJNEJ ---
// Bulk = tabela bezposrednim dzieckiem #editor, >=3 wiersze (naglowek + >=2
// dane), przelacznik "zwykly tekst" wylaczony.
function isBulkMode() {
    const cb = document.getElementById('plainTextToggle');
    if (cb && cb.checked) return false;
    const table = editor.querySelector(':scope > table.bb-import-table');
    if (!table) return false;
    return table.querySelectorAll('tr').length >= 3;
}

// Tekst komorki: wszystkie biale znaki (entery, taby, wielokrotne spacje,
// <br>) -> pojedyncza spacja + trim. Czysci smieci wklejone z Excela/kodu.
function cellText(td) {
    let s = '';
    (function walk(node) {
        node.childNodes.forEach(n => {
            if (n.nodeType === 3) s += n.textContent;
            else if (n.nodeType === 1) { if (n.tagName === 'BR') s += ' '; else walk(n); }
        });
    })(td);
    return s.replace(/\s+/g, ' ').trim();
}

// Konwersja tabeli na TSV - tryb plain (przelacznik ON lub 1 wiersz danych).
function tableToPlainText(table) {
    return Array.from(table.querySelectorAll('tr')).map(tr =>
        Array.from(tr.children).map(td => cellText(td)).join('\t')
    ).join('\n');
}

// Tekst wezla z konwersja <br>/<div> na \n - inaczej filtr '---' pudluje na
// wieloliniowych naglowkach.
function nodeTextBr(n) {
    if (n.nodeType === 3) return n.textContent;
    if (n.nodeType !== 1) return '';
    if (n.tagName === 'BR') return '\n';
    // inna tabela NIE jest czescia naglowka/stopki - nie sklejaj jej komorek
    // do jawnego tekstu (wyciek danych do stopki kazdego rekordu)
    if (n.tagName === 'TABLE') return '';
    let s = '';
    n.childNodes.forEach(ch => { s += nodeTextBr(ch); });
    return s + (n.tagName === 'DIV' ? '\n' : '');
}
// Naglowek = wezly PRZED tabela; stopka = wezly PO tabeli. Linie '---'
// (separator wizualny) usuwane z tresci rekordu.
function domTextBefore(root, table) {
    let s = '';
    for (const n of Array.from(root.childNodes)) { if (n === table) break; s += nodeTextBr(n); }
    return s.split('\n').filter(l => l.trim() !== '---').join('\n').trim();
}
function domTextAfter(root, table) {
    let s = '', seen = false;
    for (const n of Array.from(root.childNodes)) { if (n === table) { seen = true; continue; } if (seen) s += nodeTextBr(n); }
    return s.split('\n').filter(l => l.trim() !== '---').join('\n').trim();
}
// Rekord: naglowek(jawny) + per NIEpusta komorka [etykieta: (text) + wartosc
// (secret) + \n(text)] + stopka(jawny). Iteruje po KOMORKACH (nie labels) -
// wiersz szerszy niz naglowek (scalone komorki Excela) nie gubi wartosci;
// brak etykiety -> sama wartosc. Pusta komorka -> linia pominieta.
function buildRecordSections(header, labels, cells, footer) {
    const out = [];
    // '---' (separator naglowek/stopka) -> pusty wiersz (jeden Enter) w renderze:
    // naglowek, PUSTA LINIA, rekord, PUSTA LINIA, stopka.
    if (header) out.push({ type:'text', content: header + '\n\n' });
    for (let k = 0; k < cells.length; k++) {
        const val = cells[k];
        if (!val) continue;
        const label = (labels[k] || '').trim();
        if (label) out.push({ type:'text', content: label + ': ' });
        out.push({ type:'secret', content: val });
        out.push({ type:'text', content: '\n' });
    }
    if (footer) out.push({ type:'text', content: '\n' + footer });
    return out;
}
function collectBulkRecords() {
    const table = editor.querySelector(':scope > table.bb-import-table');
    const rows = Array.from(table.querySelectorAll('tr'));
    const labels = Array.from(rows[0].children).map(c => cellText(c));
    const header = domTextBefore(editor, table);
    const footer = domTextAfter(editor, table);
    const records = [];
    for (let i = 1; i < rows.length; i++) {
        const cells = Array.from(rows[i].children).map(c => cellText(c));
        if (cells.every(c => !c)) continue; // pomin calkowicie pusty wiersz (ogon zaznaczenia z Excela)
        records.push({ sections: buildRecordSections(header, labels, cells, footer), values: cells });
    }
    return records;
}

// Podglad JEDNEGO rekordu tak jak zobaczy go odbiorca (etykieta: wartosc) -
// z sekcji, ktore realnie ida do szyfrowania. expired -> wartosci zamaskowane.
// Tabela to WEJSCIE, nie output; maskowanie komorek tabeli wprowadzaloby w blad.
function buildBulkPreview(record, expired) {
    const container = document.createElement('div');
    record.sections.forEach(s => {
        if (s.type === 'secret') {
            const span = document.createElement('span');
            if (expired) { span.className = 'masked'; span.textContent = '●●●●●●'; }
            else { span.className = 'secret'; span.textContent = s.content; }
            container.appendChild(span);
        } else {
            const parts = s.content.split('\n');
            parts.forEach((part, i) => {
                if (i > 0) container.appendChild(document.createElement('br'));
                if (part) container.appendChild(document.createTextNode(part));
            });
        }
    });
    return container;
}

// --- EKSTRAKCJA DANYCH Z EDYTORA ---
// root domyslnie #editor; mozna podac klon (tryb plain nie mutuje edytora).
function extractSections(root) {
    root = root || editor;
    const sections = [];

    function getTextWithBreaks(el) {
        let text = '';
        el.childNodes.forEach(child => {
            if (child.nodeType === 3) {
                text += child.textContent;
            } else if (child.nodeType === 1) {
                if (child.tagName === 'BR') {
                    text += '\n';
                } else if (child.tagName === 'DIV') {
                    text += '\n';
                    text += getTextWithBreaks(child);
                } else {
                    text += getTextWithBreaks(child);
                }
            }
        });
        return text;
    }

    function parseNode(node) {
        if (node.nodeType === 3) {
            sections.push({ type: 'text', content: node.textContent });
        } else if (node.nodeType === 1) {
            if (node.classList && node.classList.contains('secret')) {
                sections.push({ type: 'secret', content: getTextWithBreaks(node) });
            } else if (node.tagName === 'BR') {
                sections.push({ type: 'text', content: '\n' });
            } else if (node.tagName === 'DIV') {
                sections.push({ type: 'text', content: '\n' });
                node.childNodes.forEach(child => parseNode(child));
            } else {
                node.childNodes.forEach(child => parseNode(child));
            }
        }
    }

    root.childNodes.forEach(node => parseNode(node));

    // scal sąsiednie tego samego typu
    const merged = [];
    sections.forEach(s => {
        const last = merged[merged.length - 1];
        if (last && last.type === s.type) {
            last.content += s.content;
        } else {
            merged.push({ ...s });
        }
    });

    return merged.filter(s => s.content.length > 0);
}

