// Wykrywa otpauth:// URI w odszyfrowanej treści i renderuje pod nią kod QR
// do zeskanowania w aplikacji uwierzytelniającej. Cała praca client-side:
// sekret nie opuszcza przeglądarki (spójne z modelem aplikacji).
(function () {
    'use strict';

    // ● (U+25CF, bullet maskowania wygasłego sekretu) wykluczony z klasy znaków
    var OTPAUTH_RE = /otpauth:\/\/(?:totp|hotp)\/[^\s<>"'●]+/gi;

    // qrcode-generator: typeNumber 0 (auto) bywa zawodne - iterujemy wersję w górę
    // aż dane się zmieszczą. Poziom korekcji 'M' jak przy enrollment TOTP.
    function makeQr(text) {
        for (var type = 4; type <= 40; type++) {
            try {
                var qr = qrcode(type, 'M');
                qr.addData(text);
                qr.make();
                return qr;
            } catch (e) {}
        }
        return null;
    }

    function extractSecret(uri) {
        var m = /[?&]secret=([A-Za-z2-7]+=*)/i.exec(uri);
        return m ? m[1].toUpperCase() : null;
    }

    function extractLabel(uri) {
        var m = /otpauth:\/\/[^/]+\/([^?]+)/i.exec(uri);
        if (!m) return null;
        try { return decodeURIComponent(m[1]); } catch (e) { return m[1]; }
    }

    function buildBlock(uri, strings) {
        // Bez czytelnego klucza (np. secret oznaczony jako poufny i wygasły -
        // obcięty na bullecie) QR byłby bezużyteczny - pomijamy blok.
        var secret = extractSecret(uri);
        if (!secret) return null;

        var qr = makeQr(uri);
        if (!qr) return null;

        var block = document.createElement('div');
        block.className = 'bb-totp';

        var head = document.createElement('div');
        head.className = 'bb-totp-head';
        head.textContent = strings.title;
        block.appendChild(head);

        var label = extractLabel(uri);
        if (label) {
            var lab = document.createElement('div');
            lab.className = 'bb-totp-label';
            lab.textContent = label;
            block.appendChild(lab);
        }

        var qrWrap = document.createElement('div');
        qrWrap.className = 'bb-totp-qr';
        qrWrap.innerHTML = qr.createSvgTag({ cellSize: 5, margin: 2 });
        block.appendChild(qrWrap);

        var row = document.createElement('div');
        row.className = 'bb-totp-row';

        var val = document.createElement('code');
        val.className = 'bb-totp-secret';
        val.textContent = secret;
        row.appendChild(val);

        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'bb-totp-copy';
        btn.textContent = strings.copy;
        btn.addEventListener('click', function () {
            navigator.clipboard.writeText(secret).then(function () {
                btn.textContent = strings.copied;
                setTimeout(function () { btn.textContent = strings.copy; }, 2000);
            }).catch(function () {});
        });
        row.appendChild(btn);
        block.appendChild(row);

        return block;
    }

    function scan(contentEl, zoneEl, strings) {
        if (!contentEl || !zoneEl || typeof qrcode === 'undefined') return;
        var matches = (contentEl.textContent || '').match(OTPAUTH_RE);
        if (!matches) return;

        zoneEl.innerHTML = '';
        for (var i = 0; i < matches.length; i++) {
            var uri = matches[i].replace(/[.,;:!?)\]]+$/, '');
            var block = buildBlock(uri, strings);
            if (block) zoneEl.appendChild(block);
        }
    }

    window.BBTotp = { scan: scan };
})();
