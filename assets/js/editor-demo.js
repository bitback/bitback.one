/**
 * Demo oznaczania poufnego - pokaz w nietknietym polu tresci.
 *
 * CALOSC jest zdejmowalna: skasuj ten plik, `assets/css/editor-demo.css` oraz
 * po jednej linii w listach zasobow w `index.php`. Zaden inny plik nie wie o
 * istnieniu dema.
 *
 * ZASADA NIENARUSZALNA: nie pisz do #editor. Aplikacja buduje ladunek z
 * `editor.textContent` i z elementow `.secret` w srodku (home-generate.js,
 * home-editor.js), wiec tekst dema w prawdziwym polu dalby sie zaszyfrowac i
 * wyslac odbiorcy. Animacja rysuje sie w osobnej warstwie na wierzchu,
 * przezroczystej dla myszy, i znika przy pierwszym dotknieciu pola.
 *
 * Tresc bierze sie z istniejacej podpowiedzi pola (atrybut data-ph), wiec jest
 * dwujezyczna bez nowych kluczy i18n.
 */
(function () {
    'use strict';

    var editor = document.getElementById('editor');
    if (!editor) return;

    var wrap = editor.parentNode;
    var chip = document.querySelector('.hint-text .kbd-chip');
    var markBtn = document.querySelector('[data-bb-action="toggle-secret"]');
    if (!wrap) return;

    // Nie startuj, gdy pole juz cos ma (przywrocony stan formularza) albo gdy
    // pole jest juz aktywne.
    if (editor.textContent.trim().length > 0) return;
    if (document.activeElement === editor) return;

    // DECYZJA USERA (2026-08-05): pokaz gra ZAWSZE, takze przy wylaczonych
    // efektach animacji w systemie (prefers-reduced-motion: reduce). Pierwsza
    // wersja to ustawienie respektowala i user nie widzial nic, bo ma animacje
    // wylaczone w Windows. Zgloszone jako swiadome odstepstwo od domyslnej
    // praktyki dostepnosciowej i podtrzymane wprost. Nie przywracac guardu bez
    // pytania.

    /* --- tresc pokazu z podpowiedzi pola --------------------------------- */

    var phLines = (editor.getAttribute('data-ph') || '').split('\n');
    // Pierwsza linia podpowiedzi to instrukcja ("Wpisz tresc tutaj..."), nie
    // przyklad - pokazujemy dopiero kolejne.
    var lines = phLines.slice(1).map(function (l) {
        // Ogon ze strzalka powtarza to, co animacja wlasnie pokazuje.
        var arrow = l.indexOf('←');
        return (arrow === -1 ? l : l.slice(0, arrow)).replace(/\s+$/, '');
    }).filter(function (l) { return l.length > 0; });

    if (lines.length < 2) return;

    // Oznaczamy wartosc po ostatnim dwukropku w ostatniej linii - dziala tak
    // samo dla "Haslo: s3cret123" i "Password: s3cret123".
    var lastIdx = lines.length - 1;
    var sep = lines[lastIdx].lastIndexOf(': ');
    if (sep === -1) return;
    var secretText = lines[lastIdx].slice(sep + 2);
    if (!secretText) return;

    /* --- warstwa pokazowa ------------------------------------------------ */

    var layer = document.createElement('div');
    layer.className = 'bb-demo-layer';
    layer.setAttribute('aria-hidden', 'true');

    var mouse = document.createElement('div');
    mouse.className = 'bb-demo-mouse';
    mouse.setAttribute('aria-hidden', 'true');
    mouse.innerHTML = '<span class="ring"></span>' +
        '<svg width="22" height="22" viewBox="0 0 24 24">' +
        '<path d="M5 2 L5 18 L9.2 14.2 L11.8 20.4 L14.6 19.2 L12 13.2 L18 13.2 Z" ' +
        'fill="#fff" stroke="hsl(220 45% 4%)" stroke-width="1.3" stroke-linejoin="round"/></svg>';

    var run = 0;
    var stopped = false;

    function sleep(v) { return new Promise(function (r) { setTimeout(r, v); }); }
    function alive(token) { return token === run && !stopped; }

    function mouseTo(rect, dx, dy) {
        var base = wrap.getBoundingClientRect();
        mouse.style.transform = 'translate(' + (rect.left - base.left + (dx || 0)) +
            'px, ' + (rect.top - base.top + (dy || 0)) + 'px)';
    }

    function caret() {
        var c = document.createElement('span');
        c.className = 'bb-demo-caret';
        return c;
    }

    function typeLine(token, text, markTail) {
        var line = document.createElement('div');
        layer.appendChild(line);
        var head = markTail ? text.slice(0, text.length - secretText.length) : text;
        var c = caret();
        line.appendChild(c);

        var i = 0;
        var target = null;

        function step() {
            if (!alive(token)) return Promise.resolve(null);
            if (i < head.length) {
                line.insertBefore(document.createTextNode(head[i]), c);
                i++;
                return sleep(i < 4 ? 55 : 26).then(step);
            }
            if (!markTail) { c.remove(); return Promise.resolve(null); }
            if (!target) {
                target = document.createElement('span');
                line.insertBefore(target, c);
            }
            var j = target.childNodes.length;
            if (j < secretText.length) {
                var ch = document.createElement('span');
                ch.className = 'bb-demo-ch';
                ch.textContent = secretText[j];
                target.appendChild(ch);
                return sleep(38).then(step);
            }
            c.remove();
            return Promise.resolve(target);
        }
        return step();
    }

    function play() {
        var token = ++run;
        layer.innerHTML = '';
        layer.style.opacity = '1';
        wrap.classList.add('bb-demo-idle');
        if (chip) chip.classList.remove('bb-demo-pressed');
        if (markBtn) markBtn.classList.remove('bb-demo-active');
        mouse.classList.remove('is-on', 'is-down');

        return sleep(900).then(function () {
            if (!alive(token)) return;
            wrap.classList.remove('bb-demo-idle');
            return typeLine(token, lines[0], false);
        }).then(function () {
            if (!alive(token)) return;
            return sleep(200).then(function () { return typeLine(token, lines[lastIdx], true); });
        }).then(function (target) {
            if (!alive(token) || !target) return;
            var chars = Array.prototype.slice.call(target.querySelectorAll('.bb-demo-ch'));
            if (!chars.length) return;

            // kursor wjezdza z prawego dolnego rogu pola
            var base = wrap.getBoundingClientRect();
            mouse.style.transition = 'none';
            mouse.style.transform = 'translate(' + (base.width - 44) + 'px, ' + (base.height - 34) + 'px)';
            void mouse.offsetWidth;
            mouse.style.transition = 'transform 780ms cubic-bezier(.33,.9,.28,1)';
            mouse.classList.add('is-on');
            mouseTo(chars[0].getBoundingClientRect(), -2, 6);

            return sleep(880).then(function () {
                if (!alive(token)) return;
                mouse.classList.add('is-down');
                return sleep(180);
            }).then(function () {
                mouse.style.transition = 'transform 60ms linear';
                var k = 0;
                function drag() {
                    if (!alive(token) || k >= chars.length) return Promise.resolve();
                    chars[k].classList.add('is-sel');
                    var r = chars[k].getBoundingClientRect();
                    mouseTo(r, r.width, 6);
                    k++;
                    return sleep(42).then(drag);
                }
                return drag();
            }).then(function () {
                if (!alive(token)) return;
                mouse.classList.remove('is-down');
                return sleep(340);
            }).then(function () {
                if (!alive(token)) return;
                if (chip) chip.classList.add('bb-demo-pressed');
                if (markBtn) markBtn.classList.add('bb-demo-active');
                return sleep(260);
            }).then(function () {
                if (!alive(token)) return;
                target.className = 'bb-demo-secret is-pop';
                chars.forEach(function (c) { c.classList.remove('is-sel'); });
                return sleep(260);
            }).then(function () {
                if (!alive(token)) return;
                if (chip) chip.classList.remove('bb-demo-pressed');
                if (markBtn) markBtn.classList.remove('bb-demo-active');
                mouse.classList.remove('is-on');
                return sleep(2200);
            }).then(function () {
                if (!alive(token)) return;
                layer.style.opacity = '0.12';
                return sleep(300);
            }).then(function () {
                if (!alive(token)) return;
                play();
            });
        });
    }

    /* --- zdejmowanie ------------------------------------------------------ */

    // Pierwsze dotkniecie pola konczy pokaz na dobre. Nie ma powrotu w tej
    // sesji strony: user pisze, demo nie wraca mu pod palce.
    function stop() {
        if (stopped) return;
        stopped = true;
        run++;
        wrap.classList.remove('bb-demo-idle');
        document.body.classList.remove('bb-demo-on');
        if (layer.parentNode) layer.parentNode.removeChild(layer);
        if (mouse.parentNode) mouse.parentNode.removeChild(mouse);
        if (chip) chip.classList.remove('bb-demo-pressed');
        if (markBtn) markBtn.classList.remove('bb-demo-active');
    }

    ['pointerdown', 'mousedown', 'focus', 'keydown', 'paste'].forEach(function (ev) {
        editor.addEventListener(ev, stop, true);
    });
    // Skrot z klawiatury albo klik w przycisk oznaczania tez konczy pokaz.
    document.addEventListener('keydown', stop, true);
    if (markBtn) markBtn.addEventListener('pointerdown', stop, true);

    // Przegladarka dlawi liczniki czasu w niewidocznej karcie do jednego
    // przebudzenia na sekunde (zmierzone: trzy liczniki na 38/76/114 ms
    // wystrzelily razem po 871 ms). Bez tego powrot na karte pokazuje zamrozony
    // kadr w polowie zdania - startujemy caly pokaz od nowa.
    document.addEventListener('visibilitychange', function () {
        if (document.visibilityState === 'visible' && !stopped) play();
    });

    wrap.style.position = wrap.style.position || 'relative';
    wrap.appendChild(layer);
    wrap.appendChild(mouse);
    document.body.classList.add('bb-demo-on');
    play();
})();
