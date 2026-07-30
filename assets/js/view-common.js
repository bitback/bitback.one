function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

function linkify(escapedHtml) {
    // Regex na escaped HTML - URL moze zawierac &amp; (escaped &).
    // Klasa znakow wyklucza < > ' " wiec nie da sie wyjsc z atrybutu href.
    return escapedHtml.replace(
        /https?:\/\/[^\s<>'"]+/g,
        function(match) {
            return '<a href="' + match + '" target="_blank" rel="noopener" style="color:var(--bb-accent-link);">' + match + '</a>';
        }
    );
}

async function expireNow(btn, action) {
    var wrap = document.getElementById('expireConfirmWrap');
    var cb = document.getElementById('expireConfirmCb');
    if (!cb.checked) {
        wrap.classList.remove('shake');
        void wrap.offsetWidth;
        wrap.classList.add('shake');
        return;
    }
    // Wylacz oba przyciski
    document.querySelectorAll('.expire-now-btn').forEach(function(b) { b.disabled = true; });
    cb.disabled = true;
    btn.textContent = '...';
    const ctrl = new AbortController();
    const timer = setTimeout(function() { ctrl.abort(); }, 15000);
    try {
        const resp = await fetch('/api/expire.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            signal: ctrl.signal,
            body: JSON.stringify({ uuid: btn.dataset.uuid, action: action || 'expire' }),
        });
        clearTimeout(timer);
        const result = await resp.json();
        if (result.ok) {
            btn.textContent = '✓ ' + btn.dataset.success;
            btn.classList.add('done');
            setTimeout(function() { location.reload(); }, 1500);
        } else {
            btn.textContent = btn.dataset.error;
            document.querySelectorAll('.expire-now-btn').forEach(function(b) { b.disabled = false; });
            cb.disabled = false;
        }
    } catch (e) {
        btn.textContent = btn.dataset.error;
        document.querySelectorAll('.expire-now-btn').forEach(function(b) { b.disabled = false; });
        cb.disabled = false;
    }
}
