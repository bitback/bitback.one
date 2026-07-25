# bitback.one

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/bitback/bitback.one)

Secure one-time links with zero-trust encryption.

Share passwords, API keys, and confidential data through one-time links that physically delete the secrets on expiry. The server never sees the decryption key - everything is encrypted and decrypted in the browser.

**Live:** [bitback.one](https://bitback.one)

## How it works

1. You type content and optionally mark fragments as **secret** (Ctrl+E)
2. Content is encrypted with **AES-256-GCM** in the browser
3. A link is generated: `https://bitback.one/<uuid>#<key>`
4. The `#key` part (URL fragment) **never reaches the server** - not in logs, not in memory
5. The recipient opens the link - decryption happens entirely in their browser

New links use AES-256-GCM (record format 3). Older AES-256-CBC links (format 2) stay readable until they expire - the crypto layer keeps a read-only path for them.

## Two-stage expiration

bitback.one uses a two-blob architecture for physical secret destruction:

| Stage | What happens |
|-------|-------------|
| **Secrets expire** (by time or view count) | The encrypted secrets blob is **physically deleted** from the JSON file. Irreversible - even with the key, secrets cannot be recovered. Plain text sections remain visible as context. |
| **Permanent deletion** (configurable delay) | The entire file is moved to trash. All data gone. |

This is not a software flag - the encrypted data is literally removed from disk.

## Optional open password (zero-knowledge)

You can lock a link behind a password the recipient must type before anything decrypts. The server never sees it.

- The browser derives `master = PBKDF2-HMAC-SHA256(password, salt, 600k iterations)`, then splits it with HKDF into the AES key and a separate `auth_tag`.
- Only the `auth_tag` is sent to the server, which stores `password_verifier = sha256(auth_tag)` and compares with `hash_equals`.
- A wrong password is rejected at the gate and **does not burn a view**.
- The AES key itself depends on the password, so a forgotten password means the data is **unrecoverable** - there is no reset.

The record carries its own KDF parameters (`format:3`, `kdf:{alg,iter}`), so iteration counts can be raised or the scheme upgraded later without breaking old links. Legacy links use bcrypt server-side verification (read-only).

## Bulk links

Paste a table (for example straight from Excel) and bitback.one generates **one separate encrypted link per row** - each recipient gets their own link with its own AES key. Up to 200 recipients per batch. The "after expiry" preview shows a single recipient's record (masked values), because each person only ever sees their own link, never the whole table.

## TOTP QR

If the decrypted content contains an `otpauth://totp/...` URI, the viewer renders a scannable QR code beneath it, so the recipient can enroll it in an authenticator app. Like everything else, this happens client-side - the TOTP secret never leaves the browser.

## Programmatic access (bring your own client)

The browser is only the reference client. The server is a pure zero-trust store: it accepts and returns encrypted blobs it cannot read, and never touches the key. Anything the browser does - derive a key, encrypt, assemble the `#fragment` link - can be done by your own code against the same HTTP API.

- Endpoints `api/create.php` and `api/create-batch.php` accept a Bearer API token (`Authorization: Bearer bbk_<id>_<secret>`).
- The server stores only a SHA-256 fingerprint of each token, never the token itself.
- Token auth skips the interactive anti-bot challenge, but not the payload format or KDF validation - a client must still produce well-formed encrypted records.

A language-agnostic implementation of the crypto contract and a CLI client exist internally (used for machine-to-machine delivery of secrets); they are not published in this repository. The point is that the format is a documented contract, not a browser lock-in: the server side needed to accept programmatic clients is the public code in this repo.

## Security model

- **AES-256-GCM** encryption for new links (AES-256-CBC kept read-only for older ones)
- Encryption key lives in URL `#fragment` - never sent to the server (per RFC 3986)
- Server stores only encrypted blobs - no plaintext, no key, no way to decrypt
- Two separate encrypted blobs: text and secrets - server physically deletes the secrets blob on expiry
- Optional zero-knowledge open password - the server stores only `sha256(auth_tag)`, never the password
- Apache logs show only the UUID, never the key
- IP-based rate limiting (single links and bulk batches have separate hourly buckets)
- Honeypot + math challenge anti-bot protection (bypassed only by authenticated API tokens)

See [SECURITY.md](SECURITY.md) for the full threat model.

## Security philosophy

bitback.one is deliberately simple. We treat minimalism as a security feature, not a limitation.

**Why no SIEM, audit logs, or monitoring?** The attack surface is tiny: a handful of endpoints, flat file storage, zero external dependencies, no database, no sessions, no user accounts. There is nothing to monitor because there is nothing to compromise on the server side - the server never sees plaintext data or encryption keys.

**Browser-side verification.** All encryption and decryption happens in the browser using the Web Crypto API. This is verifiable: anyone can inspect the JavaScript source and confirm that the key never leaves the browser. The server receives only encrypted base64 blobs it cannot decrypt.

**The trust boundary.** The one thing you must trust is that the server serves unmodified JavaScript. A compromised server could theoretically serve malicious JS that leaks the key. This is a fundamental limitation of all web-based encryption tools (as opposed to native apps). bitback.one mitigates this with **Subresource Integrity (SRI)** and a published cryptographic hash - see [Crypto integrity verification](#crypto-integrity-verification) below.

**What we intentionally skip:**
- Enterprise features (SIEM, centralized logging, advanced threat detection) - they add complexity without improving the core security model
- Penetration testing infrastructure - the codebase is small enough to audit by reading it
- Server-side security hardening guides - deployment security depends on your hosting setup, not on this application

**What actually matters:**
- HTTPS (required for Web Crypto API)
- Keeping the server and PHP updated
- File permissions on `data/` and `trash/` directories
- Unmodified `crypto.js` (verified by SRI hash - see below)

## Crypto integrity verification

All cryptographic functions (key generation, encryption, decryption) live in a single file: [`crypto.js`](crypto.js). This file is loaded with [Subresource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) - the browser **refuses to execute it** if the content doesn't match the expected hash.

**Expected SHA-384 of `crypto.js`:**

```
sha384-RQoDrUypIasRu3YH/1KbhpaEtfmzmQlvafmSuNpL1E3zl8rpuvHzLF/C9jqmsD53
```

### Verify any deployment

You can check whether any bitback.one deployment serves the original, unmodified cryptographic code:

```bash
# Download crypto.js from the deployment and compute its hash
curl -s https://DEPLOYMENT-URL/crypto.js | openssl dgst -sha384 -binary | openssl base64 -A
# Compare the output with the hash above
```

If the hashes match, the deployment uses the exact same crypto code as this repository. If they don't - the code has been modified and should not be trusted.

### How it works

1. `crypto.js` contains **all** encryption/decryption logic (and nothing else)
2. `index.php` and `view.php` load it with `<script src="crypto.js" integrity="sha384-...">`
3. The browser verifies the hash **before executing** - modified code is blocked automatically
4. This repository publishes the expected hash - anyone can challenge any deployment
5. After any change to `crypto.js`, run `bash tools/update-crypto-hash.sh` to update hashes everywhere

### What this protects against

- CDN or reverse proxy injecting code into `crypto.js`
- Network-level MITM modifying the script in transit (defense in depth on top of HTTPS)
- Detecting unauthorized modifications on third-party deployments

### What this does NOT protect against

- A compromised server modifying the HTML itself (changing the `integrity` attribute or adding inline scripts). This is a fundamental limitation of web-based encryption. The mitigation: **self-host and verify the source**, or use the curl command above to spot-check deployments.

## Tech stack

- **Backend:** PHP 8.0 (no framework, no dependencies)
- **Storage:** Flat JSON files (no database)
- **Frontend:** Vanilla HTML/CSS/JS (self-hosted fonts and inline SVG icons, zero CDN)
- **Crypto:** Web Crypto API (browser, AES-256-GCM + PBKDF2/HKDF) + OpenSSL (PHP)
- **Server:** Apache2 with mod_rewrite
- **Hosting:** Synology NAS (Web Station)

## Project structure

```
bitback.one/
├── index.php           # Main page (create link form, bulk table, i18n)
├── view.php            # Link viewer (password gate, expiry, encrypted payload delivery, TOTP QR)
├── crypto.js           # Client-side crypto functions (SRI-protected, verifiable)
├── .htaccess           # URL rewriting (UUID -> view.php)
├── api/
│   ├── create.php      # POST API: validate, save encrypted record, return URL
│   ├── create-batch.php# POST API: bulk records in one request
│   ├── challenge.php   # Anti-bot math/honeypot challenge issuer
│   └── expire.php      # Manual expire/kill of a link
├── inc/
│   ├── config.php      # Constants (paths, defaults, limits, cipher)
│   ├── crypto.php      # Server-side helpers, AES-256-CBC decrypt for legacy records
│   ├── apiauth.php     # Bearer API-token verification (stores only token hash)
│   ├── antibot.php     # HMAC-signed challenge validation
│   ├── i18n.php        # PL/EN translations (auto-detect from Accept-Language)
│   ├── icons.php       # Inline Lucide SVG icons (no external requests)
│   └── ratelimit.php   # IP-based rate limiter (single + batch buckets)
├── assets/js/
│   ├── totp-qr.js      # Renders a QR for otpauth:// URIs, client-side
│   └── qrcode.min.js   # QR generator
├── tools/
│   └── update-crypto-hash.sh  # Update SRI hashes after crypto.js changes
├── cron/
│   └── cleanup.php     # Daily cleanup: expire secrets, delete old files
├── data/               # Runtime: encrypted JSON files (gitignored)
└── trash/              # Runtime: deleted files (gitignored)
```

## Self-hosting

### Requirements

- PHP 8.0+ with OpenSSL extension
- Apache2 with `mod_rewrite` enabled
- HTTPS (required for Web Crypto API)

### Installation

```bash
git clone https://github.com/bitback/bitback.one.git
cd bitback.one
```

The `data/`, `data/_ratelimit/`, and `trash/` directories are created automatically on first use. Just make sure the web server user (e.g. `www-data`) has write permissions to the project root:

```bash
chown -R www-data:www-data /path/to/bitback.one  # adjust for your setup
```

### Apache config

The included `.htaccess` handles URL rewriting. Make sure `AllowOverride All` is set for your vhost, or copy the rewrite rules to your Apache config.

### Cron

Set up daily cleanup (Synology Task Scheduler, crontab, etc.):

```bash
# Run once daily
0 3 * * * php /path/to/bitback.one/cron/cleanup.php
```

### Configuration

Edit `inc/config.php`:

```php
define('APP_NAME', 'bitback.one');       // App name (used in titles, headers)
define('DEFAULT_EXPIRE_DAYS', 30);       // Secret data expiration
define('DEFAULT_MAX_VIEWS', 15);         // Max views before secrets expire
define('DEFAULT_DELETE_DAYS', 360);      // Days until permanent deletion
define('RATE_LIMIT_MAX', 10);            // Max single links per IP per hour
define('RATE_LIMIT_BATCH_MAX', 10);      // Max bulk batches per IP per hour
define('BATCH_MAX_RECORDS', 200);        // Max recipients in one batch
define('IP_HASH_SALT', '...');           // Random secret, min 24 chars - change this
// define('APP_HOST', 'bitback.one');    // Optional: pin the host used in generated URLs
```

For bulk batches of up to 200 recipients, make sure the server's PHP limits (`post_max_size`, `memory_limit`, `max_execution_time`) are generous enough.

### Custom branding

The app auto-detects its domain from the request host - generated URLs always match your server. The host is validated against a hostname pattern before use; if you sit behind an untrusted proxy or want to pin it, set `APP_HOST` in `inc/config.php`. To change the app name shown in titles and headers, edit `APP_NAME`. The main page (`index.php`) has two hardcoded references to update manually.

## i18n

Auto-detects Polish or English from the browser's `Accept-Language` header. Translations are in `inc/i18n.php`.

## License

[GNU AGPL-3.0](LICENSE) (c) 2025 bitback

The source is published under the **GNU Affero General Public License v3.0**.
You are free to use, study, modify and self-host it - but any modified version
you run, including as a network service, must make its complete source available
under the same license.

**Commercial license available.** If you want to use bitback in a closed-source
or proprietary product without the AGPL's copyleft obligations, a separate
commercial license can be arranged - contact the author.

---

### Built by [bitback.pl](https://bitback.pl)

**Zabezpieczamy pocztę, serwery i komputery.**

bitback.one to projekt open-source od bitback.pl - firmy specjalizującej się w cyberbezpieczeństwie dla biznesu.

📧 [zbigniew.gralewski@bitback.pl](mailto:zbigniew.gralewski@bitback.pl)
📞 609 505 065
👤 Zbigniew Gralewski
