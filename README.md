# bitback.one

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/bitback/bitback.one)

Secure one-time links with zero-trust encryption.

Share passwords, API keys, and confidential data through self-destructing links. The server never sees the decryption key — everything is encrypted and decrypted in the browser.

**Live:** [bitback.one](https://bitback.one)

## How it works

1. You type content and optionally mark fragments as **secret** (Ctrl+E)
2. Content is encrypted with AES-256-CBC in the browser
3. A link is generated: `https://bitback.one/<uuid>#<key>`
4. The `#key` part (URL fragment) **never reaches the server** — not in logs, not in memory
5. The recipient opens the link — decryption happens entirely in their browser

## Two-stage expiration

bitback.one uses a two-blob architecture for physical secret destruction:

| Stage | What happens |
|-------|-------------|
| **Secrets expire** (by time or view count) | The encrypted secrets blob is **physically deleted** from the JSON file. Irreversible — even with the key, secrets cannot be recovered. Plain text sections remain visible as context. |
| **Permanent deletion** (configurable delay) | The entire file is moved to trash. All data gone. |

This is not a software flag — the encrypted data is literally removed from disk.

## Security model

- **AES-256-CBC** encryption with SHA-256 key derivation
- Encryption key lives in URL `#fragment` — never sent to the server (per RFC 3986)
- Server stores only encrypted blobs — no plaintext, no key, no way to decrypt
- Two separate encrypted blobs: text and secrets — server physically deletes the secrets blob on expiry
- Optional bcrypt password protection
- Apache logs show only the UUID, never the key
- IP-based rate limiting (10 links/hour)
- Honeypot + math challenge anti-bot protection

See [SECURITY.md](SECURITY.md) for the full threat model.

## Security philosophy

bitback.one is deliberately simple. We treat minimalism as a security feature, not a limitation.

**Why no SIEM, audit logs, or monitoring?** The attack surface is tiny: 2 endpoints, flat file storage, zero external dependencies, no database, no sessions, no user accounts. There is nothing to monitor because there is nothing to compromise on the server side - the server never sees plaintext data or encryption keys.

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
sha384-lbGxH8AFxpkiMqDgkudynUSMoMFVnfMkcjN4XwCJHaTu9mLjvW4emijB7r3kh7MU
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
- **Frontend:** Vanilla HTML/CSS/JS
- **Crypto:** Web Crypto API (browser) + OpenSSL (PHP)
- **Server:** Apache2 with mod_rewrite
- **Hosting:** Synology NAS (Web Station)

## Project structure

```
bitback.one/
├── index.php           # Main page (create link form, i18n)
├── view.php            # Link viewer (password check, expiry, encrypted payload delivery)
├── crypto.js           # Client-side crypto functions (SRI-protected, verifiable)
├── .htaccess           # URL rewriting (UUID -> view.php)
├── api/
│   └── create.php      # POST API: validate, encrypt, save, return URL
├── inc/
│   ├── config.php      # Constants (paths, defaults, cipher)
│   ├── crypto.php      # AES-256-CBC encrypt/decrypt, UUID/key generation (server-side)
│   ├── i18n.php        # PL/EN translations (auto-detect from Accept-Language)
│   └── ratelimit.php   # IP-based rate limiter
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
define('APP_NAME', 'bitback.one');    // App name (used in titles, headers)
define('DEFAULT_EXPIRE_DAYS', 14);    // Secret data expiration
define('DEFAULT_MAX_VIEWS', 5);       // Max views before secrets expire
define('DEFAULT_DELETE_DAYS', 90);    // Days until permanent deletion
define('RATE_LIMIT_MAX', 10);         // Max links per IP per hour
```

### Custom branding

The app auto-detects its domain from HTTP headers — generated URLs always match your server. To change the app name shown in titles and headers, edit `APP_NAME` in `inc/config.php`. The main page (`index.html`) has two hardcoded references to update manually.

## i18n

Auto-detects Polish or English from the browser's `Accept-Language` header. Translations are in `inc/i18n.php`.

## License

[MIT](LICENSE)

---

### Built by [bitback.pl](https://bitback.pl)

**Zabezpieczamy pocztę, serwery i komputery.**

bitback.one to projekt open-source od bitback.pl — firmy specjalizującej się w cyberbezpieczeństwie dla biznesu.

📧 [zbigniew.gralewski@bitback.pl](mailto:zbigniew.gralewski@bitback.pl)
📞 609 505 065
👤 Zbigniew Gralewski
