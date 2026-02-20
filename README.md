# bitback.one

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
├── index.html          # Main page (create link form)
├── view.php            # Link viewer (password check, expiry, encrypted payload delivery)
├── .htaccess           # URL rewriting (UUID → view.php)
├── api/
│   └── create.php      # POST API: validate, encrypt, save, return URL
├── inc/
│   ├── config.php      # Constants (paths, defaults, cipher)
│   ├── crypto.php      # AES-256-CBC encrypt/decrypt, UUID/key generation
│   ├── i18n.php        # PL/EN translations (auto-detect from Accept-Language)
│   └── ratelimit.php   # IP-based rate limiter
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
define('DEFAULT_EXPIRE_DAYS', 14);    // Secret data expiration
define('DEFAULT_MAX_VIEWS', 5);       // Max views before secrets expire
define('DEFAULT_DELETE_DAYS', 90);    // Days until permanent deletion
define('RATE_LIMIT_MAX', 10);         // Max links per IP per hour
```

## i18n

Auto-detects Polish or English from the browser's `Accept-Language` header. Translations are in `inc/i18n.php`.

## License

[MIT](LICENSE)
