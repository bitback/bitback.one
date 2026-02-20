# Security Model

## Architecture: zero-trust encryption

bitback.one is designed so that **the server operator cannot read user data**, even with full access to the server, database, and source code.

### Key in URL fragment

The decryption key is placed after the `#` in the URL:

```
https://bitback.one/550e8400-e29b-41d4-a716-446655440000#a1b2c3d4e5f6a7b8
```

Per [RFC 3986 §3.5](https://datatracker.ietf.org/doc/html/rfc3986#section-3.5), the fragment identifier is **never sent to the server**. This means:

- Apache access logs contain only the UUID
- PHP `$_SERVER` variables never see the key
- The key exists only in the sender's and recipient's browser

### Client-side cryptography

| Operation | Where | Method |
|-----------|-------|--------|
| Encryption | Browser (sender) | AES-256-CBC via Web Crypto API |
| Decryption | Browser (recipient) | AES-256-CBC via Web Crypto API |
| Key derivation | Both sides | SHA-256 hash of hex key string |
| Password hashing | Server | bcrypt (for optional password protection) |

The server performs **zero cryptographic operations** on user content. It stores and serves encrypted blobs — nothing more.

### Two-blob architecture

Content is split into two separately encrypted blobs at creation time:

- `encrypted_text` — non-secret sections (survive secret expiry)
- `encrypted_secrets` — secret-marked sections (physically destroyed on expiry)

When secrets expire, the server **deletes the `encrypted_secrets` field from the JSON file**. This is not a flag or permission check — the ciphertext is gone from disk. Even someone with the decryption key and full server access cannot recover expired secrets.

## Threat model

### What we protect against

| Threat | Mitigation |
|--------|-----------|
| Server operator reads data | Cannot — key never reaches server |
| Server logs leak key | Fragment is not logged (RFC 3986) |
| Expired secrets recovered | Physically deleted from disk, not flagged |
| Brute-force link creation | IP rate limiting (10/hour) + math challenge |
| Automated bot abuse | Honeypot field + math verification |
| Password brute-force | bcrypt hashing with cost factor |
| Man-in-the-middle | HTTPS required (also needed for Web Crypto API) |

### What we do NOT protect against

| Threat | Why |
|--------|-----|
| Compromised browser | If the recipient's browser is compromised, the attacker sees decrypted content |
| Screenshot/copy after decryption | Once decrypted in the browser, the recipient can copy the content |
| Link interception before opening | If someone intercepts the full URL (with fragment), they can open the link |
| Server-side code modification | A malicious server operator could modify JS to exfiltrate data — mitigated by open source (verify the code) |

### Kerckhoffs's principle

The security of bitback.one relies entirely on the secrecy of the key, not the secrecy of the code. Open-sourcing the code allows independent verification of the security model.

## Responsible disclosure

If you find a security vulnerability, please open a GitHub issue or contact us at security@bitback.pl.
