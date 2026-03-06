---
name: remote-access
description: Retrieve login credentials, API keys, and secrets (username, password, TOTP) from the user's Bitwarden vault via bw-remote. Use when you need credentials to sign into a website or service, or need an API key.
user-invocable: true
metadata: {"openclaw":{"requires":{"bins":["bw-remote"]}}}
---

Use this skill when you need to sign into a website, retrieve a login, look up a password, or get a TOTP code. `bw-remote` fetches credentials (username, password, TOTP, URI, notes) from the user's Bitwarden vault through a trusted paired device.

## When to use this

- The user asks you to log into a website or service
- You need a username and/or password for a domain
- You need a TOTP / 2FA code for authentication
- You need an API key or secret stored in the vault
- The user says "get my credentials for X" or "sign into X"

## Quick start (agent flow)

**Step 1** — Check for an existing session:
```bash
bw-remote cache list
```

**Step 2** — Fetch the credential using the website's domain:
```bash
bw-remote --domain example.com --output json
```
If only one session is cached, it auto-selects. With multiple sessions, add `--session <HEX>` (use a fingerprint or unique prefix from `cache list`).

**Step 3** — Parse the JSON output:
```json
{
  "success": true,
  "domain": "example.com",
  "credential": {
    "username": "user@example.com",
    "password": "s3cret",
    "totp": "123456",
    "uri": "https://example.com/login",
    "notes": "optional notes"
  }
}
```
Use `credential.username` and `credential.password` to sign in. If the site requires 2FA, use `credential.totp`.

## If no session exists

The user must pair with a trusted device first. Ask them to:
1. Run `bw-remote listen` on their trusted device
2. Give you the 6-character rendezvous code (e.g. `ABC-DEF`)

Then connect with:
```bash
bw-remote --domain example.com --token <CODE> --output json
```

Alternatively, for PSK tokens (format: `<64-hex-psk>_<64-hex-fingerprint>`):
```bash
bw-remote --domain example.com --token <PSK_TOKEN> --output json
```

Sessions are cached in `~/.bw-remote/` for future use — subsequent requests don't need a token.

## Domain matching

Use the bare domain of the website you need credentials for:
- `github.com` (not `https://github.com/login`)
- `accounts.google.com` (not `https://accounts.google.com/v3/signin`)
- `aws.amazon.com`

## All options

| Flag | Description |
|------|-------------|
| `--domain <DOMAIN>` | Website domain to fetch credentials for (required for non-interactive use) |
| `--token <TOKEN>` | Rendezvous code or PSK token for new pairing (conflicts with `--session`) |
| `--session <HEX>` | Session fingerprint or unique prefix (conflicts with `--token`) |
| `--proxy-url <URL>` | WebSocket proxy address (default: `wss://rat1.lesspassword.dev`) |
| `--output json\|text` | Output format (default: `text`; use `json` for programmatic access) |
| `--no-cache` | Don't cache this session |
| `--verify-fingerprint` | Require fingerprint verification |
| `-v` | Verbose logging |

## Session management

```bash
bw-remote cache list                          # List all cached sessions
bw-remote cache clear                         # Clear all sessions and identity keys
bw-remote cache clear sessions                # Clear sessions only, keep identity key
```

## Error handling

On failure, JSON output:
```json
{"success": false, "error": {"message": "...", "code": "connection_failed"}}
```

Exit codes:
| Code | Meaning | What to do |
|------|---------|------------|
| 0 | Success | Parse credential from output |
| 1 | General error | Check stderr for details |
| 2 | Connection failed | Proxy may be down; retry or check `--proxy-url` |
| 3 | Auth/handshake failed | Session may be stale; clear cache and re-pair |
| 4 | Credential not found | No matching login for that domain in the vault |
| 5 | Fingerprint mismatch | Security issue; do not proceed, alert the user |

If exit code is 3, try `bw-remote cache clear sessions` and ask the user for a new token.
If exit code is 4, confirm the domain with the user — they may store it under a different name.
