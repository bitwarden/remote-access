---
name: remote-access
description: Request credentials from a trusted Bitwarden device via bw-remote
user-invocable: true
metadata: {"openclaw":{"requires":{"bins":["bw-remote"]}}}
---

You help users request credentials from a trusted Bitwarden device using `bw-remote`.

## Single-Shot Mode (Non-Interactive)

Use `--domain` to trigger single-shot mode. Output goes to stdout, status to stderr.

### Retrieve a credential (one cached session auto-selected)

```bash
bw-remote --domain example.com --output json
```

### Retrieve a credential (specify session)

```bash
bw-remote --domain example.com --session <HEX> --output json
```

### New connection with rendezvous code

```bash
bw-remote --domain example.com --token <RENDEZVOUS_CODE> --output json
```

### New connection with PSK token

```bash
bw-remote --domain example.com --token <64-hex-psk>_<64-hex-fingerprint> --output json
```

## Session Management

```bash
bw-remote cache list                          # List all cached sessions
bw-remote cache clear                         # Clear all sessions and identity keys
bw-remote cache clear sessions                # Clear sessions only, keep identity key
bw-remote cache list --client-type remote     # List only remote (connect) side
```

## All Connect Options

| Flag | Description |
|------|-------------|
| `--domain <DOMAIN>` | Domain to request credentials for (enables single-shot mode) |
| `--token <TOKEN>` | Rendezvous code or PSK token (conflicts with `--session`) |
| `--session <HEX>` | Session fingerprint or unique prefix to reconnect (conflicts with `--token`) |
| `--proxy-url <URL>` | WebSocket proxy address (default: `wss://rat1.lesspassword.dev`) |
| `--output <FORMAT>` | `text` (default) or `json` |
| `--no-cache` | Disable session caching |
| `--verify-fingerprint` | Require fingerprint verification |
| `-v, --verbose` | Enable verbose logging |

## Output Formats

### JSON (--output json)

Success:
```json
{"success": true, "domain": "example.com", "credential": {"username": "user", "password": "pass", "totp": "123456", "uri": "https://example.com", "notes": null}}
```

Error:
```json
{"success": false, "error": {"message": "...", "code": "connection_failed"}}
```

### Text (--output text)

```
domain: example.com
username: user
password: pass
totp: 123456
uri: https://example.com
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Connection failed |
| 3 | Auth/handshake failed |
| 4 | Credential not found |
| 5 | Fingerprint mismatch |

## Workflow

1. Run `bw-remote cache list` to check for existing sessions
2. If a session exists, use `bw-remote --domain <DOMAIN> --session <HEX> --output json`
3. If only one session is cached, `--session` can be omitted — it auto-selects
4. If no sessions exist, the user must provide a `--token` from a trusted device running `bw-remote listen`
5. Parse the JSON output for `"success": true` and extract credentials from the `credential` object

## Prerequisites

- A trusted device must already be listening via `bw-remote listen`
- Sessions are cached in `~/.bw-remote/` for future reconnection
- `--session` accepts a full 64-char hex fingerprint or any unique prefix from `cache list`
