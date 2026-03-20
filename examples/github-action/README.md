# GitHub Actions — Reusable PSK Credential Fetch

Fetch credentials from a Bitwarden vault in CI using a reusable pre-shared key (PSK). Each workflow run performs a fresh Noise handshake — no cached sessions required.

## How it works

1. A trusted machine runs `aac listen --reusable-psk` with Bitwarden unlocked
2. The listener prints a 129-character PSK token (once)
3. GitHub Actions uses that token to connect, authenticate, and fetch credentials on every run

## One-time setup

### 1. Start the listener

On a trusted machine with the `bw` CLI unlocked:

```bash
aac listen --reusable-psk
```

Copy the printed PSK token.

### 2. Add GitHub secrets

| Secret | Value |
|--------|-------|
| `AAC_TOKEN` | The 129-char PSK token from step 1 |

### 3. Add the workflow

Copy `reusable-psk-credential.yml` into your repo's `.github/workflows/` directory and adjust the domain and credential usage to fit your needs.

## Adapting for other use cases

**Inject credentials into a command** — use `aac run` instead of `aac connect`:

```yaml
- name: Run with credentials
  run: |
    aac run \
      --domain "registry.example.com" \
      --ephemeral-connection \
      --env DOCKER_USER=username \
      --env DOCKER_PASS=password \
      -- sh -c 'echo "$DOCKER_PASS" | docker login registry.example.com -u "$DOCKER_USER" --password-stdin'
```

**Fetch by vault item ID** — replace `--domain` with `--id`:

```yaml
- name: Fetch by ID
  run: |
    aac connect \
      --id "12345678-1234-1234-1234-123456789abc" \
      --ephemeral-connection \
      --output json
```
