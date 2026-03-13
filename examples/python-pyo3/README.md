# Bitwarden Remote Access — PyO3 Python Bindings

Thin Python bindings around the Rust `RemoteClient` via [PyO3](https://pyo3.rs). Uses the exact same crypto and protocol code as the `aac` CLI binary — no reimplementation.

## Setup

Requires Python 3.9+ and a Rust toolchain.

```bash
cd examples/python-pyo3
python -m venv .venv
source .venv/bin/activate
pip install maturin
maturin develop
```

## Demo Flow

### 1. Start the Rust proxy server

```bash
cargo run --bin bw-proxy
```

### 2. Start the Rust UserClient (listen side)

```bash
cargo run --bin aac -- listen
```

Copy the rendezvous code displayed (e.g., `ABC-DEF-GHI`).

### 3. Run the Python RemoteClient

```bash
python connect_request.py --token ABC-DEF-GHI --domain example.com
```

### 4. Approve on the listen side

On the Rust listen side, approve the credential request when prompted.

## Connection Modes

### Rendezvous Code (new connection)

```bash
python connect_request.py --token ABC-DEF-GHI --domain example.com
```

### PSK Token (pre-shared key)

```bash
python connect_request.py --token "<64hex_psk>_<64hex_fingerprint>" --domain example.com
```

### Cached Session (reconnection)

After the first connection, session state is cached at `~/.bw-remote/`:

```bash
# Auto-select if only one cached session exists
python connect_request.py --domain example.com

# Specify a session by fingerprint
python connect_request.py --session <fingerprint_hex> --domain example.com
```

## Programmatic Usage

```python
from bw_remote_rs import RemoteClient

client = RemoteClient(proxy_url="ws://localhost:8080")
client.connect(token="ABC-DEF-GHI")

cred = client.request_credential("example.com")
print(f"Username: {cred.username}")
print(f"Password: {cred.password}")

client.close()
```

Note: unlike the pure-Python SDK, the PyO3 API is **synchronous** — it runs a Tokio runtime internally.

## Architecture

| File | Purpose |
|------|---------|
| `src/lib.rs` | PyO3 module definition, `connect_and_request()` one-shot helper |
| `src/client.rs` | `PyRemoteClient` — wraps Rust `RemoteClient` with an internal Tokio runtime |
| `src/storage.rs` | `FileIdentityStorage` + `FileSessionCache` — file-based identity and session persistence |
| `src/types.rs` | `PyCredentialData` + `RemoteAccessError` — Python-facing types |

All crypto, handshake, and transport logic is delegated to the workspace crates (`bw-noise-protocol`, `bw-rat-client`, `bw-proxy-client`).
