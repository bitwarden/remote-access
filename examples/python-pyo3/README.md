# Bitwarden Remote Access — PyO3 Python Bindings

Thin Python bindings around the Rust `RemoteClient` via [PyO3](https://pyo3.rs). Uses the exact same crypto and protocol code as the `aac` CLI binary — no reimplementation.

## Setup

Requires Python 3.9+ and a Rust toolchain.

```bash
cd examples/python-pyo3
python3 -m venv .venv
source .venv/bin/activate
pip install maturin
maturin develop
```

## Demo Flow

### 1. Start the Rust UserClient (listen side)

```bash
cargo run --bin aac -- listen
```

Copy the rendezvous code displayed (e.g., `ABC-DEF-GHI`).

### 2. Pair from Python

```bash
python3 pair.py --token ABC-DEF-GHI
```

Or with a PSK token:

```bash
python3 pair.py --token "<64hex_psk>_<64hex_fingerprint>"
```

This clears any existing cached connection and pairs with the listener. Only one connection is kept at a time.

### 3. Request a credential

```bash
python3 get.py --domain example.com
```

Uses the cached connection from step 2. Approve the request on the listen side.

## Programmatic Usage

```python
from bw_remote_rs import RemoteClient

# Pair (clears previous connection)
client = RemoteClient(proxy_url="wss://ap.lesspassword.dev")
client.clear_connections()
client.connect(token="ABC-DEF-GHI")
client.close()

# Later — request a credential using cached connection
client = RemoteClient(proxy_url="wss://ap.lesspassword.dev")
client.connect()
cred = client.request_credential("example.com")
print(f"Username: {cred.username}")
print(f"Password: {cred.password}")
client.close()
```

The API is **synchronous** — all async Rust operations are handled internally.

## Architecture

| File | Purpose |
|------|---------|
| `pair.py` | Pair with a listening peer (clears and replaces cached connection) |
| `get.py` | Request a credential using the cached connection |
| `src/lib.rs` | PyO3 module definition, `connect_and_request()` one-shot helper |
| `src/client.rs` | `PyRemoteClient` — wraps Rust `RemoteClient` with a synchronous Python API |
| `src/storage.rs` | `FileIdentityStorage` + `FileConnectionCache` — file-based identity and connection persistence |
| `src/types.rs` | `PyCredentialData` + `RemoteAccessError` — Python-facing types |

All crypto, handshake, and transport logic is delegated to the workspace crates (`bw-noise-protocol`, `bw-rat-client`, `bw-proxy-client`).
