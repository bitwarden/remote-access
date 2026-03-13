# Bitwarden Remote Access — Python SDK Example

Python implementation of the **RemoteClient** (connect side) for the Bitwarden Remote Access protocol. Connects to a Rust `UserClient` through the WebSocket proxy and requests credentials programmatically.

## Setup

```bash
cd examples/python
python -m venv .venv
source .venv/bin/activate
pip install -e .
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
# Connect via rendezvous code and request a credential
python examples/connect_request.py --token ABC-DEF-GHI --domain example.com

# With verbose logging
python examples/connect_request.py --token ABC-DEF-GHI --domain example.com -v
```

### 4. Approve on the listen side

On the Rust listen side, approve the credential request when prompted.

## Connection Modes

### Rendezvous Code (new connection)

```bash
python examples/connect_request.py --token ABC-DEF-GHI --domain example.com
```

### PSK Token (pre-shared key)

```bash
python examples/connect_request.py --token "<64hex_psk>_<64hex_fingerprint>" --domain example.com
```

### Cached Session (reconnection)

After the first connection, session state is cached at `~/.bw-remote/`:

```bash
# Auto-select if only one cached session exists
python examples/connect_request.py --domain example.com

# Specify a session by fingerprint
python examples/connect_request.py --session <fingerprint_hex> --domain example.com
```

## Programmatic Usage

```python
import asyncio
from bw_remote import RemoteClient

async def main():
    client = RemoteClient(proxy_url="ws://localhost:8080")
    await client.connect(token="ABC-DEF-GHI")

    cred = await client.request_credential("example.com")
    if cred:
        print(f"Username: {cred.username}")
        print(f"Password: {cred.password}")

    await client.close()

asyncio.run(main())
```

## Architecture

| Module | Purpose | Rust Reference |
|--------|---------|----------------|
| `identity.py` | Ed25519 keypair, COSE encoding, fingerprints | `bw-proxy-protocol/src/auth.rs` |
| `psk.py` | Pre-shared key type | `bw-noise-protocol/src/psk.rs` |
| `packet.py` | HandshakePacket, TransportPacket (CBOR) | `bw-noise-protocol/src/packet.rs` |
| `noise_handshake.py` | NNpsk2 initiator handshake | `bw-noise-protocol/src/handshake.rs` |
| `transport.py` | XChaCha20-Poly1305 transport encryption | `bw-noise-protocol/src/transport.rs` |
| `protocol_messages.py` | ProtocolMessage JSON types | `bw-rat-client/src/types.rs` |
| `proxy_client.py` | WebSocket proxy client | `bw-proxy-client/src/protocol_client.rs` |
| `session_store.py` | Session persistence | `bw-remote/src/storage/` |
| `remote_client.py` | RemoteClient orchestrator | `bw-rat-client/src/clients/remote_client.rs` |

## Dependencies

- `websockets` — WebSocket client
- `PyNaCl` — Ed25519 signatures + XChaCha20-Poly1305 AEAD
- `cbor2` — CBOR encoding (COSE keys, packets, transport state)
- `dissononce` — Noise protocol NNpsk2 handshake
