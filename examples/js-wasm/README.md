# JavaScript WASM Example

Browser-based remote access client using WebAssembly. Wraps the Rust `RemoteClient` via `wasm-bindgen`, providing a native JavaScript async API.

## Prerequisites

- [Rust](https://rustup.rs/) (1.85+)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [Node.js](https://nodejs.org/) (18+)
- A user-client listening (`cargo run --bin aac -- listen`)

## Build & Run

```bash
# 1. Build the WASM package
./build.sh

# 2. Install JS dependencies and start dev server
npm install
npm run dev
```

Then in a separate terminal, start a listener:

```bash
cargo run --bin aac -- listen --proxy wss://ap.lesspassword.dev
```

Open the URL shown by Vite (default http://localhost:5173), paste the rendezvous code, click **Connect**, enter a domain, and click **Request Credential**.

### Manual WASM build

```bash
wasm-pack build --target web --out-dir pkg
```

## Programmatic Usage

```javascript
import { createClient } from "./remote-access.js";

const client = await createClient("wss://ap.lesspassword.dev");

// Pair with a new device
await client.pair("ABC-DEF-GHI");

// Or reconnect to a saved session
// await client.reconnect(fingerprint);

// Request a credential
const cred = await client.getCredential("example.com");
console.log(cred.username, cred.password, cred.totp);

// Disconnect
client.disconnect();
```

## API

### `await createClient(proxyUrl, identityName?)`

Create a client. Identity and sessions are persisted in `localStorage`.

### `await client.pair(token)`

Pair with a new device using a rendezvous code (`"ABC-DEF-GHI"`) or PSK token. Returns the handshake fingerprint for rendezvous, or `null` for PSK.

### `await client.reconnect(fingerprint)`

Reconnect to a previously paired device using its hex fingerprint.

### `await client.getCredential(domain)`

Request credentials for a domain. Returns `{ username, password, totp, uri, notes, credential_id, domain }`.

### `await client.listConnections()`

List saved connections. Returns `[{ fingerprint, name, cachedAt, lastConnectedAt }]`.

### `client.clearConnections()`

Clear all saved connections from localStorage.

### `client.disconnect()`

Disconnect and release resources.

## Architecture

| Component | Implementation |
|-----------|---------------|
| WebSocket transport | `web_sys::WebSocket` (browser native) |
| Identity storage | `localStorage` (COSE-encoded keypair) |
| Session cache | `localStorage` (JSON) |
| Crypto | Noise NNpsk2 via `ap-noise` (compiled to WASM) |
| Async runtime | `wasm-bindgen-futures::spawn_local` |

## Limitations

- Browser only (uses `web_sys::WebSocket` and `localStorage`)
- Post-quantum crypto is disabled (PQ keys are too large for WASM stack)
- No fingerprint verification UI (headless mode only)
