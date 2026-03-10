# bw-proxy

A WebSocket relay server for `bw-remote` that routes messages between authenticated clients without access to message contents.

For the client library, see [`bw-proxy-client`](../bw-proxy-client/).
For shared protocol types, see [`bw-proxy-protocol`](../bw-proxy-protocol/).

## Quick Start

### Running the Proxy Server

```bash
cargo run --bin bw-proxy
```

The server will start listening on `ws://localhost:8080` by default.

### Embedding in Your Application

```rust
use bw_proxy::server::ProxyServer;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let server = ProxyServer::new(addr);
    server.run().await?;
    Ok(())
}
```

## Architecture

The proxy implements a three-phase protocol:

### 1. Authentication Phase

- Client connects to proxy via WebSocket
- Server sends a cryptographic challenge
- Client signs the challenge with its cryptographic identity
- Server verifies the signature and authenticates the client
- This establishes the client's identity

### 2. Rendezvous Phase (Optional)

- Clients can request temporary rendezvous codes (e.g., "ABC-DEF-GHI")
- Other clients can look up an identity by providing the code
- Enables peer discovery without sharing long-lived identifiers

### 3. Messaging Phase

- Authenticated clients can send messages to other clients by fingerprint
- Messages are routed through the proxy server
- The proxy validates the source identity but cannot decrypt message contents
