# bw-proxy

A WebSocket proxy client + server that can act as a transport for `bw-remote`.

## Overview

`bw-proxy` provides a relay server that enables secure peer-to-peer communication between clients without the server having access to message contents. It uses MlDsa65 post-quantum digital signatures for authentication and implements a rendezvous system for client discovery.

## Quick Start

### Running the Proxy Server

```bash
cargo run --bin bw-proxy
```

The server will start listening on `ws://localhost:8080` by default.

### Using as a Client Library

Add to your `Cargo.toml`:

```toml
[dependencies]
bw-proxy = "0.1.0"
```

Basic client example:

```rust
use bw_proxy::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client configuration
    let config = ProxyClientConfig {
        proxy_url: "ws://localhost:8080".to_string(),
        identity_keypair: None, // Generates a new identity
    };

    // Create and connect client
    let mut client = ProxyProtocolClient::new(config);
    let mut incoming = client.connect().await?;

    println!("Connected! Fingerprint: {:?}", client.fingerprint());

    // Handle incoming messages
    tokio::spawn(async move {
        while let Some(msg) = incoming.recv().await {
            match msg {
                IncomingMessage::Send { source, payload, .. } => {
                    println!("Message from {:?}: {:?}", source, payload);
                }
                IncomingMessage::RendevouzInfo(code) => {
                    println!("Your rendezvous code: {}", code.code());
                }
                IncomingMessage::IdentityInfo { identity, .. } => {
                    println!("Found peer: {:?}", identity.fingerprint());
                }
            }
        }
    });

    // Request a rendezvous code for others to find you
    client.request_rendezvous().await?;

    // Send a message to another client
    client.send_to(target_fingerprint, payload).await?;

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

- Clients can request temporary rendezvous codes (e.g., "ABC-DEF")
- Other clients can look up an identity by providing the code
- Enables peer discovery without sharing long-lived identifiers

### 3. Messaging Phase

- Authenticated clients can send messages to other clients by fingerprint
- Messages are routed through the proxy server
- The proxy validates the source identity but cannot decrypt message contents
