# ap-proxy-client

A client library for connecting to an `ap-proxy` WebSocket server.

## Overview

`ap-proxy-client` provides `ProxyProtocolClient` for connecting to a proxy server, authenticating with cryptographic identities, and exchanging messages with other clients. It uses rustls for TLS.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
ap-proxy-client = "0.1.0"
```

Basic client example:

```rust
use ap_proxy_client::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ProxyClientConfig {
        proxy_url: "ws://localhost:8080".to_string(),
        identity_keypair: None, // Generates a new identity
    };

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
                    println!("Your pairing token: {}", code.as_str());
                }
                IncomingMessage::IdentityInfo { identity, .. } => {
                    println!("Found peer: {:?}", identity.fingerprint());
                }
            }
        }
    });

    // Request a pairing token for others to find you
    client.request_rendezvous().await?;

    Ok(())
}
```
