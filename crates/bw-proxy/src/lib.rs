//! WebSocket proxy
//!
//! `bw-proxy` provides both a relay server and client library for secure peer-to-peer messaging.
//! For authentication, a challenge-response using cryptographic identities is used.
//!
//! # Architecture
//!
//! The proxy operates as a message relay between authenticated clients:
//!
//! ```text
//! Client A                    Proxy Server                   Client B
//!    |                             |                             |
//!    |---(1) WebSocket Connect---->|                             |
//!    |<--(2) Auth Challenge--------|                             |
//!    |---(3) Signed Response------>|                             |
//!    |                             |<---(1) WebSocket Connect----|
//!    |                             |----(2) Auth Challenge------>|
//!    |                             |<---(3) Signed Response------|
//!    |                             |                             |
//!    |---(4) Request Rendezvous--->|                             |
//!    |<--(5) Code: "ABC-DEF"-------|                             |
//!    |                             |                             |
//!    |                             |<---(6) Lookup "ABC-DEF"-----|
//!    |                             |----(7) Identity of A------->|
//!    |                             |                             |
//!    |                             |<---(8) Encrypted Message----|
//!    |<--(9) Relay Message---------|                             |
//! ```
//!
//! ## Three-Phase Protocol
//!
//! ### Phase 1: Authentication
//!
//! When a client connects, the server sends a cryptographic challenge. The client signs this
//! challenge with its identity key pair and sends the response back. The server verifies
//! the signature to authenticate the client's identity. This proves possession of the private
//! key without revealing it.
//!
//! ### Phase 2: Rendezvous (Optional)
//!
//! Clients can request temporary rendezvous codes (e.g., "ABC-DEF") that are valid for 5 minutes.
//! Other clients can look up an identity by providing the code, enabling peer discovery without
//! exchanging long-lived identifiers. Codes are single-use and expire automatically.
//!
//! ### Phase 3: Messaging
//!
//! Once authenticated, clients can send messages to other clients by their identity fingerprint.
//! The proxy validates the source identity and routes messages to the destination. The proxy
//! cannot decrypt message contents - clients should implement end-to-end encryption separately.
//!
//! # Usage Modes
//!
//! ## As a Client Library
//!
//! Use [`ProxyProtocolClient`] to connect to a proxy server:
//!
//! ```no_run
//! use bw_proxy::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ProxyClientConfig {
//!     proxy_url: "ws://localhost:8080".to_string(),
//!     identity_keypair: None, // Generates new identity
//! };
//!
//! let mut client = ProxyProtocolClient::new(config);
//! let mut incoming = client.connect().await?;
//!
//! // Handle incoming messages
//! tokio::spawn(async move {
//!     while let Some(msg) = incoming.recv().await {
//!         match msg {
//!             IncomingMessage::Send { source, payload, .. } => {
//!                 println!("Message from {:?}", source);
//!             }
//!             IncomingMessage::RendevouzInfo(code) => {
//!                 println!("Your code: {}", code.as_str());
//!             }
//!             IncomingMessage::IdentityInfo { identity, .. } => {
//!                 println!("Found peer: {:?}", identity.fingerprint());
//!             }
//!         }
//!     }
//! });
//!
//! // Request a rendezvous code
//! client.request_rendezvous().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## As a Binary Server
//!
//! Run the proxy server using the binary:
//!
//! ```bash
//! cargo run --bin bw-proxy
//! ```
//!
//! Or embed the server in your application using [`server::ProxyServer`]:
//!
//! ```no_run
//! use bw_proxy::server::ProxyServer;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let addr: SocketAddr = "127.0.0.1:8080".parse()?;
//! let server = ProxyServer::new(addr);
//! server.run().await?;
//! # Ok(())
//! # }
//! ```

pub mod auth;
pub mod client;
mod connection;
pub mod error;
pub mod messages;
pub mod rendevouz;
pub mod server;

pub use auth::{Challenge, ChallengeResponse, Identity, IdentityFingerprint, IdentityKeyPair};
pub use client::{IncomingMessage, ProxyClientConfig, ProxyProtocolClient};
pub use error::ProxyError;
pub use messages::Messages;
pub use rendevouz::RendevouzCode;
