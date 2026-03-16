//! WebSocket proxy server for secure peer-to-peer messaging.
//!
//! This crate provides the proxy server that accepts WebSocket connections,
//! authenticates clients, and routes messages between them. The server is
//! zero-knowledge and cannot decrypt client payloads.
//!
//!
//! # Architecture
//!
//! The proxy routes messages between authenticated clients:
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
//!    |<--(5) Code: "ABC-DEF-GHI"---|                             |
//!    |                             |                             |
//!    |                             |<---(6) Lookup "ABC-DEF-GHI"-|
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
//! Clients can request temporary rendezvous codes (e.g., "ABC-DEF-GHI") that are valid for 5 minutes.
//! Other clients can look up an identity by providing the code, enabling peer discovery without
//! exchanging long-lived identifiers. Codes are single-use and expire automatically.
//!
//! ### Phase 3: Messaging
//!
//! Once authenticated, clients can send messages to other clients by their identity fingerprint.
//! The proxy validates the source identity and routes messages to the destination. The proxy
//! cannot decrypt message contents — clients should implement end-to-end encryption separately.
//!
//! # Running as a Binary
//!
//! ```bash
//! cargo run --bin ap-proxy
//! ```
//!
//! # Embedding in Your Application
//!
//! ```no_run
//! use ap_proxy::server::ProxyServer;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let addr: SocketAddr = "127.0.0.1:8080".parse()?;
//! let server = ProxyServer::new(addr);
//! server.run().await?;
//! # Ok(())
//! # }
//! ```

pub(crate) mod connection;
pub mod server;
