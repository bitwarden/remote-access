//! Proxy server implementation.
//!
//! This module provides the server-side implementation of the ap-proxy server.
//! The server can be run standalone using the binary, or embedded in custom applications.
//!
//! # Running as a Binary
//!
//! The simplest way to run the proxy server:
//!
//! ```bash
//! cargo run --bin ap-proxy
//! ```
//!
//! # Embedding in Your Application
//!
//! You can embed the proxy server in your own application:
//!
//! ```no_run
//! use ap_proxy::server::ProxyServer;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let addr: SocketAddr = "127.0.0.1:8080".parse()?;
//! let server = ProxyServer::new(addr);
//!
//! // Run the server (blocks until shutdown)
//! server.run().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Server Responsibilities
//!
//! The proxy server:
//! - Accepts WebSocket connections from clients
//! - Authenticates clients using MlDsa65 challenge-response
//! - Manages rendezvous codes for peer discovery
//! - Routes messages between authenticated clients
//! - Cleans up expired rendezvous codes automatically
//!
//! # Security Considerations
//!
//! The server operates as a zero-knowledge proxy:
//! - Verifies client identities via cryptographic signatures
//! - Routes messages based on fingerprints
//! - Does not decrypt or inspect message payloads
//! - Sees metadata: source, destination, timing, message size

mod handler;
mod proxy_server;

pub use proxy_server::ProxyServer;
