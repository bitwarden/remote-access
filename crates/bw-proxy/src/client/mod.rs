//! Client library for connecting to the proxy server.
//!
//! This module provides the client-side implementation for connecting to a bw-proxy server,
//! authenticating, and sending/receiving messages.
//!
//! # Basic Usage
//!
//! ```no_run
//! use bw_proxy::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure and create client
//! let config = ProxyClientConfig {
//!     proxy_url: "ws://localhost:8080".to_string(),
//!     identity_keypair: None, // Generate a new identity
//! };
//! let mut client = ProxyProtocolClient::new(config);
//!
//! // Connect and authenticate
//! let mut incoming = client.connect().await?;
//!
//! // Handle incoming messages in a separate task
//! tokio::spawn(async move {
//!     while let Some(msg) = incoming.recv().await {
//!         match msg {
//!             IncomingMessage::Send { source, payload, .. } => {
//!                 // Handle message from another client
//!             }
//!             IncomingMessage::RendevouzInfo(code) => {
//!                 // Got a rendezvous code to share
//!             }
//!             IncomingMessage::IdentityInfo { identity, .. } => {
//!                 // Found a peer's identity by rendezvous code
//!             }
//!         }
//!     }
//! });
//!
//! // Request a rendezvous code
//! client.request_rendezvous().await?;
//!
//! // Send a message to another client
//! // let target = /* fingerprint from IdentityInfo */;
//! // client.send_to(target, b"Hello!".to_vec()).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Identity Management
//!
//! You can generate and persist client identities:
//!
//! ```no_run
//! use bw_proxy::{IdentityKeyPair, ProxyClientConfig};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate new identity
//! let keypair = IdentityKeyPair::generate();
//! let cose_bytes = keypair.to_cose();
//!
//! // Save COSE key securely (e.g., to encrypted storage)
//! // std::fs::write("identity.key", &cose_bytes)?;
//!
//! // Later, restore identity
//! // let cose_bytes = std::fs::read("identity.key")?;
//! // let restored = IdentityKeyPair::from_cose(&cose_bytes).unwrap();
//! # Ok(())
//! # }
//! ```

mod config;
#[cfg(feature = "native")]
mod protocol_client;

pub use config::IncomingMessage;
#[cfg(feature = "native")]
pub use config::ProxyClientConfig;
#[cfg(feature = "native")]
pub use protocol_client::ProxyProtocolClient;
