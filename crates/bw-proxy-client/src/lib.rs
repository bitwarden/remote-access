//! Client library for connecting to a bw-proxy WebSocket relay server.
//!
//! This crate provides [`ProxyProtocolClient`] for connecting to a proxy server,
//! authenticating, and sending/receiving messages.
//!
//! # Example
//!
//! ```no_run
//! use bw_proxy_client::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ProxyClientConfig {
//!     proxy_url: "ws://localhost:8080".to_string(),
//!     identity_keypair: None,
//! };
//!
//! let mut client = ProxyProtocolClient::new(config);
//! let mut incoming = client.connect().await?;
//!
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
//! client.request_rendezvous().await?;
//! # Ok(())
//! # }
//! ```

mod config;
mod protocol_client;

pub use config::ProxyClientConfig;
pub use protocol_client::ProxyProtocolClient;

// Re-export key types from bw-proxy-protocol for ergonomics
pub use bw_proxy_protocol::{
    Challenge, ChallengeResponse, Identity, IdentityFingerprint, IdentityKeyPair, IncomingMessage,
    Messages, ProxyError, RendevouzCode, SignatureAlgorithm,
};
