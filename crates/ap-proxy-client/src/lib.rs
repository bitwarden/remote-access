//! Client library for connecting to an ap-proxy WebSocket server.
//!
//! This crate provides [`ProxyProtocolClient`] for connecting to a proxy server,
//! authenticating, and sending/receiving messages.
//!
//! # Example
//!
//! ```no_run
//! use ap_proxy_client::{ProxyProtocolClient, IncomingMessage, IdentityKeyPair};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = ProxyProtocolClient::from_url("ws://localhost:8080".to_string());
//! let mut incoming = client.connect(IdentityKeyPair::generate()).await?;
//!
//! tokio::spawn(async move {
//!     while let Some(msg) = incoming.recv().await {
//!         match msg {
//!             IncomingMessage::Send { source, payload, .. } => {
//!                 println!("Message from {:?}", source);
//!             }
//!             IncomingMessage::RendezvousInfo(code) => {
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
#[cfg(feature = "native-websocket")]
mod protocol_client;

pub use config::{IncomingMessage, ProxyClientConfig};
#[cfg(feature = "native-websocket")]
pub use protocol_client::ProxyProtocolClient;

// Re-export key types from ap-proxy-protocol for ergonomics
pub use ap_proxy_protocol::{
    Challenge, ChallengeResponse, Identity, IdentityFingerprint, IdentityKeyPair, Messages,
    ProxyError, RendezvousCode, SignatureAlgorithm,
};
