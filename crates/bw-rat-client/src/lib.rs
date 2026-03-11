//! Noise Protocol Clients for bw_remote
//!
//! This crate provides both remote and user client implementations for
//! connecting through a proxy using the Noise Protocol.
//!
//! ## Features
//!
//! - PSK-based authentication using pairing codes
//! - Noise Protocol NNpsk2 pattern for secure 2-message handshake
//! - Session caching for reconnection without re-pairing
//! - Supports both classical (Curve25519) and post-quantum (Kyber768) cryptography
//!
//! ## Remote Client Usage (untrusted device)
//!
//! ```ignore
//! use bw_noise_client::{RemoteClient, DefaultProxyClient, IdentityProvider, SessionStore};
//! use bw_proxy_client::ProxyClientConfig;
//! use tokio::sync::mpsc;
//!
//! // Create proxy client
//! let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
//!     proxy_url: "ws://localhost:8080".to_string(),
//!     identity_keypair: Some(identity_provider.identity().to_owned()),
//! }));
//!
//! let (event_tx, mut event_rx) = mpsc::channel(32);
//! let (response_tx, response_rx) = mpsc::channel(32);
//!
//! let mut client = RemoteClient::new(
//!     identity_provider,
//!     session_store,
//!     event_tx,
//!     response_rx,
//!     proxy_client,
//! ).await?;
//!
//! // Pair with rendezvous code
//! client.pair_with_handshake("ABCDEF123").await?;
//!
//! let credential = client.request_credential("example.com").await?;
//! ```
//!
//! ## User Client Usage (trusted device)
//!
//! ```ignore
//! use bw_noise_client::{
//!     DefaultProxyClient, IdentityProvider, UserClient, UserClientEvent, UserClientResponse,
//! };
//! use bw_proxy_client::ProxyClientConfig;
//! use tokio::sync::mpsc;
//!
//! // Create proxy client
//! let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
//!     proxy_url: "ws://localhost:8080".to_string(),
//!     identity_keypair: Some(identity_provider.identity().to_owned()),
//! }));
//!
//! let (event_tx, event_rx) = mpsc::channel(32);
//! let (response_tx, response_rx) = mpsc::channel(32);
//!
//! let mut client = UserClient::listen(
//!     identity_provider,
//!     session_store,
//!     proxy_client,
//! ).await?;
//!
//! // Enable PSK mode or rendezvous mode
//! client.enable_psk(event_tx, response_rx).await?;
//! ```

/// Error types
pub mod error;
/// Proxy client trait and default implementation
pub mod proxy;
/// Traits for storage implementations
pub mod traits;
/// Protocol types and events
pub mod types;

mod clients;

pub use clients::remote_client::RemoteClient;
pub use clients::user_client::{
    CredentialData as UserCredentialData, UserClient, UserClientEvent, UserClientResponse,
};
pub use error::RemoteClientError;
#[cfg(feature = "native-websocket")]
pub use proxy::DefaultProxyClient;
pub use proxy::ProxyClient;
pub use traits::{IdentityProvider, SessionStore};
pub use types::{ConnectionMode, CredentialData, RemoteClientEvent, RemoteClientResponse};

// Re-export bw-proxy-protocol types
pub use bw_proxy_protocol::{IdentityFingerprint, RendevouzCode};
// Re-export PSK type from noise protocol
pub use bw_noise_protocol::Psk;
