//! Noise Protocol Clients for access-protocol
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
//! use ap_client::{RemoteClient, DefaultProxyClient, IdentityProvider, SessionStore};
//! use ap_proxy_client::ProxyClientConfig;
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
//! let query = ap_client::CredentialQuery::Domain("example.com".to_string());
//! let credential = client.request_credential(&query).await?;
//! ```
//!
//! ## User Client Usage (trusted device)
//!
//! ```ignore
//! use ap_client::{
//!     DefaultProxyClient, IdentityProvider, UserClient, UserClientNotification,
//!     UserClientRequest,
//! };
//! use ap_proxy_client::ProxyClientConfig;
//! use tokio::sync::mpsc;
//!
//! // Create proxy client
//! let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
//!     proxy_url: "ws://localhost:8080".to_string(),
//!     identity_keypair: Some(identity_provider.identity().to_owned()),
//! }));
//!
//! let (notification_tx, mut notification_rx) = mpsc::channel(32);
//! let (request_tx, mut request_rx) = mpsc::channel(32);
//!
//! // Connect — spawns event loop internally, returns handle
//! let client = UserClient::connect(
//!     identity_provider,
//!     session_store,
//!     proxy_client,
//!     notification_tx,
//!     request_tx,
//!     None, // audit_log
//! ).await?;
//!
//! // Already listening. Just use it.
//! let token = client.get_psk_token(None).await?;
//! // Or: let code = client.get_rendezvous_token(None).await?;
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
    CredentialRequestReply, FingerprintVerificationReply, UserClient, UserClientNotification,
    UserClientRequest,
};
pub use error::RemoteClientError;
#[cfg(feature = "native-websocket")]
pub use proxy::DefaultProxyClient;
pub use proxy::ProxyClient;
pub use traits::{
    AuditConnectionType, AuditEvent, AuditLog, CredentialFieldSet, IdentityProvider, NoOpAuditLog,
    SessionStore,
};
pub use types::{
    ConnectionMode, CredentialData, CredentialQuery, PskId, RemoteClientEvent, RemoteClientResponse,
};

// Re-export ap-proxy-protocol types
pub use ap_proxy_protocol::{IdentityFingerprint, RendezvousCode};
// Re-export PSK type from noise protocol
pub use ap_noise::Psk;
