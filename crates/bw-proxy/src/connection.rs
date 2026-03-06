//! Internal connection state tracking.
//!
//! This module contains internal types used by the proxy server to track authenticated
//! client connections. These types are not part of the public API.

use bw_proxy_protocol::{Identity, IdentityFingerprint};
use std::time::SystemTime;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// Internal state for an authenticated client connection.
///
/// The proxy server maintains one of these for each authenticated client to:
/// - Track the client's identity and fingerprint
/// - Send messages back to the client via the WebSocket channel
/// - Record connection time for debugging and monitoring
#[allow(dead_code)]
pub struct AuthenticatedConnection {
    /// Unique identifier for this connection (used for cleanup when multiple
    /// clients share the same fingerprint)
    pub conn_id: u64,
    /// The client's identity fingerprint (SHA256 hash of public key)
    pub fingerprint: IdentityFingerprint,
    /// The client's full identity (MlDsa65 public key)
    pub identity: Identity,
    /// Channel to send WebSocket messages to this client
    pub tx: mpsc::UnboundedSender<Message>,
    /// When this client completed authentication
    pub connected_at: SystemTime,
}
