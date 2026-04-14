use crate::error::ClientError;
use crate::types::{FfiAuditEvent, FfiCredentialData, FfiCredentialQuery, FfiEvent, FfiPskEntry};

/// Callback interface for handling credential requests from remote devices.
///
/// Implement this in Python/Kotlin/Swift to serve credentials when a remote
/// device requests them.
#[uniffi::export(callback_interface)]
pub trait CredentialProvider: Send + Sync {
    /// Handle a credential request from a remote device.
    ///
    /// * `query` — The credential query (domain, ID, or search).
    /// * `remote_fingerprint` — Hex-encoded fingerprint of the requesting device.
    ///
    /// Return credential data to approve, or `None` to deny.
    fn handle_credential_request(
        &self,
        query: FfiCredentialQuery,
        remote_fingerprint: String,
    ) -> Option<FfiCredentialData>;
}

/// Callback interface for verifying handshake fingerprints on rendezvous connections.
///
/// Only needed for `UserClient` when accepting rendezvous (non-PSK) pairings.
/// PSK connections are pre-authenticated and skip fingerprint verification.
#[uniffi::export(callback_interface)]
pub trait FingerprintVerifier: Send + Sync {
    /// Verify a handshake fingerprint for a new rendezvous connection.
    ///
    /// * `fingerprint` — The 6-character hex handshake fingerprint.
    /// * `remote_identity` — Hex-encoded identity fingerprint of the remote device.
    ///
    /// Return `true` to accept, `false` to reject.
    fn verify_fingerprint(&self, fingerprint: String, remote_identity: String) -> bool;
}

/// Callback interface for receiving status notifications.
///
/// Optional — implement to receive events like handshake progress, connection
/// state changes, errors, etc.
#[uniffi::export(callback_interface)]
pub trait EventHandler: Send + Sync {
    /// Called when a notification event occurs.
    fn on_event(&self, event: FfiEvent);
}

/// Callback interface for persistent identity storage.
///
/// Implement this to control where identity keypairs are stored (file, keychain,
/// database, etc.). The bytes are opaque — just store and return them as-is.
/// No CBOR/COSE parsing is needed on the language side.
#[uniffi::export(callback_interface)]
pub trait IdentityStorage: Send + Sync {
    /// Load previously saved identity bytes, or None if no identity exists yet.
    fn load_identity(&self) -> Option<Vec<u8>>;

    /// Save identity bytes for later retrieval.
    fn save_identity(&self, identity_bytes: Vec<u8>) -> Result<(), ClientError>;
}

/// Storage record for a cached connection (FFI-safe).
///
/// `transport_state` is opaque bytes — language bindings store and return them
/// as-is. No CBOR parsing is needed on the language side.
#[derive(Clone, uniffi::Record)]
pub struct FfiStoredConnection {
    /// Hex-encoded identity fingerprint of the remote peer.
    pub fingerprint: String,
    /// Optional human-readable name for the connection.
    pub name: Option<String>,
    /// Unix timestamp (seconds) when the connection was first cached.
    pub cached_at: u64,
    /// Unix timestamp (seconds) of the last successful connection.
    pub last_connected_at: u64,
    /// Opaque transport state bytes — store and return as-is.
    pub transport_state: Option<Vec<u8>>,
}

/// Callback interface for receiving audit events from the UserClient.
///
/// Optional — implement to receive security-relevant events like connection
/// establishment, credential approvals/denials, etc.
#[uniffi::export(callback_interface)]
pub trait AuditLogger: Send + Sync {
    /// Called when a security-relevant audit event occurs.
    fn on_audit_event(&self, event: FfiAuditEvent);
}

/// Callback interface for persistent PSK storage.
///
/// Optional — implement to persist reusable pre-shared keys across restarts.
/// Only needed when using `get_psk_token(reusable: true)`.
#[uniffi::export(callback_interface)]
pub trait PskStorage: Send + Sync {
    /// Get a PSK entry by its hex-encoded identifier.
    fn get(&self, psk_id: String) -> Option<FfiPskEntry>;

    /// Save a PSK entry (insert or update).
    fn save(&self, entry: FfiPskEntry) -> Result<(), ClientError>;

    /// Remove a PSK entry by its hex-encoded identifier.
    fn remove(&self, psk_id: String) -> Result<(), ClientError>;

    /// List all stored PSK entries.
    fn list(&self) -> Vec<FfiPskEntry>;
}

/// Callback interface for persistent connection storage.
///
/// Implement this to control where cached connections are stored.
#[uniffi::export(callback_interface)]
pub trait ConnectionStorage: Send + Sync {
    /// Get a cached connection by hex-encoded fingerprint.
    fn get(&self, fingerprint_hex: String) -> Option<FfiStoredConnection>;

    /// Save a connection (insert or update).
    fn save(&self, connection: FfiStoredConnection) -> Result<(), ClientError>;

    /// Update the last_connected_at timestamp for an existing connection.
    fn update(&self, fingerprint_hex: String, last_connected_at: u64) -> Result<(), ClientError>;

    /// List all cached connections.
    fn list(&self) -> Vec<FfiStoredConnection>;
}
