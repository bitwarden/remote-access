use crate::types::{FfiCredentialData, FfiEvent};

/// Callback interface for handling credential requests from remote devices.
///
/// Implement this in Python/Kotlin/Swift to serve credentials when a remote
/// device requests them.
#[uniffi::export(callback_interface)]
pub trait CredentialProvider: Send + Sync {
    /// Handle a credential request from a remote device.
    ///
    /// * `query_type` — The type of query: "domain", "id", or "search".
    /// * `query_value` — The query value (e.g. "example.com" for domain queries).
    /// * `remote_fingerprint` — Hex-encoded fingerprint of the requesting device.
    ///
    /// Return credential data to approve, or `None` to deny.
    fn handle_credential_request(
        &self,
        query_type: String,
        query_value: String,
        remote_fingerprint: String,
    ) -> Option<FfiCredentialData>;

    /// Handle fingerprint verification for a new rendezvous connection.
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
