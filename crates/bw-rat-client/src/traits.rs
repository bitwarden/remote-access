use async_trait::async_trait;
use bw_noise_protocol::MultiDeviceTransport;
use bw_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};

use crate::error::RemoteClientError;

/// Trait for session cache storage implementations
///
/// Provides an abstraction for storing and retrieving approved remote fingerprints.
/// Implementations must be thread-safe for use in async contexts.
pub trait SessionStore: Send + Sync {
    /// Check if a fingerprint exists in the cache
    fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool;

    /// Cache a new session fingerprint
    ///
    /// If the fingerprint already exists, updates the cached_at timestamp.
    fn cache_session(&mut self, fingerprint: IdentityFingerprint) -> Result<(), RemoteClientError>;

    /// Remove a fingerprint from the cache
    fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), RemoteClientError>;

    /// Clear all cached sessions
    fn clear(&mut self) -> Result<(), RemoteClientError>;

    /// List all cached sessions
    ///
    /// Returns tuples of (fingerprint, optional_name, created_timestamp, last_connected_timestamp)
    fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)>;

    /// Set a friendly name for a cached session
    fn set_session_name(
        &mut self,
        fingerprint: &IdentityFingerprint,
        name: String,
    ) -> Result<(), RemoteClientError>;

    /// Update the last_connected_at timestamp for a session
    fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), RemoteClientError>;

    /// Save transport state for a session
    ///
    /// This allows session resumption without requiring a new Noise handshake.
    fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport_state: MultiDeviceTransport,
    ) -> Result<(), RemoteClientError>;

    /// Load transport state for a session
    ///
    /// Returns None if no transport state is stored for this session.
    fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, RemoteClientError>;
}

/// Provides a cryptographic identity for the current client.
///
/// For the device group, this should be one shared identity, for the single-device, a unique identity.
/// This should be generated on first run and stored persistently, in secure storage where possible.
pub trait IdentityProvider: Send + Sync {
    /// Get reference to the identity keypair
    fn identity(&self) -> &IdentityKeyPair;

    /// Get the fingerprint of this identity
    fn fingerprint(&self) -> IdentityFingerprint {
        self.identity().identity().fingerprint()
    }
}

/// How a connection was established
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditConnectionType {
    /// Rendezvous code pairing
    Rendezvous,
    /// Pre-shared key pairing
    Psk,
}

/// Which credential fields were included in an approved response.
/// Contains only presence flags, never actual values.
#[derive(Debug, Clone)]
pub struct CredentialFieldSet {
    pub has_username: bool,
    pub has_password: bool,
    pub has_totp: bool,
    pub has_uri: bool,
    pub has_notes: bool,
}

/// Audit events for security-relevant actions on the UserClient
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuditEvent<'a> {
    /// A new device completed handshake and was accepted
    ConnectionEstablished {
        fingerprint: &'a IdentityFingerprint,
        session_name: Option<&'a str>,
        connection_type: AuditConnectionType,
    },
    /// A cached/known device reconnected (transport keys refreshed)
    SessionRefreshed {
        fingerprint: &'a IdentityFingerprint,
    },
    /// A new connection was rejected during fingerprint verification
    ConnectionRejected {
        fingerprint: &'a IdentityFingerprint,
    },
    /// A remote device requested a credential
    CredentialRequested {
        domain: &'a str,
        fingerprint: &'a IdentityFingerprint,
        request_id: &'a str,
    },
    /// A credential was approved and sent
    CredentialApproved {
        domain: &'a str,
        fingerprint: &'a IdentityFingerprint,
        request_id: &'a str,
        fields: CredentialFieldSet,
    },
    /// A credential request was denied
    CredentialDenied {
        domain: &'a str,
        fingerprint: &'a IdentityFingerprint,
        request_id: &'a str,
    },
}

/// Persistent audit logging for security-relevant events on the UserClient.
///
/// Implementations may write to files, databases, or external services.
/// All methods receive `&self` (interior mutability is the implementor's
/// responsibility). Implementations should handle errors internally
/// (e.g., log a warning via `tracing`). Timestamps are the implementor's
/// responsibility.
#[async_trait]
pub trait AuditLog: Send + Sync {
    /// Write an audit event
    async fn write(&self, event: AuditEvent<'_>);
}

/// No-op audit logger that discards all events.
/// Used as the default when no audit logging is configured.
pub struct NoOpAuditLog;

#[async_trait]
impl AuditLog for NoOpAuditLog {
    async fn write(&self, _event: AuditEvent<'_>) {}
}
