use ap_noise::MultiDeviceTransport;
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use async_trait::async_trait;

use crate::error::ClientError;

/// Trait for session cache storage implementations
///
/// Provides an abstraction for storing and retrieving approved remote fingerprints.
/// Implementations must be thread-safe for use in async contexts.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Check if a fingerprint exists in the cache
    async fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool;

    /// Cache a new session fingerprint
    ///
    /// If the fingerprint already exists, updates the cached_at timestamp.
    async fn cache_session(&mut self, fingerprint: IdentityFingerprint) -> Result<(), ClientError>;

    /// Remove a fingerprint from the cache
    async fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), ClientError>;

    /// Clear all cached sessions
    async fn clear(&mut self) -> Result<(), ClientError>;

    /// List all cached sessions
    ///
    /// Returns tuples of (fingerprint, optional_name, created_timestamp, last_connected_timestamp)
    async fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)>;

    /// Set a friendly name for a cached session
    async fn set_session_name(
        &mut self,
        fingerprint: &IdentityFingerprint,
        name: String,
    ) -> Result<(), ClientError>;

    /// Update the last_connected_at timestamp for a session
    async fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), ClientError>;

    /// Save transport state for a session
    ///
    /// This allows session resumption without requiring a new Noise handshake.
    async fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport_state: MultiDeviceTransport,
    ) -> Result<(), ClientError>;

    /// Load transport state for a session
    ///
    /// Returns None if no transport state is stored for this session.
    async fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, ClientError>;
}

/// Provides a cryptographic identity for the current client.
///
/// For the device group, this should be one shared identity, for the single-device, a unique identity.
/// This should be generated on first run and stored persistently, in secure storage where possible.
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Get the identity keypair
    async fn identity(&self) -> IdentityKeyPair;

    /// Get the fingerprint of this identity
    async fn fingerprint(&self) -> IdentityFingerprint {
        self.identity().await.identity().fingerprint()
    }
}

/// An [`IdentityProvider`] that generates a random ephemeral identity on creation.
///
/// Useful for tests, examples, and consumers that don't need persistent identity.
/// The keypair lives only in memory and is lost when the provider is dropped.
///
/// ```
/// use ap_client::MemoryIdentityProvider;
///
/// let identity = MemoryIdentityProvider::new();
/// ```
///
/// To wrap an existing keypair:
///
/// ```
/// use ap_client::MemoryIdentityProvider;
/// use ap_proxy_protocol::IdentityKeyPair;
///
/// let keypair = IdentityKeyPair::generate();
/// let identity = MemoryIdentityProvider::from_keypair(keypair);
/// ```
#[derive(Clone)]
pub struct MemoryIdentityProvider {
    keypair: IdentityKeyPair,
}

impl MemoryIdentityProvider {
    /// Generate a new random ephemeral identity.
    pub fn new() -> Self {
        Self {
            keypair: IdentityKeyPair::generate(),
        }
    }

    /// Wrap an existing keypair as an ephemeral identity provider.
    pub fn from_keypair(keypair: IdentityKeyPair) -> Self {
        Self { keypair }
    }
}

impl Default for MemoryIdentityProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdentityProvider for MemoryIdentityProvider {
    async fn identity(&self) -> IdentityKeyPair {
        self.keypair.clone()
    }
}

/// How a new connection was established between devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditConnectionType {
    /// Paired using a 9-character rendezvous code exchanged out-of-band.
    /// Requires explicit fingerprint verification before the connection is trusted.
    Rendezvous,
    /// Paired using a pre-shared key (PSK) token.
    /// Trust is established through the shared secret — no fingerprint verification needed.
    Psk,
}

/// Describes which credential fields were included in an approved response.
///
/// Contains only presence flags, never actual credential values.
/// Useful for audit trails that need to record *what kind* of data was shared
/// without logging sensitive material.
#[derive(Debug, Clone, Default)]
pub struct CredentialFieldSet {
    pub has_username: bool,
    pub has_password: bool,
    pub has_totp: bool,
    pub has_uri: bool,
    pub has_notes: bool,
}

/// Audit events emitted by the [`UserClient`] (trusted device) for security-relevant actions.
///
/// Each variant represents a discrete, auditable action in the access protocol.
/// Implementations of [`AuditLog`] receive these events and can persist them to files,
/// databases, or external services.
///
/// ## Field conventions
///
/// - `remote_identity` — the [`IdentityFingerprint`] of the remote (untrusted) device.
///   This is a stable 32-byte identifier derived from the device's persistent public key.
/// - `remote_name` — optional human-friendly label assigned by the user when pairing
///   (e.g., "Work Laptop"). Only available on connection events.
/// - `request_id` — unique per-request correlation token generated by the remote client.
///   Use this to correlate `CredentialRequested` → `CredentialApproved`/`CredentialDenied`.
/// - `query` — the [`CredentialQuery`](crate::CredentialQuery) that triggered the lookup.
/// - `domain` — the credential's domain (from the matched vault item), if available.
///
/// This enum is `#[non_exhaustive]` — new variants may be added in future versions.
/// Implementations should include a `_ => {}` catch-all arm when matching.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuditEvent<'a> {
    /// A new remote device completed the Noise handshake and was accepted as trusted.
    ///
    /// Emitted once per new pairing, after the session is cached. For rendezvous connections,
    /// this fires only after the user has explicitly approved the fingerprint verification.
    /// For PSK connections, trust is implicit via the shared secret.
    ConnectionEstablished {
        remote_identity: &'a IdentityFingerprint,
        remote_name: Option<&'a str>,
        connection_type: AuditConnectionType,
    },

    /// A previously-paired device reconnected and refreshed its transport keys.
    ///
    /// This is a routine reconnection of an already-trusted device — no user approval
    /// is needed. The Noise handshake runs again to derive fresh encryption keys,
    /// but the device was already verified during the original pairing.
    SessionRefreshed {
        remote_identity: &'a IdentityFingerprint,
    },

    /// A new connection attempt was rejected during fingerprint verification.
    ///
    /// The user was shown the handshake fingerprint and chose to reject it,
    /// meaning the remote device was not added to the trusted session cache.
    /// Only applies to rendezvous connections (PSK connections skip verification).
    ConnectionRejected {
        remote_identity: &'a IdentityFingerprint,
    },

    /// A remote device sent a request for credentials.
    ///
    /// Emitted when the encrypted request is received and decrypted. At this point
    /// the request is pending user approval — no credential data has been shared yet.
    CredentialRequested {
        query: &'a crate::CredentialQuery,
        remote_identity: &'a IdentityFingerprint,
        request_id: &'a str,
    },

    /// A credential request was approved and the credential was sent to the remote device.
    ///
    /// The `fields` indicate which credential fields were included (e.g., username,
    /// password, TOTP) without revealing the actual values.
    CredentialApproved {
        query: &'a crate::CredentialQuery,
        domain: Option<&'a str>,
        remote_identity: &'a IdentityFingerprint,
        request_id: &'a str,
        credential_id: Option<&'a str>,
        fields: CredentialFieldSet,
    },

    /// A credential request was denied by the user.
    ///
    /// No credential data was sent to the remote device.
    CredentialDenied {
        query: &'a crate::CredentialQuery,
        domain: Option<&'a str>,
        remote_identity: &'a IdentityFingerprint,
        request_id: &'a str,
        credential_id: Option<&'a str>,
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
