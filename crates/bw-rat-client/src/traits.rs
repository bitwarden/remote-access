use bw_noise_protocol::MultiDeviceTransport;
use bw_proxy::{IdentityFingerprint, IdentityKeyPair};

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
