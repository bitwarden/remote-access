//! Thin adapters that bridge FFI callback traits to `ap_client` trait interfaces.

use std::sync::Arc;

use ap_client::{
    AuditConnectionType, AuditEvent, AuditLog, ClientError, ConnectionInfo, ConnectionStore,
    ConnectionUpdate, IdentityProvider, PskEntry, PskStore,
};
use ap_noise::{MultiDeviceTransport, PersistentTransportState, Psk};
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use async_trait::async_trait;

use crate::callbacks::{
    AuditLogger, ConnectionStorage, FfiStoredConnection, IdentityStorage, PskStorage,
};
use crate::types::{FfiAuditEvent, FfiConnectionType, FfiCredentialQuery, FfiPskEntry};

// ---------------------------------------------------------------------------
// IdentityStorage → IdentityProvider
// ---------------------------------------------------------------------------

pub struct CallbackIdentityProvider {
    keypair: IdentityKeyPair,
}

/// Resolve the identity fingerprint from storage without constructing a full provider.
///
/// Loads (or generates) the identity keypair and returns its hex-encoded fingerprint.
pub(crate) fn resolve_identity_fingerprint(
    storage: &dyn IdentityStorage,
) -> Result<String, ClientError> {
    let provider = CallbackIdentityProvider::from_storage(storage)?;
    Ok(provider.keypair.identity().fingerprint().to_hex())
}

impl CallbackIdentityProvider {
    pub fn from_storage(storage: &dyn IdentityStorage) -> Result<Self, ClientError> {
        let keypair = if let Some(bytes) = storage.load_identity() {
            IdentityKeyPair::from_cose(&bytes).map_err(|_| {
                ClientError::IdentityStorageFailed(
                    "Failed to parse identity from stored bytes".to_string(),
                )
            })?
        } else {
            let keypair = IdentityKeyPair::generate();
            let cose_bytes = keypair.to_cose();
            storage.save_identity(cose_bytes).map_err(|e| {
                ClientError::IdentityStorageFailed(format!("Failed to save identity: {e}"))
            })?;
            keypair
        };

        Ok(Self { keypair })
    }
}

#[async_trait]
impl IdentityProvider for CallbackIdentityProvider {
    async fn identity(&self) -> IdentityKeyPair {
        self.keypair.clone()
    }
}

// ---------------------------------------------------------------------------
// ConnectionStorage → ConnectionStore
// ---------------------------------------------------------------------------

pub struct CallbackConnectionStore {
    storage: Arc<dyn ConnectionStorage>,
}

impl CallbackConnectionStore {
    pub fn new(storage: Arc<dyn ConnectionStorage>) -> Self {
        Self { storage }
    }
}

fn stored_to_info(stored: &FfiStoredConnection) -> Option<ConnectionInfo> {
    let fingerprint = match IdentityFingerprint::from_hex(&stored.fingerprint) {
        Ok(fp) => fp,
        Err(e) => {
            tracing::warn!(
                "Skipping connection with invalid fingerprint '{}': {e}",
                stored.fingerprint
            );
            return None;
        }
    };
    let transport_state =
        stored.transport_state.as_ref().and_then(
            |bytes| match PersistentTransportState::from_bytes(bytes) {
                Ok(state) => Some(MultiDeviceTransport::from(state)),
                Err(e) => {
                    tracing::warn!(
                        "Failed to restore transport state for {}: {e}",
                        stored.fingerprint
                    );
                    None
                }
            },
        );

    Some(ConnectionInfo {
        fingerprint,
        name: stored.name.clone(),
        cached_at: stored.cached_at,
        last_connected_at: stored.last_connected_at,
        transport_state,
    })
}

fn info_to_stored(info: &ConnectionInfo) -> FfiStoredConnection {
    let transport_state = info.transport_state.as_ref().and_then(|t| {
        match PersistentTransportState::from(t).to_bytes() {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                tracing::warn!(
                    "Failed to serialize transport state for {}: {e}",
                    info.fingerprint.to_hex()
                );
                None
            }
        }
    });

    FfiStoredConnection {
        fingerprint: info.fingerprint.to_hex(),
        name: info.name.clone(),
        cached_at: info.cached_at,
        last_connected_at: info.last_connected_at,
        transport_state,
    }
}

#[async_trait]
impl ConnectionStore for CallbackConnectionStore {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<ConnectionInfo> {
        self.storage
            .get(fingerprint.to_hex())
            .and_then(|stored| stored_to_info(&stored))
    }

    async fn save(&mut self, connection: ConnectionInfo) -> Result<(), ClientError> {
        let stored = info_to_stored(&connection);
        self.storage
            .save(stored)
            .map_err(|e| ClientError::ConnectionCache(e.to_string()))
    }

    async fn update(&mut self, update: ConnectionUpdate) -> Result<(), ClientError> {
        self.storage
            .update(update.fingerprint.to_hex(), update.last_connected_at)
            .map_err(|e| ClientError::ConnectionCache(e.to_string()))
    }

    async fn list(&self) -> Vec<ConnectionInfo> {
        self.storage
            .list()
            .into_iter()
            .filter_map(|stored| stored_to_info(&stored))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// AuditLogger → AuditLog
// ---------------------------------------------------------------------------

pub struct CallbackAuditLog {
    logger: Arc<dyn AuditLogger>,
}

impl CallbackAuditLog {
    pub fn new(logger: Arc<dyn AuditLogger>) -> Self {
        Self { logger }
    }
}

#[async_trait]
impl AuditLog for CallbackAuditLog {
    async fn write(&self, event: AuditEvent<'_>) {
        let ffi_event = match event {
            AuditEvent::ConnectionEstablished {
                remote_identity,
                remote_name,
                connection_type,
            } => FfiAuditEvent::ConnectionEstablished {
                remote_identity: remote_identity.to_hex(),
                remote_name: remote_name.map(|s| s.to_string()),
                connection_type: match connection_type {
                    AuditConnectionType::Rendezvous => FfiConnectionType::Rendezvous,
                    AuditConnectionType::Psk => FfiConnectionType::Psk,
                },
            },
            AuditEvent::SessionRefreshed { remote_identity } => FfiAuditEvent::SessionRefreshed {
                remote_identity: remote_identity.to_hex(),
            },
            AuditEvent::ConnectionRejected { remote_identity } => {
                FfiAuditEvent::ConnectionRejected {
                    remote_identity: remote_identity.to_hex(),
                }
            }
            AuditEvent::CredentialRequested {
                query,
                remote_identity,
                request_id,
            } => FfiAuditEvent::CredentialRequested {
                query: FfiCredentialQuery::from(query),
                remote_identity: remote_identity.to_hex(),
                request_id: request_id.to_string(),
            },
            AuditEvent::CredentialApproved {
                query,
                domain,
                remote_identity,
                request_id,
                credential_id,
                ..
            } => FfiAuditEvent::CredentialApproved {
                query: FfiCredentialQuery::from(query),
                domain: domain.map(|s| s.to_string()),
                remote_identity: remote_identity.to_hex(),
                request_id: request_id.to_string(),
                credential_id: credential_id.map(|s| s.to_string()),
            },
            AuditEvent::CredentialDenied {
                query,
                domain,
                remote_identity,
                request_id,
                credential_id,
            } => FfiAuditEvent::CredentialDenied {
                query: FfiCredentialQuery::from(query),
                domain: domain.map(|s| s.to_string()),
                remote_identity: remote_identity.to_hex(),
                request_id: request_id.to_string(),
                credential_id: credential_id.map(|s| s.to_string()),
            },
            _ => return, // non_exhaustive: silently skip unknown variants
        };
        self.logger.on_audit_event(ffi_event);
    }
}

// ---------------------------------------------------------------------------
// PskStorage → PskStore
// ---------------------------------------------------------------------------

pub struct CallbackPskStore {
    storage: Arc<dyn PskStorage>,
}

impl CallbackPskStore {
    pub fn new(storage: Arc<dyn PskStorage>) -> Self {
        Self { storage }
    }
}

fn ffi_to_psk_entry(ffi: &FfiPskEntry) -> Option<PskEntry> {
    let psk_bytes: [u8; 32] = match ffi.psk.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!(
                "Invalid PSK length for psk_id '{}': expected 32 bytes",
                ffi.psk_id
            );
            return None;
        }
    };

    Some(PskEntry {
        psk_id: ffi.psk_id.clone(),
        psk: Psk::from_bytes(psk_bytes),
        name: ffi.name.clone(),
        created_at: ffi.created_at,
    })
}

fn psk_entry_to_ffi(entry: &PskEntry) -> FfiPskEntry {
    FfiPskEntry {
        psk_id: entry.psk_id.clone(),
        psk: entry.psk.to_bytes().to_vec(),
        name: entry.name.clone(),
        created_at: entry.created_at,
    }
}

#[async_trait]
impl PskStore for CallbackPskStore {
    async fn get(&self, psk_id: &String) -> Option<PskEntry> {
        self.storage
            .get(psk_id.to_string())
            .and_then(|ffi| ffi_to_psk_entry(&ffi))
    }

    async fn save(&mut self, entry: PskEntry) -> Result<(), ClientError> {
        let ffi = psk_entry_to_ffi(&entry);
        self.storage
            .save(ffi)
            .map_err(|e| ClientError::ConnectionCache(e.to_string()))
    }

    async fn remove(&mut self, psk_id: &String) -> Result<(), ClientError> {
        self.storage
            .remove(psk_id.to_string())
            .map_err(|e| ClientError::ConnectionCache(e.to_string()))
    }

    async fn list(&self) -> Vec<PskEntry> {
        self.storage
            .list()
            .into_iter()
            .filter_map(|ffi| ffi_to_psk_entry(&ffi))
            .collect()
    }
}
