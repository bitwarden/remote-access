use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ap_client::{RemoteClientError, SessionStore};
use ap_noise::{MultiDeviceTransport, PersistentTransportState};
use ap_proxy_protocol::IdentityFingerprint;
use async_trait::async_trait;

struct SessionEntry {
    fingerprint: IdentityFingerprint,
    name: Option<String>,
    cached_at: u64,
    last_connected_at: u64,
    transport_state: Option<Vec<u8>>,
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// In-memory session store that does not persist to disk.
///
/// Used for ephemeral connections where the session should not be saved.
pub struct MemorySessionStore {
    sessions: HashMap<IdentityFingerprint, SessionEntry>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool {
        self.sessions.contains_key(fingerprint)
    }

    async fn cache_session(
        &mut self,
        fingerprint: IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        let now = now_seconds();
        self.sessions
            .entry(fingerprint)
            .and_modify(|e| e.cached_at = now)
            .or_insert(SessionEntry {
                fingerprint,
                name: None,
                cached_at: now,
                last_connected_at: now,
                transport_state: None,
            });
        Ok(())
    }

    async fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        self.sessions.remove(fingerprint);
        Ok(())
    }

    async fn clear(&mut self) -> Result<(), RemoteClientError> {
        self.sessions.clear();
        Ok(())
    }

    async fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)> {
        self.sessions
            .values()
            .map(|s| {
                (
                    s.fingerprint,
                    s.name.clone(),
                    s.cached_at,
                    s.last_connected_at,
                )
            })
            .collect()
    }

    async fn set_session_name(
        &mut self,
        fingerprint: &IdentityFingerprint,
        name: String,
    ) -> Result<(), RemoteClientError> {
        if let Some(session) = self.sessions.get_mut(fingerprint) {
            session.name = Some(name);
            Ok(())
        } else {
            Err(RemoteClientError::SessionCache(
                "Session not found".to_string(),
            ))
        }
    }

    async fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        if let Some(session) = self.sessions.get_mut(fingerprint) {
            session.last_connected_at = now_seconds();
            Ok(())
        } else {
            Err(RemoteClientError::SessionCache(
                "Session not found".to_string(),
            ))
        }
    }

    async fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport_state: MultiDeviceTransport,
    ) -> Result<(), RemoteClientError> {
        if let Some(session) = self.sessions.get_mut(fingerprint) {
            session.transport_state = Some(
                PersistentTransportState::from(&transport_state)
                    .to_bytes()
                    .map_err(|e| {
                        RemoteClientError::NoiseProtocol(format!(
                            "Failed to serialize transport state: {e}"
                        ))
                    })?,
            );
            Ok(())
        } else {
            Err(RemoteClientError::SessionCache(
                "Session not found".to_string(),
            ))
        }
    }

    async fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, RemoteClientError> {
        if let Some(session) = self.sessions.get(fingerprint) {
            Ok(Some(
                PersistentTransportState::from_bytes(session.transport_state.as_ref().ok_or_else(
                    || {
                        RemoteClientError::SessionCache(
                            "No transport state stored for this session".to_string(),
                        )
                    },
                )?)
                .map(MultiDeviceTransport::from)?,
            ))
        } else {
            Err(RemoteClientError::SessionCache(
                "Session not found".to_string(),
            ))
        }
    }
}
