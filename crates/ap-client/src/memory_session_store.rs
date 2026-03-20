use std::collections::HashMap;

use ap_proxy_protocol::IdentityFingerprint;
use async_trait::async_trait;

use crate::error::ClientError;
use crate::traits::{SessionInfo, SessionStore, SessionUpdate};

/// In-memory session store that does not persist to disk.
///
/// Used for ephemeral connections where the session should not be saved.
pub struct MemorySessionStore {
    sessions: HashMap<IdentityFingerprint, SessionInfo>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<SessionInfo> {
        self.sessions.get(fingerprint).cloned()
    }

    async fn save(&mut self, session: SessionInfo) -> Result<(), ClientError> {
        self.sessions.insert(session.fingerprint, session);
        Ok(())
    }

    async fn update(&mut self, update: SessionUpdate) -> Result<(), ClientError> {
        if let Some(session) = self.sessions.get_mut(&update.fingerprint) {
            session.last_connected_at = update.last_connected_at;
            Ok(())
        } else {
            Err(ClientError::SessionCache("Session not found".to_string()))
        }
    }

    async fn remove(&mut self, fingerprint: &IdentityFingerprint) -> Result<(), ClientError> {
        self.sessions.remove(fingerprint);
        Ok(())
    }

    async fn list(&self) -> Vec<SessionInfo> {
        self.sessions.values().cloned().collect()
    }
}
