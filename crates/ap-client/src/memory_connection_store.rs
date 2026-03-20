use std::collections::HashMap;

use ap_proxy_protocol::IdentityFingerprint;
use async_trait::async_trait;

use crate::error::ClientError;
use crate::traits::{ConnectionInfo, ConnectionStore, ConnectionUpdate};

/// In-memory connection store that does not persist to disk.
///
/// Used for ephemeral connections where the connection should not be saved.
pub struct MemoryConnectionStore {
    connections: HashMap<IdentityFingerprint, ConnectionInfo>,
}

impl MemoryConnectionStore {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Clear all cached connections.
    pub fn clear(&mut self) {
        self.connections.clear();
    }
}

impl Default for MemoryConnectionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ConnectionStore for MemoryConnectionStore {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<ConnectionInfo> {
        self.connections.get(fingerprint).cloned()
    }

    async fn save(&mut self, connection: ConnectionInfo) -> Result<(), ClientError> {
        self.connections.insert(connection.fingerprint, connection);
        Ok(())
    }

    async fn update(&mut self, update: ConnectionUpdate) -> Result<(), ClientError> {
        if let Some(connection) = self.connections.get_mut(&update.fingerprint) {
            connection.last_connected_at = update.last_connected_at;
            Ok(())
        } else {
            Err(ClientError::ConnectionCache(
                "Connection not found".to_string(),
            ))
        }
    }

    async fn list(&self) -> Vec<ConnectionInfo> {
        self.connections.values().cloned().collect()
    }
}
