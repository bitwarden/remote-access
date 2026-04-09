use std::fs;
use std::path::{Path, PathBuf};

use ap_client::{ClientError, ConnectionInfo, ConnectionStore, ConnectionUpdate, IdentityProvider};
use ap_noise::{MultiDeviceTransport, PersistentTransportState};
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// FileIdentityStorage — implements IdentityProvider
// ---------------------------------------------------------------------------

pub struct FileIdentityStorage {
    keypair: IdentityKeyPair,
}

#[async_trait]
impl IdentityProvider for FileIdentityStorage {
    async fn identity(&self) -> IdentityKeyPair {
        self.keypair.clone()
    }
}

impl FileIdentityStorage {
    pub fn load_or_generate(storage_name: &str) -> Result<Self, ClientError> {
        let storage_path = Self::default_storage_path(storage_name)?;

        let keypair = if storage_path.exists() {
            Self::load_from_file(&storage_path)?
        } else {
            let keypair = IdentityKeyPair::generate();
            Self::save_to_file(&storage_path, &keypair)?;
            keypair
        };

        Ok(Self { keypair })
    }

    fn default_storage_path(storage_name: &str) -> Result<PathBuf, ClientError> {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            ClientError::IdentityStorageFailed("Could not find home directory".to_string())
        })?;

        let bw_remote_dir = home_dir.join(".bw-remote");
        if !bw_remote_dir.exists() {
            fs::create_dir_all(&bw_remote_dir).map_err(|e| {
                ClientError::IdentityStorageFailed(format!(
                    "Failed to create .bw-remote directory: {e}"
                ))
            })?;
        }

        Ok(bw_remote_dir.join(format!("{storage_name}.key")))
    }

    fn load_from_file(path: &Path) -> Result<IdentityKeyPair, ClientError> {
        let cose_bytes = fs::read(path).map_err(|e| {
            ClientError::IdentityStorageFailed(format!("Failed to read identity file: {e}"))
        })?;
        IdentityKeyPair::from_cose(&cose_bytes).map_err(|_| {
            ClientError::IdentityStorageFailed("Failed to parse identity from seed".to_string())
        })
    }

    fn save_to_file(path: &Path, keypair: &IdentityKeyPair) -> Result<(), ClientError> {
        let cose_bytes = keypair.to_cose();
        fs::write(path, cose_bytes).map_err(|e| {
            ClientError::IdentityStorageFailed(format!("Failed to write identity file: {e}"))
        })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FileSessionCache — implements ConnectionStore
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRecord {
    remote_fingerprint: IdentityFingerprint,
    cached_at: u64,
    last_connected_at: u64,
    #[serde(default)]
    transport_state: Option<Vec<u8>>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionCacheData {
    sessions: Vec<SessionRecord>,
}

pub struct FileSessionCache {
    cache_path: PathBuf,
    data: SessionCacheData,
}

impl FileSessionCache {
    pub fn load_or_create(cache_name: &str) -> Result<Self, ClientError> {
        let cache_path = Self::default_cache_path(cache_name)?;

        let data = if cache_path.exists() {
            Self::load_from_file(&cache_path)?
        } else {
            SessionCacheData {
                sessions: Vec::new(),
            }
        };

        Ok(Self { cache_path, data })
    }

    fn persist(&self) -> Result<(), ClientError> {
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| ClientError::ConnectionCache(format!("Serialization failed: {e}")))?;
        fs::write(&self.cache_path, json).map_err(|e| {
            ClientError::ConnectionCache(format!("Failed to write cache file: {e}"))
        })?;
        Ok(())
    }

    fn default_cache_path(cache_name: &str) -> Result<PathBuf, ClientError> {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            ClientError::ConnectionCache("Could not find home directory".to_string())
        })?;

        let bw_remote_dir = home_dir.join(".bw-remote");
        if !bw_remote_dir.exists() {
            fs::create_dir_all(&bw_remote_dir).map_err(|e| {
                ClientError::ConnectionCache(format!("Failed to create .bw-remote directory: {e}"))
            })?;
        }

        Ok(bw_remote_dir.join(format!("session_cache_{cache_name}.json")))
    }

    fn load_from_file(path: &Path) -> Result<SessionCacheData, ClientError> {
        let contents = fs::read_to_string(path)
            .map_err(|e| ClientError::ConnectionCache(format!("Failed to read cache file: {e}")))?;
        let data: SessionCacheData = serde_json::from_str(&contents).map_err(|e| {
            ClientError::ConnectionCache(format!("Failed to parse cache file: {e}"))
        })?;
        Ok(data)
    }

    /// List all cached connections synchronously (for standalone `list_connections` function).
    pub fn list_sync(&self) -> Vec<ConnectionInfo> {
        self.data
            .sessions
            .iter()
            .map(Self::record_to_connection_info)
            .collect()
    }

    /// Clear all cached connections synchronously (for standalone `clear_connections` function).
    pub fn clear_sync(&mut self) -> Result<(), ClientError> {
        self.data.sessions.clear();
        self.persist()
    }

    fn record_to_connection_info(record: &SessionRecord) -> ConnectionInfo {
        let transport_state = record.transport_state.as_ref().and_then(|bytes| {
            PersistentTransportState::from_bytes(bytes)
                .ok()
                .map(MultiDeviceTransport::from)
        });

        ConnectionInfo {
            fingerprint: record.remote_fingerprint,
            name: record.name.clone(),
            cached_at: record.cached_at,
            last_connected_at: record.last_connected_at,
            transport_state,
        }
    }
}

#[async_trait]
impl ConnectionStore for FileSessionCache {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<ConnectionInfo> {
        self.data
            .sessions
            .iter()
            .find(|s| s.remote_fingerprint == *fingerprint)
            .map(Self::record_to_connection_info)
    }

    async fn save(&mut self, connection: ConnectionInfo) -> Result<(), ClientError> {
        let transport_bytes = connection
            .transport_state
            .as_ref()
            .and_then(|t| PersistentTransportState::from(t).to_bytes().ok());

        // Update or insert
        if let Some(existing) = self
            .data
            .sessions
            .iter_mut()
            .find(|s| s.remote_fingerprint == connection.fingerprint)
        {
            existing.name = connection.name;
            existing.cached_at = connection.cached_at;
            existing.last_connected_at = connection.last_connected_at;
            existing.transport_state = transport_bytes;
        } else {
            self.data.sessions.push(SessionRecord {
                remote_fingerprint: connection.fingerprint,
                cached_at: connection.cached_at,
                last_connected_at: connection.last_connected_at,
                transport_state: transport_bytes,
                name: connection.name,
            });
        }
        self.persist()?;
        Ok(())
    }

    async fn update(&mut self, update: ConnectionUpdate) -> Result<(), ClientError> {
        if let Some(session) = self
            .data
            .sessions
            .iter_mut()
            .find(|s| s.remote_fingerprint == update.fingerprint)
        {
            session.last_connected_at = update.last_connected_at;
            self.persist()?;
            Ok(())
        } else {
            Err(ClientError::ConnectionCache(
                "Connection not found".to_string(),
            ))
        }
    }

    async fn list(&self) -> Vec<ConnectionInfo> {
        self.data
            .sessions
            .iter()
            .map(Self::record_to_connection_info)
            .collect()
    }
}
