use std::fs;
use std::path::{Path, PathBuf};

use ap_client::{ClientError, ConnectionInfo, ConnectionStore, ConnectionUpdate};
use ap_noise::{MultiDeviceTransport, PersistentTransportState};
use ap_proxy_protocol::IdentityFingerprint;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Connection record stored in cache (serde representation).
///
/// Transport state is stored as CBOR bytes for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionRecord {
    remote_fingerprint: IdentityFingerprint,
    cached_at: u64,
    last_connected_at: u64,
    #[serde(default)]
    transport_state: Option<Vec<u8>>,
    #[serde(default)]
    name: Option<String>,
}

/// Cache data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionCacheData {
    connections: Vec<ConnectionRecord>,
}

/// Convert a `ConnectionRecord` to a `ConnectionInfo`, deserializing transport state.
fn record_to_info(record: &ConnectionRecord) -> Result<ConnectionInfo, ClientError> {
    let transport_state = match &record.transport_state {
        Some(bytes) => {
            Some(PersistentTransportState::from_bytes(bytes).map(MultiDeviceTransport::from)?)
        }
        None => None,
    };

    Ok(ConnectionInfo {
        fingerprint: record.remote_fingerprint,
        name: record.name.clone(),
        cached_at: record.cached_at,
        last_connected_at: record.last_connected_at,
        transport_state,
    })
}

/// Convert a `ConnectionInfo` to a `ConnectionRecord`, serializing transport state.
fn info_to_record(info: &ConnectionInfo) -> Result<ConnectionRecord, ClientError> {
    let transport_bytes = match &info.transport_state {
        Some(transport) => Some(
            PersistentTransportState::from(transport)
                .to_bytes()
                .map_err(|e| {
                    ClientError::NoiseProtocol(format!("Failed to serialize transport state: {e}"))
                })?,
        ),
        None => None,
    };

    Ok(ConnectionRecord {
        remote_fingerprint: info.fingerprint,
        cached_at: info.cached_at,
        last_connected_at: info.last_connected_at,
        transport_state: transport_bytes,
        name: info.name.clone(),
    })
}

/// File-based connection cache implementation
///
/// Stores connections in a JSON file at ~/.access-protocol/connection_cache_{name}.json
pub struct FileConnectionCache {
    cache_path: PathBuf,
    data: ConnectionCacheData,
}

#[async_trait]
impl ConnectionStore for FileConnectionCache {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<ConnectionInfo> {
        self.data
            .connections
            .iter()
            .find(|s| s.remote_fingerprint == *fingerprint)
            .and_then(|record| match record_to_info(record) {
                Ok(info) => Some(info),
                Err(e) => {
                    debug!(
                        "Failed to deserialize connection for {:?}: {}",
                        fingerprint, e
                    );
                    None
                }
            })
    }

    async fn save(&mut self, connection: ConnectionInfo) -> Result<(), ClientError> {
        let record = info_to_record(&connection)?;

        if let Some(existing) = self
            .data
            .connections
            .iter_mut()
            .find(|s| s.remote_fingerprint == connection.fingerprint)
        {
            *existing = record;
            debug!("Updated existing connection cache entry");
        } else {
            self.data.connections.push(record);
            debug!("Added new connection cache entry");
        }

        self.persist()?;
        Ok(())
    }

    async fn update(&mut self, update: ConnectionUpdate) -> Result<(), ClientError> {
        if let Some(connection) = self
            .data
            .connections
            .iter_mut()
            .find(|s| s.remote_fingerprint == update.fingerprint)
        {
            connection.last_connected_at = update.last_connected_at;
            self.persist()?;
            debug!("Updated last_connected_at for connection");
            Ok(())
        } else {
            Err(ClientError::ConnectionCache(
                "Connection not found".to_string(),
            ))
        }
    }

    async fn list(&self) -> Vec<ConnectionInfo> {
        self.data
            .connections
            .iter()
            .filter_map(|record| match record_to_info(record) {
                Ok(info) => Some(info),
                Err(e) => {
                    debug!("Failed to deserialize connection: {}", e);
                    None
                }
            })
            .collect()
    }
}

impl FileConnectionCache {
    /// Clear all cached connections.
    pub async fn clear(&mut self) -> Result<(), ClientError> {
        self.data.connections.clear();
        self.persist()?;
        debug!("Cleared all connection cache entries");
        Ok(())
    }

    /// Load or create connection cache
    pub fn load_or_create(cache_name: &str) -> Result<Self, ClientError> {
        let cache_path = Self::default_cache_path(cache_name)?;

        let data = if cache_path.exists() {
            debug!("Loading connection cache from {:?}", cache_path);
            Self::load_from_file(&cache_path)?
        } else {
            debug!("Creating new connection cache");
            ConnectionCacheData {
                connections: Vec::new(),
            }
        };

        Ok(Self { cache_path, data })
    }

    /// Save cache to disk
    fn persist(&self) -> Result<(), ClientError> {
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| ClientError::ConnectionCache(format!("Serialization failed: {e}")))?;

        fs::write(&self.cache_path, json).map_err(|e| {
            ClientError::ConnectionCache(format!("Failed to write cache file: {e}"))
        })?;

        debug!("Saved connection cache");
        Ok(())
    }

    /// Get default cache path (~/.access-protocol/connection_cache_{cache_name}.json)
    fn default_cache_path(cache_name: &str) -> Result<PathBuf, ClientError> {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            ClientError::ConnectionCache("Could not find home directory".to_string())
        })?;

        let ap_dir = home_dir.join(".access-protocol");
        if !ap_dir.exists() {
            fs::create_dir_all(&ap_dir).map_err(|e| {
                ClientError::ConnectionCache(format!(
                    "Failed to create .access-protocol directory: {e}"
                ))
            })?;
        }

        Ok(ap_dir.join(format!("connection_cache_{cache_name}.json")))
    }

    /// Load cache from file
    fn load_from_file(path: &Path) -> Result<ConnectionCacheData, ClientError> {
        let contents = fs::read_to_string(path)
            .map_err(|e| ClientError::ConnectionCache(format!("Failed to read cache file: {e}")))?;

        let data: ConnectionCacheData = serde_json::from_str(&contents).map_err(|e| {
            ClientError::ConnectionCache(format!("Failed to parse cache file: {e}"))
        })?;

        debug!("Loaded {} connection(s) from cache", data.connections.len());
        Ok(data)
    }
}
