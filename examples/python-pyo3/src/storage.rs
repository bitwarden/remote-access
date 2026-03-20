use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use ap_noise::{MultiDeviceTransport, PersistentTransportState};
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use ap_client::{IdentityProvider, ClientError, ConnectionInfo, ConnectionStore, ConnectionUpdate};
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
            ClientError::IdentityStorageFailed(
                "Failed to parse identity from seed".to_string(),
            )
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
// FileConnectionCache — implements ConnectionStore
// ---------------------------------------------------------------------------

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionCacheData {
    connections: Vec<ConnectionRecord>,
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn record_to_info(record: &ConnectionRecord) -> Result<ConnectionInfo, ClientError> {
    let transport_state = match &record.transport_state {
        Some(bytes) => Some(
            PersistentTransportState::from_bytes(bytes)
                .map(MultiDeviceTransport::from)?,
        ),
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

fn info_to_record(info: &ConnectionInfo) -> Result<ConnectionRecord, ClientError> {
    let transport_bytes = match &info.transport_state {
        Some(transport) => Some(
            PersistentTransportState::from(transport)
                .to_bytes()
                .map_err(|e| {
                    ClientError::NoiseProtocol(format!(
                        "Failed to serialize transport state: {e}"
                    ))
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

pub struct FileConnectionCache {
    cache_path: PathBuf,
    data: ConnectionCacheData,
}

impl FileConnectionCache {
    pub async fn clear(&mut self) -> Result<(), ClientError> {
        self.data.connections.clear();
        self.persist()?;
        Ok(())
    }

    pub fn load_or_create(cache_name: &str) -> Result<Self, ClientError> {
        let cache_path = Self::default_cache_path(cache_name)?;

        let data = if cache_path.exists() {
            Self::load_from_file(&cache_path)?
        } else {
            ConnectionCacheData {
                connections: Vec::new(),
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
                ClientError::ConnectionCache(format!(
                    "Failed to create .bw-remote directory: {e}"
                ))
            })?;
        }

        Ok(bw_remote_dir.join(format!("connection_cache_{cache_name}.json")))
    }

    fn load_from_file(path: &Path) -> Result<ConnectionCacheData, ClientError> {
        let contents = fs::read_to_string(path).map_err(|e| {
            ClientError::ConnectionCache(format!("Failed to read cache file: {e}"))
        })?;
        let data: ConnectionCacheData = serde_json::from_str(&contents).map_err(|e| {
            ClientError::ConnectionCache(format!("Failed to parse cache file: {e}"))
        })?;
        Ok(data)
    }
}

#[async_trait]
impl ConnectionStore for FileConnectionCache {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<ConnectionInfo> {
        self.data
            .connections
            .iter()
            .find(|s| s.remote_fingerprint == *fingerprint)
            .and_then(|record| record_to_info(record).ok())
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
        } else {
            self.data.connections.push(record);
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
            Ok(())
        } else {
            Err(ClientError::ConnectionCache("Connection not found".to_string()))
        }
    }

    async fn list(&self) -> Vec<ConnectionInfo> {
        self.data
            .connections
            .iter()
            .filter_map(|record| record_to_info(record).ok())
            .collect()
    }
}
