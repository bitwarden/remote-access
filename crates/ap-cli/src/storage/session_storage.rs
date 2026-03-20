use std::fs;
use std::path::{Path, PathBuf};

use ap_client::{ClientError, SessionInfo, SessionStore, SessionUpdate};
use ap_noise::{MultiDeviceTransport, PersistentTransportState};
use ap_proxy_protocol::IdentityFingerprint;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Session record stored in cache (serde representation).
///
/// Transport state is stored as CBOR bytes for serialization.
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

/// Cache data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionCacheData {
    sessions: Vec<SessionRecord>,
}

/// Convert a `SessionRecord` to a `SessionInfo`, deserializing transport state.
fn record_to_info(record: &SessionRecord) -> Result<SessionInfo, ClientError> {
    let transport_state = match &record.transport_state {
        Some(bytes) => {
            Some(PersistentTransportState::from_bytes(bytes).map(MultiDeviceTransport::from)?)
        }
        None => None,
    };

    Ok(SessionInfo {
        fingerprint: record.remote_fingerprint,
        name: record.name.clone(),
        cached_at: record.cached_at,
        last_connected_at: record.last_connected_at,
        transport_state,
    })
}

/// Convert a `SessionInfo` to a `SessionRecord`, serializing transport state.
fn info_to_record(info: &SessionInfo) -> Result<SessionRecord, ClientError> {
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

    Ok(SessionRecord {
        remote_fingerprint: info.fingerprint,
        cached_at: info.cached_at,
        last_connected_at: info.last_connected_at,
        transport_state: transport_bytes,
        name: info.name.clone(),
    })
}

/// File-based session cache implementation
///
/// Stores sessions in a JSON file at ~/.access-protocol/session_cache_{name}.json
pub struct FileSessionCache {
    cache_path: PathBuf,
    data: SessionCacheData,
}

#[async_trait]
impl SessionStore for FileSessionCache {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<SessionInfo> {
        self.data
            .sessions
            .iter()
            .find(|s| s.remote_fingerprint == *fingerprint)
            .and_then(|record| match record_to_info(record) {
                Ok(info) => Some(info),
                Err(e) => {
                    debug!("Failed to deserialize session for {:?}: {}", fingerprint, e);
                    None
                }
            })
    }

    async fn save(&mut self, session: SessionInfo) -> Result<(), ClientError> {
        let record = info_to_record(&session)?;

        if let Some(existing) = self
            .data
            .sessions
            .iter_mut()
            .find(|s| s.remote_fingerprint == session.fingerprint)
        {
            *existing = record;
            debug!("Updated existing session cache entry");
        } else {
            self.data.sessions.push(record);
            debug!("Added new session cache entry");
        }

        self.persist()?;
        Ok(())
    }

    async fn update(&mut self, update: SessionUpdate) -> Result<(), ClientError> {
        if let Some(session) = self
            .data
            .sessions
            .iter_mut()
            .find(|s| s.remote_fingerprint == update.fingerprint)
        {
            session.last_connected_at = update.last_connected_at;
            self.persist()?;
            debug!("Updated last_connected_at for session");
            Ok(())
        } else {
            Err(ClientError::SessionCache("Session not found".to_string()))
        }
    }

    async fn list(&self) -> Vec<SessionInfo> {
        self.data
            .sessions
            .iter()
            .filter_map(|record| match record_to_info(record) {
                Ok(info) => Some(info),
                Err(e) => {
                    debug!("Failed to deserialize session: {}", e);
                    None
                }
            })
            .collect()
    }
}

impl FileSessionCache {
    /// Clear all cached sessions.
    pub async fn clear(&mut self) -> Result<(), ClientError> {
        self.data.sessions.clear();
        self.persist()?;
        debug!("Cleared all session cache entries");
        Ok(())
    }

    /// Load or create session cache
    pub fn load_or_create(cache_name: &str) -> Result<Self, ClientError> {
        let cache_path = Self::default_cache_path(cache_name)?;

        let data = if cache_path.exists() {
            debug!("Loading session cache from {:?}", cache_path);
            Self::load_from_file(&cache_path)?
        } else {
            debug!("Creating new session cache");
            SessionCacheData {
                sessions: Vec::new(),
            }
        };

        Ok(Self { cache_path, data })
    }

    /// Save cache to disk
    fn persist(&self) -> Result<(), ClientError> {
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| ClientError::SessionCache(format!("Serialization failed: {e}")))?;

        fs::write(&self.cache_path, json)
            .map_err(|e| ClientError::SessionCache(format!("Failed to write cache file: {e}")))?;

        debug!("Saved session cache");
        Ok(())
    }

    /// Get default cache path (~/.access-protocol/session_cache_{cache_name}.json)
    fn default_cache_path(cache_name: &str) -> Result<PathBuf, ClientError> {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            ClientError::SessionCache("Could not find home directory".to_string())
        })?;

        let ap_dir = home_dir.join(".access-protocol");
        if !ap_dir.exists() {
            fs::create_dir_all(&ap_dir).map_err(|e| {
                ClientError::SessionCache(format!(
                    "Failed to create .access-protocol directory: {e}"
                ))
            })?;
        }

        Ok(ap_dir.join(format!("session_cache_{cache_name}.json")))
    }

    /// Load cache from file
    fn load_from_file(path: &Path) -> Result<SessionCacheData, ClientError> {
        let contents = fs::read_to_string(path)
            .map_err(|e| ClientError::SessionCache(format!("Failed to read cache file: {e}")))?;

        let data: SessionCacheData = serde_json::from_str(&contents)
            .map_err(|e| ClientError::SessionCache(format!("Failed to parse cache file: {e}")))?;

        debug!("Loaded {} session(s) from cache", data.sessions.len());
        Ok(data)
    }
}
