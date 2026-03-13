use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bw_noise_protocol::{MultiDeviceTransport, PersistentTransportState};
use bw_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use bw_rat_client::{IdentityProvider, RemoteClientError, SessionStore};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// FileIdentityStorage — implements IdentityProvider
// ---------------------------------------------------------------------------

pub struct FileIdentityStorage {
    keypair: IdentityKeyPair,
}

impl IdentityProvider for FileIdentityStorage {
    fn identity(&self) -> &IdentityKeyPair {
        &self.keypair
    }
}

impl FileIdentityStorage {
    pub fn load_or_generate(storage_name: &str) -> Result<Self, RemoteClientError> {
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

    fn default_storage_path(storage_name: &str) -> Result<PathBuf, RemoteClientError> {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            RemoteClientError::IdentityStorageFailed("Could not find home directory".to_string())
        })?;

        let bw_remote_dir = home_dir.join(".bw-remote");
        if !bw_remote_dir.exists() {
            fs::create_dir_all(&bw_remote_dir).map_err(|e| {
                RemoteClientError::IdentityStorageFailed(format!(
                    "Failed to create .bw-remote directory: {e}"
                ))
            })?;
        }

        Ok(bw_remote_dir.join(format!("{storage_name}.key")))
    }

    fn load_from_file(path: &Path) -> Result<IdentityKeyPair, RemoteClientError> {
        let cose_bytes = fs::read(path).map_err(|e| {
            RemoteClientError::IdentityStorageFailed(format!("Failed to read identity file: {e}"))
        })?;
        IdentityKeyPair::from_cose(&cose_bytes).map_err(|_| {
            RemoteClientError::IdentityStorageFailed(
                "Failed to parse identity from seed".to_string(),
            )
        })
    }

    fn save_to_file(path: &Path, keypair: &IdentityKeyPair) -> Result<(), RemoteClientError> {
        let cose_bytes = keypair.to_cose();
        fs::write(path, cose_bytes).map_err(|e| {
            RemoteClientError::IdentityStorageFailed(format!("Failed to write identity file: {e}"))
        })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FileSessionCache — implements SessionStore
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

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct FileSessionCache {
    cache_path: PathBuf,
    data: SessionCacheData,
}

impl FileSessionCache {
    pub fn load_or_create(cache_name: &str) -> Result<Self, RemoteClientError> {
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

    fn save(&self) -> Result<(), RemoteClientError> {
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| RemoteClientError::SessionCache(format!("Serialization failed: {e}")))?;
        fs::write(&self.cache_path, json).map_err(|e| {
            RemoteClientError::SessionCache(format!("Failed to write cache file: {e}"))
        })?;
        Ok(())
    }

    fn default_cache_path(cache_name: &str) -> Result<PathBuf, RemoteClientError> {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            RemoteClientError::SessionCache("Could not find home directory".to_string())
        })?;

        let bw_remote_dir = home_dir.join(".bw-remote");
        if !bw_remote_dir.exists() {
            fs::create_dir_all(&bw_remote_dir).map_err(|e| {
                RemoteClientError::SessionCache(format!(
                    "Failed to create .bw-remote directory: {e}"
                ))
            })?;
        }

        Ok(bw_remote_dir.join(format!("session_cache_{cache_name}.json")))
    }

    fn load_from_file(path: &Path) -> Result<SessionCacheData, RemoteClientError> {
        let contents = fs::read_to_string(path).map_err(|e| {
            RemoteClientError::SessionCache(format!("Failed to read cache file: {e}"))
        })?;
        let data: SessionCacheData = serde_json::from_str(&contents).map_err(|e| {
            RemoteClientError::SessionCache(format!("Failed to parse cache file: {e}"))
        })?;
        Ok(data)
    }
}

impl SessionStore for FileSessionCache {
    fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool {
        self.data
            .sessions
            .iter()
            .any(|s| s.remote_fingerprint == *fingerprint)
    }

    fn cache_session(&mut self, fingerprint: IdentityFingerprint) -> Result<(), RemoteClientError> {
        if let Some(existing) = self
            .data
            .sessions
            .iter_mut()
            .find(|s| s.remote_fingerprint == fingerprint)
        {
            existing.cached_at = now_seconds();
        } else {
            let now = now_seconds();
            self.data.sessions.push(SessionRecord {
                remote_fingerprint: fingerprint,
                cached_at: now,
                last_connected_at: now,
                transport_state: None,
                name: None,
            });
        }
        self.save()?;
        Ok(())
    }

    fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        self.data
            .sessions
            .retain(|s| s.remote_fingerprint != *fingerprint);
        self.save()?;
        Ok(())
    }

    fn clear(&mut self) -> Result<(), RemoteClientError> {
        self.data.sessions.clear();
        self.save()?;
        Ok(())
    }

    fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)> {
        self.data
            .sessions
            .iter()
            .map(|s| {
                (
                    s.remote_fingerprint,
                    s.name.clone(),
                    s.cached_at,
                    s.last_connected_at,
                )
            })
            .collect()
    }

    fn set_session_name(
        &mut self,
        fingerprint: &IdentityFingerprint,
        name: String,
    ) -> Result<(), RemoteClientError> {
        if let Some(session) = self
            .data
            .sessions
            .iter_mut()
            .find(|s| s.remote_fingerprint == *fingerprint)
        {
            session.name = Some(name);
            self.save()?;
            Ok(())
        } else {
            Err(RemoteClientError::SessionCache(
                "Session not found".to_string(),
            ))
        }
    }

    fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        if let Some(session) = self
            .data
            .sessions
            .iter_mut()
            .find(|s| s.remote_fingerprint == *fingerprint)
        {
            session.last_connected_at = now_seconds();
            self.save()?;
            Ok(())
        } else {
            Err(RemoteClientError::SessionCache(
                "Session not found".to_string(),
            ))
        }
    }

    fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport_state: MultiDeviceTransport,
    ) -> Result<(), RemoteClientError> {
        if let Some(session) = self
            .data
            .sessions
            .iter_mut()
            .find(|s| s.remote_fingerprint == *fingerprint)
        {
            session.transport_state = Some(
                PersistentTransportState::from(&transport_state)
                    .to_bytes()
                    .map_err(|e| {
                        RemoteClientError::NoiseProtocol(format!(
                            "Failed to serialize transport state: {e}"
                        ))
                    })?,
            );
            self.save()?;
            Ok(())
        } else {
            Err(RemoteClientError::SessionCache(
                "Session not found".to_string(),
            ))
        }
    }

    fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, RemoteClientError> {
        if let Some(session) = self
            .data
            .sessions
            .iter()
            .find(|s| s.remote_fingerprint == *fingerprint)
        {
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
