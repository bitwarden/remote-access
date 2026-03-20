use std::fs;
use std::path::{Path, PathBuf};

use ap_client::{ClientError, Psk, PskEntry, PskStore};

const PSK_LENGTH: usize = 32;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// On-disk representation of a PSK entry.
#[derive(Clone, Serialize, Deserialize)]
struct PskRecord {
    psk_id: String,
    /// Hex-encoded PSK (64 chars).
    psk_hex: String,
    #[serde(default)]
    name: Option<String>,
    created_at: u64,
}

impl std::fmt::Debug for PskRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PskRecord")
            .field("psk_id", &self.psk_id)
            .field("psk_hex", &"[REDACTED]")
            .field("name", &self.name)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Persistent data stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PskStoreData {
    psks: Vec<PskRecord>,
}

fn record_to_entry(record: &PskRecord) -> Result<PskEntry, ClientError> {
    let psk_bytes = hex::decode(&record.psk_hex)
        .map_err(|e| ClientError::Serialization(format!("Invalid PSK hex: {e}")))?;

    if psk_bytes.len() != PSK_LENGTH {
        return Err(ClientError::Serialization(format!(
            "Invalid PSK length: expected {PSK_LENGTH}, got {}",
            psk_bytes.len()
        )));
    }

    let mut arr = [0u8; PSK_LENGTH];
    arr.copy_from_slice(&psk_bytes);

    Ok(PskEntry {
        psk_id: record.psk_id.clone(),
        psk: Psk::from_bytes(arr),
        name: record.name.clone(),
        created_at: record.created_at,
    })
}

fn entry_to_record(entry: &PskEntry) -> PskRecord {
    PskRecord {
        psk_id: entry.psk_id.clone(),
        psk_hex: entry.psk.to_hex(),
        name: entry.name.clone(),
        created_at: entry.created_at,
    }
}

/// File-backed PSK store implementation.
///
/// Stores reusable PSKs in a JSON file at `~/.access-protocol/psk_store_{name}.json`.
pub struct FilePskStore {
    store_path: PathBuf,
    data: PskStoreData,
}

impl std::fmt::Debug for FilePskStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilePskStore")
            .field("store_path", &self.store_path)
            .field("count", &self.data.psks.len())
            .finish()
    }
}

#[async_trait]
impl PskStore for FilePskStore {
    async fn get(&self, psk_id: &String) -> Option<PskEntry> {
        self.data
            .psks
            .iter()
            .find(|r| r.psk_id == *psk_id)
            .and_then(|record| match record_to_entry(record) {
                Ok(entry) => Some(entry),
                Err(e) => {
                    debug!("Failed to deserialize PSK entry for {}: {}", psk_id, e);
                    None
                }
            })
    }

    async fn save(&mut self, entry: PskEntry) -> Result<(), ClientError> {
        let record = entry_to_record(&entry);

        if let Some(existing) = self.data.psks.iter_mut().find(|r| r.psk_id == entry.psk_id) {
            *existing = record;
            debug!("Updated existing PSK entry");
        } else {
            self.data.psks.push(record);
            debug!("Added new PSK entry");
        }

        self.persist()?;
        Ok(())
    }

    async fn remove(&mut self, psk_id: &String) -> Result<(), ClientError> {
        self.data.psks.retain(|r| r.psk_id != *psk_id);
        self.persist()?;
        debug!("Removed PSK entry");
        Ok(())
    }

    async fn list(&self) -> Vec<PskEntry> {
        self.data
            .psks
            .iter()
            .filter_map(|record| match record_to_entry(record) {
                Ok(entry) => Some(entry),
                Err(e) => {
                    debug!("Failed to deserialize PSK entry: {}", e);
                    None
                }
            })
            .collect()
    }
}

impl FilePskStore {
    /// Load or create PSK store.
    pub fn load_or_create(store_name: &str) -> Result<Self, ClientError> {
        let store_path = Self::default_store_path(store_name)?;

        let data = if store_path.exists() {
            debug!("Loading PSK store from {:?}", store_path);
            Self::load_from_file(&store_path)?
        } else {
            debug!("Creating new PSK store");
            PskStoreData { psks: Vec::new() }
        };

        debug!("PSK store has {} entries", data.psks.len());
        Ok(Self { store_path, data })
    }

    /// Save store to disk.
    fn persist(&self) -> Result<(), ClientError> {
        let json = serde_json::to_string_pretty(&self.data).map_err(|e| {
            ClientError::Serialization(format!("PSK store serialization failed: {e}"))
        })?;

        fs::write(&self.store_path, json).map_err(|e| {
            ClientError::Serialization(format!("Failed to write PSK store file: {e}"))
        })?;

        debug!("Saved PSK store");
        Ok(())
    }

    /// Get default store path (`~/.access-protocol/psk_store_{store_name}.json`).
    fn default_store_path(store_name: &str) -> Result<PathBuf, ClientError> {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            ClientError::Serialization("Could not find home directory".to_string())
        })?;

        let ap_dir = home_dir.join(".access-protocol");
        fs::create_dir_all(&ap_dir).map_err(|e| {
            ClientError::Serialization(format!("Failed to create .access-protocol directory: {e}"))
        })?;

        Ok(ap_dir.join(format!("psk_store_{store_name}.json")))
    }

    /// Load store from file.
    fn load_from_file(path: &Path) -> Result<PskStoreData, ClientError> {
        let contents = fs::read_to_string(path).map_err(|e| {
            ClientError::Serialization(format!("Failed to read PSK store file: {e}"))
        })?;

        let data: PskStoreData = serde_json::from_str(&contents).map_err(|e| {
            ClientError::Serialization(format!("Failed to parse PSK store file: {e}"))
        })?;

        debug!("Loaded {} PSK(s) from store", data.psks.len());
        Ok(data)
    }
}
