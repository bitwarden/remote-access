use std::fs;
use std::path::{Path, PathBuf};

use bw_proxy::IdentityKeyPair;
use bw_rat_client::{IdentityProvider, RemoteClientError};
use tracing::{debug, info};

/// Manages persistent storage identity key pairs to a file
pub struct FileIdentityStorage {
    keypair: IdentityKeyPair,
}

impl IdentityProvider for FileIdentityStorage {
    fn identity(&self) -> &IdentityKeyPair {
        &self.keypair
    }
}
impl FileIdentityStorage {
    /// Load existing identity or generate new one
    ///
    /// Stores the 32-byte seed in ~/.bw-remote/identity.key
    pub fn load_or_generate(storage_name: &str) -> Result<Self, RemoteClientError> {
        let storage_path = Self::default_storage_path(storage_name)?;

        let keypair = if storage_path.exists() {
            info!("Loading existing identity from {:?}", storage_path);
            Self::load_from_file(&storage_path)?
        } else {
            info!("Generating new identity and saving to {:?}", storage_path);
            let keypair = IdentityKeyPair::generate();
            Self::save_to_file(&storage_path, &keypair)?;
            keypair
        };

        Ok(Self { keypair })
    }

    /// Get the default storage path (~/.bw-remote/identity.key)
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

    /// Load keypair from file
    fn load_from_file(path: &Path) -> Result<IdentityKeyPair, RemoteClientError> {
        let cose_bytes = fs::read(path).map_err(|e| {
            RemoteClientError::IdentityStorageFailed(format!("Failed to read identity file: {e}"))
        })?;
        debug!("Loaded identity seed from file");
        IdentityKeyPair::from_cose(&cose_bytes).map_err(|_| {
            RemoteClientError::IdentityStorageFailed(
                "Failed to parse identity from seed".to_string(),
            )
        })
    }

    /// Save keypair to file
    fn save_to_file(path: &Path, keypair: &IdentityKeyPair) -> Result<(), RemoteClientError> {
        let cose_bytes = keypair.to_cose();

        fs::write(path, cose_bytes).map_err(|e| {
            RemoteClientError::IdentityStorageFailed(format!("Failed to write identity file: {e}"))
        })?;

        debug!("Saved identity seed to file");
        Ok(())
    }
}
