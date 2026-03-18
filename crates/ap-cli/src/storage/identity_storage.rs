use std::fs;
use std::path::{Path, PathBuf};

use ap_client::{IdentityProvider, RemoteClientError};
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use async_trait::async_trait;
use tracing::debug;

/// Manages persistent storage identity key pairs to a file
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
    /// Load existing identity or generate new one
    ///
    /// Stores the 32-byte seed in ~/.access-protocol/identity.key
    pub fn load_or_generate(storage_name: &str) -> Result<Self, RemoteClientError> {
        let storage_path = Self::default_storage_path(storage_name)?;

        let keypair = if storage_path.exists() {
            debug!("Loading existing identity from {:?}", storage_path);
            Self::load_from_file(&storage_path)?
        } else {
            debug!("Generating new identity and saving to {:?}", storage_path);
            let keypair = IdentityKeyPair::generate();
            Self::save_to_file(&storage_path, &keypair)?;
            keypair
        };

        Ok(Self { keypair })
    }

    /// Load the identity fingerprint without generating a new key if none exists.
    ///
    /// Returns `None` if no key file exists, `Some(fingerprint)` if it does.
    pub fn load_fingerprint(
        storage_name: &str,
    ) -> Result<Option<IdentityFingerprint>, RemoteClientError> {
        let storage_path = Self::default_storage_path(storage_name)?;
        if !storage_path.exists() {
            return Ok(None);
        }
        let keypair = Self::load_from_file(&storage_path)?;
        Ok(Some(keypair.identity().fingerprint()))
    }

    /// Delete the identity key file for the given storage name.
    ///
    /// Does nothing if the file does not exist.
    pub fn delete(storage_name: &str) -> Result<(), RemoteClientError> {
        let storage_path = Self::default_storage_path(storage_name)?;
        match fs::remove_file(&storage_path) {
            Ok(()) => {
                debug!("Deleted identity key file: {:?}", storage_path);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(RemoteClientError::IdentityStorageFailed(format!(
                "Failed to delete identity file: {e}"
            ))),
        }
    }

    /// Get the default storage path (~/.access-protocol/identity.key)
    fn default_storage_path(storage_name: &str) -> Result<PathBuf, RemoteClientError> {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            RemoteClientError::IdentityStorageFailed("Could not find home directory".to_string())
        })?;

        let ap_dir = home_dir.join(".access-protocol");
        if !ap_dir.exists() {
            fs::create_dir_all(&ap_dir).map_err(|e| {
                RemoteClientError::IdentityStorageFailed(format!(
                    "Failed to create .access-protocol directory: {e}"
                ))
            })?;
        }

        Ok(ap_dir.join(format!("{storage_name}.key")))
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
