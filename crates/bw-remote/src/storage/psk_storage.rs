use std::fs;
use std::path::PathBuf;

use bw_noise_protocol::Psk;
use bw_rat_client::RemoteClientError;
use tracing::{debug, info};

use super::ensure_storage_dir;

/// Manages persistent storage of reusable PSKs.
///
/// PSKs are stored as 64-character hex strings in `~/.bw-remote/psk_{name}.hex`.
pub struct PskStorage;

impl PskStorage {
    /// Load an existing PSK by name, or generate and save a new one.
    pub fn load_or_generate(name: &str) -> Result<Psk, RemoteClientError> {
        let path = Self::psk_path(name)?;

        if path.exists() {
            info!("Loading existing PSK from {:?}", path);
            Self::load_from_file(&path)
        } else {
            info!("Generating new PSK and saving to {:?}", path);
            let psk = Psk::generate();
            Self::save_to_file(&path, &psk)?;
            Ok(psk)
        }
    }

    /// Load all stored PSKs from `~/.bw-remote/psk_*.hex`.
    pub fn load_all() -> Result<Vec<Psk>, RemoteClientError> {
        let dir = ensure_storage_dir()?;
        let mut psks = Vec::new();

        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(psks),
            Err(e) => {
                return Err(RemoteClientError::IdentityStorageFailed(format!(
                    "Failed to read .bw-remote directory: {e}"
                )));
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            if file_name.starts_with("psk_") && file_name.ends_with(".hex") {
                match Self::load_from_file(&path) {
                    Ok(psk) => {
                        debug!("Loaded PSK from {:?}", path);
                        psks.push(psk);
                    }
                    Err(e) => {
                        info!("Skipping invalid PSK file {:?}: {}", path, e);
                    }
                }
            }
        }

        if !psks.is_empty() {
            info!("Loaded {} stored PSK(s) into keychain", psks.len());
        }

        Ok(psks)
    }

    fn psk_path(name: &str) -> Result<PathBuf, RemoteClientError> {
        let dir = ensure_storage_dir()?;
        Ok(dir.join(format!("psk_{name}.hex")))
    }

    fn load_from_file(path: &std::path::Path) -> Result<Psk, RemoteClientError> {
        let hex_str = fs::read_to_string(path).map_err(|e| {
            RemoteClientError::IdentityStorageFailed(format!("Failed to read PSK file: {e}"))
        })?;
        Psk::from_hex(hex_str.trim()).map_err(|e| {
            RemoteClientError::IdentityStorageFailed(format!("Failed to parse PSK: {e}"))
        })
    }

    fn save_to_file(path: &std::path::Path, psk: &Psk) -> Result<(), RemoteClientError> {
        fs::write(path, psk.to_hex()).map_err(|e| {
            RemoteClientError::IdentityStorageFailed(format!("Failed to write PSK file: {e}"))
        })?;
        debug!("Saved PSK to {:?}", path);
        Ok(())
    }
}
