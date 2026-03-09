mod identity_storage;
mod psk_storage;
mod session_storage;

use std::path::PathBuf;

use bw_rat_client::RemoteClientError;

pub use identity_storage::FileIdentityStorage;
pub use psk_storage::PskStorage;
pub use session_storage::FileSessionCache;

/// Ensure the `~/.bw-remote/` storage directory exists, creating it if needed.
fn ensure_storage_dir() -> Result<PathBuf, RemoteClientError> {
    let home_dir = dirs::home_dir().ok_or_else(|| {
        RemoteClientError::IdentityStorageFailed("Could not find home directory".to_string())
    })?;
    let dir = home_dir.join(".bw-remote");
    std::fs::create_dir_all(&dir).map_err(|e| {
        RemoteClientError::IdentityStorageFailed(format!(
            "Failed to create .bw-remote directory: {e}"
        ))
    })?;
    Ok(dir)
}
