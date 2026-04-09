uniffi::setup_scaffolding!();

mod callbacks;
mod client;
mod error;
mod storage;
mod types;
mod user_client;

pub use callbacks::{CredentialProvider, EventHandler};
pub use client::RemoteAccessClient;
pub use error::RemoteAccessError;
pub use types::{FfiConnectionInfo, FfiCredentialData, FfiEvent};
pub use user_client::UserAccessClient;

use storage::FileSessionCache;

/// Check whether a token string looks like a PSK token.
///
/// Returns `true` if the token matches the PSK format
/// (`<64-hex-psk>_<64-hex-fingerprint>`, 129 chars).
/// Useful for consumers to dispatch between `pair_with_psk()` and
/// `pair_with_handshake()`.
#[uniffi::export]
pub fn looks_like_psk_token(token: String) -> bool {
    ap_client::PskToken::looks_like_psk_token(&token)
}

/// List all cached connections for a given identity.
///
/// Reads the session cache file directly — no proxy connection needed.
#[uniffi::export]
pub fn list_connections(identity_name: String) -> Vec<FfiConnectionInfo> {
    let cache = match FileSessionCache::load_or_create(&identity_name) {
        Ok(cache) => cache,
        Err(_) => return Vec::new(),
    };

    cache
        .list_sync()
        .into_iter()
        .map(|c| FfiConnectionInfo {
            fingerprint: c.fingerprint.to_hex(),
            name: c.name,
            cached_at: c.cached_at,
            last_connected_at: c.last_connected_at,
        })
        .collect()
}

/// Clear all cached connections for a given identity.
///
/// Removes all entries from the session cache file.
#[uniffi::export]
pub fn clear_connections(identity_name: String) -> Result<(), RemoteAccessError> {
    let mut cache =
        FileSessionCache::load_or_create(&identity_name).map_err(RemoteAccessError::from)?;
    cache.clear_sync().map_err(RemoteAccessError::from)
}
