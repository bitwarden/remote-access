uniffi::setup_scaffolding!();

mod adapters;
mod callbacks;
mod error;
mod remote_client;
mod types;
mod user_client;

pub use callbacks::{
    AuditLogger, ConnectionStorage, CredentialProvider, EventHandler, FfiStoredConnection,
    FingerprintVerifier, IdentityStorage, PskStorage,
};
pub use error::ClientError;
pub use remote_client::RemoteClient;
pub use types::{
    FfiAuditEvent, FfiConnectionInfo, FfiConnectionType, FfiCredentialData, FfiCredentialQuery,
    FfiEvent, FfiPskEntry,
};
pub use user_client::UserClient;

use std::sync::OnceLock;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Shared tokio runtime for async UniFFI exports and background tasks.
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| tokio::runtime::Runtime::new().expect("Failed to create tokio runtime"))
}

/// Initialize tracing subscriber (called once per process, subsequent calls are no-ops).
pub(crate) fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

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
