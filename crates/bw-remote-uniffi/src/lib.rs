uniffi::setup_scaffolding!();

mod client;
mod error;
mod storage;
mod types;

pub use client::RemoteAccessClient;
pub use error::RemoteAccessError;
pub use types::{RemoteCredentialData, SessionInfo};

/// Connect to a remote peer and request a single credential (one-shot convenience function).
///
/// Creates a client, connects, requests the credential, and closes — all in one call.
///
/// * `domain` — Domain to request credentials for (e.g. "example.com").
/// * `token` — Rendezvous code or PSK token. `None` to use a cached session.
/// * `session` — Hex fingerprint of a specific cached session.
/// * `proxy_url` — WebSocket URL of the proxy server.
/// * `identity_name` — Name for the identity keypair file.
#[uniffi::export]
pub fn connect_and_request(
    domain: String,
    token: Option<String>,
    session: Option<String>,
    proxy_url: String,
    identity_name: String,
) -> Result<RemoteCredentialData, RemoteAccessError> {
    let client = RemoteAccessClient::new(proxy_url, identity_name)?;
    client.connect(token, session)?;
    let cred = client.request_credential(domain)?;
    client.close();
    Ok(cred)
}
