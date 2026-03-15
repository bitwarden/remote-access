use std::sync::Mutex;

use tokio::sync::mpsc;

use bw_proxy_client::ProxyClientConfig;
use bw_rat_client::{DefaultProxyClient, IdentityFingerprint, IdentityProvider, Psk, RemoteClient};

use crate::error::RemoteAccessError;
use crate::storage::{FileIdentityStorage, FileSessionCache};
use crate::types::{RemoteCredentialData, SessionInfo};

/// A remote-access client for requesting credentials from a trusted peer.
///
/// Wraps the full Rust crypto/protocol stack behind a synchronous FFI-safe API.
/// Internally owns a Tokio runtime and blocks on async operations.
///
/// Fingerprint verification is not performed in headless mode — the returned
/// handshake fingerprint from `connect()` can be verified out-of-band by callers.
///
/// Implements `Drop` to ensure the underlying connection is closed if the caller
/// forgets to call `close()`.
#[derive(uniffi::Object)]
pub struct RemoteAccessClient {
    runtime: tokio::runtime::Runtime,
    inner: Mutex<Option<RemoteClient>>,
    proxy_url: String,
    identity_name: String,
}

#[uniffi::export]
impl RemoteAccessClient {
    /// Create a new RemoteAccessClient.
    ///
    /// * `proxy_url` — WebSocket URL of the proxy server (e.g. "ws://localhost:8080").
    /// * `identity_name` — Name for the identity keypair file (~/.bw-remote/{name}.key).
    #[uniffi::constructor]
    pub fn new(proxy_url: String, identity_name: String) -> Result<Self, RemoteAccessError> {
        // Enable RUST_LOG for debugging
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_writer(std::io::stderr)
            .try_init();

        let runtime =
            tokio::runtime::Runtime::new().map_err(|e| RemoteAccessError::ConnectionFailed {
                message: format!("Failed to create runtime: {e}"),
            })?;

        Ok(Self {
            runtime,
            inner: Mutex::new(None),
            proxy_url,
            identity_name,
        })
    }

    /// Connect to a remote peer.
    ///
    /// * `token` — Rendezvous code (e.g. "ABC-DEF-GHI") or PSK token
    ///   (`<64hex>_<64hex>`). Pass `None` to use a cached session.
    /// * `session` — Hex fingerprint of a specific cached session to reconnect.
    ///
    /// Returns the 6-char handshake fingerprint (for new connections) or `None` (cached).
    pub fn connect(
        &self,
        token: Option<String>,
        session: Option<String>,
    ) -> Result<Option<String>, RemoteAccessError> {
        let identity = FileIdentityStorage::load_or_generate(&self.identity_name)
            .map_err(RemoteAccessError::from)?;

        let session_store = FileSessionCache::load_or_create(&self.identity_name)
            .map_err(RemoteAccessError::from)?;

        // Large event buffer: events are not consumed in headless mode, so the channel
        // must be big enough to hold all events emitted during connect + handshake without
        // blocking RemoteClient. Response channel is unused (fingerprint verification disabled).
        let (event_tx, _event_rx) = mpsc::channel(256);
        let (_response_tx, response_rx) = mpsc::channel(32);

        let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
            proxy_url: self.proxy_url.clone(),
            identity_keypair: Some(identity.identity().to_owned()),
        }));

        // Create the client (connects to proxy)
        let mut client = self
            .runtime
            .block_on(async {
                RemoteClient::new(
                    Box::new(identity),
                    Box::new(session_store),
                    event_tx,
                    response_rx,
                    proxy_client,
                )
                .await
            })
            .map_err(RemoteAccessError::from)?;

        // Determine connection mode and connect
        let handshake_fingerprint = self.runtime.block_on(async {
            if let Some(token_str) = token.as_deref() {
                // Parse token: PSK or rendezvous
                if token_str.contains('_') && token_str.len() == 129 {
                    // PSK token: <64hex>_<64hex>
                    let parts: Vec<&str> = token_str.split('_').collect();
                    if parts.len() != 2 || parts[0].len() != 64 || parts[1].len() != 64 {
                        return Err(RemoteAccessError::InvalidArgument {
                            message: "Invalid PSK token format".to_string(),
                        });
                    }
                    let psk = Psk::from_hex(parts[0]).map_err(|e| {
                        RemoteAccessError::InvalidArgument {
                            message: format!("Invalid PSK: {e}"),
                        }
                    })?;
                    let fingerprint = parse_fingerprint_hex(parts[1])?;

                    client
                        .pair_with_psk(psk, fingerprint)
                        .await
                        .map_err(RemoteAccessError::from)?;
                    Ok(None)
                } else {
                    // Rendezvous code — no fingerprint verification (headless)
                    let fp = client
                        .pair_with_handshake(token_str, false)
                        .await
                        .map_err(RemoteAccessError::from)?;
                    Ok(Some(hex::encode(fp.0)))
                }
            } else if let Some(session_hex) = session.as_deref() {
                let fingerprint = parse_fingerprint_hex(session_hex)?;
                client
                    .load_cached_session(fingerprint)
                    .await
                    .map_err(RemoteAccessError::from)?;
                Ok(None)
            } else {
                // Auto-select cached session if exactly one exists
                let sessions = client.session_store().list_sessions();
                if sessions.len() == 1 {
                    let (fingerprint, _, _, _) = &sessions[0];
                    client
                        .load_cached_session(*fingerprint)
                        .await
                        .map_err(RemoteAccessError::from)?;
                    Ok(None)
                } else if sessions.is_empty() {
                    Err(RemoteAccessError::SessionError {
                        message: "No cached sessions — provide a token to start a new connection"
                            .to_string(),
                    })
                } else {
                    Err(RemoteAccessError::SessionError {
                        message: format!(
                            "Multiple cached sessions ({}) — specify one with session parameter",
                            sessions.len()
                        ),
                    })
                }
            }
        })?;

        // Store the connected client
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| RemoteAccessError::SessionError {
                message: "Failed to acquire client lock".to_string(),
            })?;
        *inner = Some(client);

        Ok(handshake_fingerprint)
    }

    /// Request a credential for a domain.
    ///
    /// * `domain` — The domain to look up (e.g. "example.com").
    ///
    /// Returns credential data with username, password, totp, uri, and notes.
    pub fn request_credential(
        &self,
        domain: String,
    ) -> Result<RemoteCredentialData, RemoteAccessError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| RemoteAccessError::SessionError {
                message: "Failed to acquire client lock".to_string(),
            })?;

        let client = inner
            .as_mut()
            .ok_or(RemoteAccessError::CredentialRequestFailed {
                message: "Not connected — call connect() first".to_string(),
            })?;

        let cred = self
            .runtime
            .block_on(async { client.request_credential(&domain).await })
            .map_err(RemoteAccessError::from)?;

        Ok(RemoteCredentialData::from(cred))
    }

    /// Whether the secure channel is established and ready.
    pub fn is_ready(&self) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.as_ref().map(|c| c.is_ready()))
            .unwrap_or(false)
    }

    /// List all cached sessions.
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Vec::new(),
        };

        match inner.as_ref() {
            Some(client) => client
                .session_store()
                .list_sessions()
                .into_iter()
                .map(
                    |(fingerprint, name, cached_at, last_connected_at)| SessionInfo {
                        fingerprint: hex::encode(fingerprint.0),
                        name,
                        cached_at,
                        last_connected_at,
                    },
                )
                .collect(),
            None => Vec::new(),
        }
    }

    /// Close the connection and release resources.
    pub fn close(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(mut client) = inner.take() {
                self.runtime.block_on(async {
                    client.close().await;
                });
            }
        }
    }
}

impl Drop for RemoteAccessClient {
    fn drop(&mut self) {
        self.close();
    }
}

/// Parse a 64-char hex string into an IdentityFingerprint.
fn parse_fingerprint_hex(hex_str: &str) -> Result<IdentityFingerprint, RemoteAccessError> {
    let clean = hex_str.replace(['-', ' ', ':'], "");
    if clean.len() != 64 {
        return Err(RemoteAccessError::InvalidArgument {
            message: format!("Fingerprint must be 64 hex characters, got {}", clean.len()),
        });
    }
    let bytes = hex::decode(&clean).map_err(|e| RemoteAccessError::InvalidArgument {
        message: format!("Invalid hex: {e}"),
    })?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(IdentityFingerprint(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_fingerprint() {
        let hex_str = "a".repeat(64);
        let result = parse_fingerprint_hex(&hex_str);
        assert!(result.is_ok());
        let fp = result.expect("should parse");
        assert_eq!(fp.0, [0xaa; 32]);
    }

    #[test]
    fn parse_fingerprint_with_separators() {
        // 64 hex chars with dashes, spaces, colons mixed in
        let raw = "aa".repeat(32);
        // Insert separators: "aa-aa aa:aa..."
        let with_seps = format!(
            "{}-{} {}:{}",
            &raw[..16],
            &raw[16..32],
            &raw[32..48],
            &raw[48..64]
        );
        let result = parse_fingerprint_hex(&with_seps);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_fingerprint_too_short() {
        let result = parse_fingerprint_hex("aabb");
        assert!(matches!(
            result,
            Err(RemoteAccessError::InvalidArgument { .. })
        ));
    }

    #[test]
    fn parse_fingerprint_too_long() {
        let hex_str = "a".repeat(66);
        let result = parse_fingerprint_hex(&hex_str);
        assert!(matches!(
            result,
            Err(RemoteAccessError::InvalidArgument { .. })
        ));
    }

    #[test]
    fn parse_fingerprint_invalid_hex() {
        let hex_str = format!("{}zz", "a".repeat(62));
        let result = parse_fingerprint_hex(&hex_str);
        assert!(matches!(
            result,
            Err(RemoteAccessError::InvalidArgument { .. })
        ));
    }

    #[test]
    fn client_new_succeeds() {
        let client = RemoteAccessClient::new(
            "ws://localhost:9999".to_string(),
            "test-uniffi-unit".to_string(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn client_not_ready_before_connect() {
        let client = RemoteAccessClient::new(
            "ws://localhost:9999".to_string(),
            "test-uniffi-unit".to_string(),
        )
        .expect("should create client");
        assert!(!client.is_ready());
    }

    #[test]
    fn client_list_sessions_empty_before_connect() {
        let client = RemoteAccessClient::new(
            "ws://localhost:9999".to_string(),
            "test-uniffi-unit".to_string(),
        )
        .expect("should create client");
        assert!(client.list_sessions().is_empty());
    }

    #[test]
    fn client_request_credential_fails_before_connect() {
        let client = RemoteAccessClient::new(
            "ws://localhost:9999".to_string(),
            "test-uniffi-unit".to_string(),
        )
        .expect("should create client");
        let result = client.request_credential("example.com".to_string());
        assert!(matches!(
            result,
            Err(RemoteAccessError::CredentialRequestFailed { .. })
        ));
    }

    #[test]
    fn client_close_is_safe_before_connect() {
        let client = RemoteAccessClient::new(
            "ws://localhost:9999".to_string(),
            "test-uniffi-unit".to_string(),
        )
        .expect("should create client");
        // Should not panic
        client.close();
    }
}
