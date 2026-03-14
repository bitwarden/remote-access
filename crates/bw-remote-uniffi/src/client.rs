use std::sync::Mutex;

use ap_client::{
    ConnectionInfo, CredentialQuery, DefaultProxyClient, IdentityFingerprint,
    Psk, RemoteClient, RemoteClientHandle,
};

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
        // Close any existing connection before creating a new one
        // (avoids duplicate proxy registrations with the same identity)
        if let Ok(mut inner) = self.inner.lock() {
            *inner = None;
        }

        let identity = FileIdentityStorage::load_or_generate(&self.identity_name)
            .map_err(RemoteAccessError::from)?;

        let session_store = FileSessionCache::load_or_create(&self.identity_name)
            .map_err(RemoteAccessError::from)?;

        let proxy_client = Box::new(DefaultProxyClient::from_url(self.proxy_url.clone()));

        // Create the client (connects to proxy)
        let RemoteClientHandle {
            client,
            notifications: _notifications,
            requests: _requests,
        } = self
            .runtime
            .block_on(async {
                RemoteClient::connect(
                    Box::new(identity),
                    Box::new(session_store),
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
                        .pair_with_handshake(token_str.to_string(), false)
                        .await
                        .map_err(RemoteAccessError::from)?;
                    Ok(Some(fp.to_hex()))
                }
            } else if let Some(session_hex) = session.as_deref() {
                let fingerprint = parse_fingerprint_hex(session_hex)?;
                client
                    .load_cached_connection(fingerprint)
                    .await
                    .map_err(RemoteAccessError::from)?;
                Ok(None)
            } else {
                // Auto-select cached session if exactly one exists
                let connections = client
                    .list_connections()
                    .await
                    .map_err(RemoteAccessError::from)?;
                if connections.len() == 1 {
                    let fingerprint = connections[0].fingerprint;
                    client
                        .load_cached_connection(fingerprint)
                        .await
                        .map_err(RemoteAccessError::from)?;
                    Ok(None)
                } else if connections.is_empty() {
                    Err(RemoteAccessError::SessionError {
                        message: "No cached sessions — provide a token to start a new connection"
                            .to_string(),
                    })
                } else {
                    Err(RemoteAccessError::SessionError {
                        message: format!(
                            "Multiple cached sessions ({}) — specify one with session parameter",
                            connections.len()
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
        let inner = self
            .inner
            .lock()
            .map_err(|_| RemoteAccessError::SessionError {
                message: "Failed to acquire client lock".to_string(),
            })?;

        let client = inner
            .as_ref()
            .ok_or(RemoteAccessError::CredentialRequestFailed {
                message: "Not connected — call connect() first".to_string(),
            })?;

        let query = CredentialQuery::Domain(domain);
        let cred = self
            .runtime
            .block_on(async { client.request_credential(&query, None).await })
            .map_err(RemoteAccessError::from)?;

        Ok(RemoteCredentialData::from(cred))
    }

    /// Whether the client is connected and has a secure channel.
    pub fn is_ready(&self) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.as_ref().map(|_| true))
            .unwrap_or(false)
    }

    /// List all cached sessions.
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Vec::new(),
        };

        match inner.as_ref() {
            Some(client) => {
                let connections: Vec<ConnectionInfo> = self
                    .runtime
                    .block_on(async { client.list_connections().await })
                    .unwrap_or_default();

                connections
                    .into_iter()
                    .map(|c| SessionInfo {
                        fingerprint: c.fingerprint.to_hex(),
                        name: c.name,
                        cached_at: c.cached_at,
                        last_connected_at: c.last_connected_at,
                    })
                    .collect()
            }
            None => Vec::new(),
        }
    }

    /// Close the connection and release resources.
    pub fn close(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            // Drop the client handle, which shuts down the event loop
            *inner = None;
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
    IdentityFingerprint::from_hex(hex_str).map_err(|e| RemoteAccessError::InvalidArgument {
        message: format!("Invalid fingerprint: {e}"),
    })
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
