use std::sync::{Arc, Mutex};

use ap_client::{
    CredentialQuery, DefaultProxyClient, IdentityFingerprint, PskToken, RemoteClient,
    RemoteClientHandle, RemoteClientNotification,
};
use tokio::sync::mpsc;

use crate::EventHandler;
use crate::error::RemoteAccessError;
use crate::storage::{FileIdentityStorage, FileSessionCache};
use crate::types::{FfiConnectionInfo, FfiCredentialData, FfiEvent};

/// A remote-access client for requesting credentials from a trusted peer.
///
/// Thin wrapper around `ap_client::RemoteClient` exposing individual pairing
/// methods — connection mode orchestration (PSK vs rendezvous vs cached)
/// belongs in the consumer, not here.
///
/// Implements `Drop` to ensure the underlying connection is closed if the
/// caller forgets to call `close()`.
#[derive(uniffi::Object)]
pub struct RemoteAccessClient {
    runtime: tokio::runtime::Runtime,
    inner: Mutex<Option<RemoteClient>>,
    event_handler: Option<Arc<dyn EventHandler>>,
    proxy_url: String,
    identity_name: String,
}

#[uniffi::export]
impl RemoteAccessClient {
    /// Create a new RemoteAccessClient.
    ///
    /// * `proxy_url` — WebSocket URL of the proxy server (e.g. "ws://localhost:8080").
    /// * `identity_name` — Name for the identity keypair file.
    /// * `event_handler` — Optional callback for receiving status notifications.
    #[uniffi::constructor]
    pub fn new(
        proxy_url: String,
        identity_name: String,
        event_handler: Option<Box<dyn EventHandler>>,
    ) -> Result<Self, RemoteAccessError> {
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
            event_handler: event_handler.map(Arc::from),
            proxy_url,
            identity_name,
        })
    }

    /// Connect to the proxy server and authenticate.
    ///
    /// After this, call one of the pairing methods to establish a secure channel:
    /// `pair_with_handshake()`, `pair_with_psk()`, or `load_existing_connection()`.
    pub fn connect(&self) -> Result<(), RemoteAccessError> {
        // Close any existing connection first
        if let Ok(mut inner) = self.inner.lock() {
            *inner = None;
        }

        let identity = FileIdentityStorage::load_or_generate(&self.identity_name)
            .map_err(RemoteAccessError::from)?;

        let session_store = FileSessionCache::load_or_create(&self.identity_name)
            .map_err(RemoteAccessError::from)?;

        let proxy_client = Box::new(DefaultProxyClient::from_url(self.proxy_url.clone()));

        let RemoteClientHandle {
            client,
            notifications,
            requests: _requests,
        } = self
            .runtime
            .block_on(async {
                RemoteClient::connect(Box::new(identity), Box::new(session_store), proxy_client)
                    .await
            })
            .map_err(RemoteAccessError::from)?;

        // Forward notifications to event handler if provided
        if let Some(handler) = &self.event_handler {
            spawn_remote_notification_forwarder(&self.runtime, notifications, Arc::clone(handler));
        }

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| RemoteAccessError::SessionError {
                message: "Failed to acquire client lock".to_string(),
            })?;
        *inner = Some(client);

        Ok(())
    }

    /// Pair with a new device using a rendezvous code.
    ///
    /// * `code` — Rendezvous code (e.g. "ABC-DEF-GHI").
    ///
    /// Returns the 6-char handshake fingerprint as a hex string for out-of-band
    /// verification. No fingerprint verification is performed (headless mode).
    pub fn pair_with_handshake(&self, code: String) -> Result<String, RemoteAccessError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| RemoteAccessError::SessionError {
                message: "Failed to acquire client lock".to_string(),
            })?;
        let client = inner.as_ref().ok_or(RemoteAccessError::ConnectionFailed {
            message: "Not connected — call connect() first".to_string(),
        })?;

        let fp = self
            .runtime
            .block_on(async { client.pair_with_handshake(code, false).await })
            .map_err(RemoteAccessError::from)?;

        Ok(fp.to_hex())
    }

    /// Pair with a new device using a PSK token.
    ///
    /// * `psk_token` — PSK token string (`<64-hex-psk>_<64-hex-fingerprint>`).
    pub fn pair_with_psk(&self, psk_token: String) -> Result<(), RemoteAccessError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| RemoteAccessError::SessionError {
                message: "Failed to acquire client lock".to_string(),
            })?;
        let client = inner.as_ref().ok_or(RemoteAccessError::ConnectionFailed {
            message: "Not connected — call connect() first".to_string(),
        })?;

        let parsed =
            PskToken::parse(&psk_token).map_err(|e| RemoteAccessError::InvalidArgument {
                message: format!("Invalid PSK token: {e}"),
            })?;
        let (psk, fingerprint) = parsed.into_parts();

        self.runtime
            .block_on(async { client.pair_with_psk(psk, fingerprint).await })
            .map_err(RemoteAccessError::from)?;

        Ok(())
    }

    /// Reconnect to a previously paired device using a cached connection.
    ///
    /// * `fingerprint_hex` — Hex-encoded identity fingerprint of the remote peer.
    pub fn load_existing_connection(
        &self,
        fingerprint_hex: String,
    ) -> Result<(), RemoteAccessError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| RemoteAccessError::SessionError {
                message: "Failed to acquire client lock".to_string(),
            })?;
        let client = inner.as_ref().ok_or(RemoteAccessError::ConnectionFailed {
            message: "Not connected — call connect() first".to_string(),
        })?;

        let fingerprint = IdentityFingerprint::from_hex(&fingerprint_hex).map_err(|e| {
            RemoteAccessError::InvalidArgument {
                message: format!("Invalid fingerprint: {e}"),
            }
        })?;

        self.runtime
            .block_on(async { client.load_cached_connection(fingerprint).await })
            .map_err(RemoteAccessError::from)?;

        Ok(())
    }

    /// Request a credential for a domain.
    ///
    /// * `domain` — The domain to look up (e.g. "example.com").
    pub fn request_credential(
        &self,
        domain: String,
    ) -> Result<FfiCredentialData, RemoteAccessError> {
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

        Ok(FfiCredentialData::from(cred))
    }

    /// List all cached connections.
    pub fn list_connections(&self) -> Vec<FfiConnectionInfo> {
        let inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return Vec::new(),
        };

        match inner.as_ref() {
            Some(client) => self
                .runtime
                .block_on(async { client.list_connections().await })
                .unwrap_or_default()
                .into_iter()
                .map(|c| FfiConnectionInfo {
                    fingerprint: c.fingerprint.to_hex(),
                    name: c.name,
                    cached_at: c.cached_at,
                    last_connected_at: c.last_connected_at,
                })
                .collect(),
            None => Vec::new(),
        }
    }

    /// Close the connection and release resources.
    pub fn close(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            *inner = None;
        }
    }
}

impl Drop for RemoteAccessClient {
    fn drop(&mut self) {
        self.close();
    }
}

/// Spawn a task that forwards `RemoteClientNotification`s to an `EventHandler`.
fn spawn_remote_notification_forwarder(
    runtime: &tokio::runtime::Runtime,
    mut rx: mpsc::Receiver<RemoteClientNotification>,
    handler: Arc<dyn EventHandler>,
) {
    runtime.spawn(async move {
        while let Some(notif) = rx.recv().await {
            let event = match notif {
                RemoteClientNotification::Connecting => FfiEvent::Connecting,
                RemoteClientNotification::Connected { fingerprint } => FfiEvent::Connected {
                    fingerprint: fingerprint.to_hex(),
                },
                RemoteClientNotification::ReconnectingToSession { fingerprint } => {
                    FfiEvent::ReconnectingToSession {
                        fingerprint: fingerprint.to_hex(),
                    }
                }
                RemoteClientNotification::RendezvousResolving { code } => {
                    FfiEvent::RendezvousResolving { code }
                }
                RemoteClientNotification::RendezvousResolved { fingerprint } => {
                    FfiEvent::RendezvousResolved {
                        fingerprint: fingerprint.to_hex(),
                    }
                }
                RemoteClientNotification::PskMode { fingerprint } => FfiEvent::PskMode {
                    fingerprint: fingerprint.to_hex(),
                },
                RemoteClientNotification::HandshakeStart => FfiEvent::HandshakeStart,
                RemoteClientNotification::HandshakeProgress { message } => {
                    FfiEvent::HandshakeProgress { message }
                }
                RemoteClientNotification::HandshakeComplete => FfiEvent::HandshakeComplete,
                RemoteClientNotification::HandshakeFingerprint { fingerprint } => {
                    FfiEvent::HandshakeFingerprint {
                        fingerprint,
                        identity: None,
                    }
                }
                RemoteClientNotification::FingerprintVerified => FfiEvent::FingerprintVerified,
                RemoteClientNotification::FingerprintRejected { reason } => {
                    FfiEvent::FingerprintRejected { reason }
                }
                RemoteClientNotification::Ready { .. } => FfiEvent::Ready,
                RemoteClientNotification::CredentialRequestSent { query } => {
                    FfiEvent::CredentialRequestSent {
                        domain: format!("{query:?}"),
                    }
                }
                RemoteClientNotification::CredentialReceived { .. } => FfiEvent::CredentialReceived,
                RemoteClientNotification::Error { message, context } => {
                    FfiEvent::Error { message, context }
                }
                RemoteClientNotification::Disconnected { reason } => {
                    FfiEvent::Disconnected { reason }
                }
            };
            handler.on_event(event);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_new_succeeds() {
        let client = RemoteAccessClient::new(
            "ws://localhost:9999".to_string(),
            "test-unit".to_string(),
            None,
        );
        assert!(client.is_ok());
    }

    #[test]
    fn client_request_credential_fails_before_connect() {
        let client = RemoteAccessClient::new(
            "ws://localhost:9999".to_string(),
            "test-unit".to_string(),
            None,
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
            "test-unit".to_string(),
            None,
        )
        .expect("should create client");
        client.close();
    }

    #[test]
    fn pair_methods_fail_before_connect() {
        let client = RemoteAccessClient::new(
            "ws://localhost:9999".to_string(),
            "test-unit".to_string(),
            None,
        )
        .expect("should create client");

        assert!(
            client
                .pair_with_handshake("ABC-DEF-GHI".to_string())
                .is_err()
        );
        assert!(client.pair_with_psk("x".repeat(129)).is_err());
        assert!(client.load_existing_connection("a".repeat(64)).is_err());
    }
}
