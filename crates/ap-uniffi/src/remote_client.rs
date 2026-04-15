use std::sync::Arc;
use std::time::Duration;

use ap_client::{
    DefaultProxyClient, IdentityFingerprint, PskToken, RemoteClientFingerprintReply,
    RemoteClientHandle, RemoteClientNotification, RemoteClientRequest,
};
use tokio::sync::{Mutex, mpsc};

use crate::EventHandler;
use crate::adapters::{
    CallbackConnectionStore, CallbackIdentityProvider, resolve_identity_fingerprint,
};
use crate::callbacks::{ConnectionStorage, FingerprintVerifier, IdentityStorage};
use crate::error::ClientError;
use crate::types::{FfiConnectionInfo, FfiCredentialData, FfiCredentialQuery, FfiEvent};

/// A remote-access client for requesting credentials from a trusted peer.
///
/// Thin wrapper around `ap_client::RemoteClient` exposing individual pairing
/// methods — connection mode orchestration (PSK vs rendezvous vs cached)
/// belongs in the consumer, not here.
///
/// Implements `Drop` to ensure the underlying connection is closed if the
/// caller forgets to call `close()`.
#[derive(uniffi::Object)]
pub struct RemoteClient {
    inner: Mutex<Option<ap_client::RemoteClient>>,
    event_handler: Option<Arc<dyn EventHandler>>,
    fingerprint_verifier: Option<Arc<dyn FingerprintVerifier>>,
    identity_storage: Arc<dyn IdentityStorage>,
    connection_storage: Arc<dyn ConnectionStorage>,
    proxy_url: String,
}

#[uniffi::export(async_runtime = "tokio")]
impl RemoteClient {
    /// Create a new RemoteClient.
    ///
    /// * `proxy_url` — WebSocket URL of the proxy server (e.g. "ws://localhost:8080").
    /// * `identity_storage` — Callback for persistent identity keypair storage.
    /// * `connection_storage` — Callback for persistent connection cache storage.
    /// * `event_handler` — Optional callback for receiving status notifications.
    /// * `fingerprint_verifier` — Optional callback for verifying handshake fingerprints.
    ///   Most consumers should pass `None` — fingerprint verification is only relevant
    ///   for interactive UIs using rendezvous pairing that want MITM protection.
    ///   PSK connections and headless/agent scenarios skip verification.
    #[uniffi::constructor]
    pub fn new(
        proxy_url: String,
        identity_storage: Box<dyn IdentityStorage>,
        connection_storage: Box<dyn ConnectionStorage>,
        event_handler: Option<Box<dyn EventHandler>>,
        fingerprint_verifier: Option<Box<dyn FingerprintVerifier>>,
    ) -> Result<Self, ClientError> {
        crate::init_tracing();

        Ok(Self {
            inner: Mutex::new(None),
            event_handler: event_handler.map(Arc::from),
            fingerprint_verifier: fingerprint_verifier.map(Arc::from),
            identity_storage: Arc::from(identity_storage),
            connection_storage: Arc::from(connection_storage),
            proxy_url,
        })
    }

    /// Connect to the proxy server and authenticate.
    ///
    /// After this, call one of the pairing methods to establish a secure channel:
    /// `pair_with_handshake()`, `pair_with_psk()`, or `load_existing_connection()`.
    pub async fn connect(&self) -> Result<(), ClientError> {
        *self.inner.lock().await = None;

        let identity = CallbackIdentityProvider::from_storage(self.identity_storage.as_ref())
            .map_err(ClientError::from)?;

        let session_store = CallbackConnectionStore::new(Arc::clone(&self.connection_storage));

        let proxy_client = Box::new(DefaultProxyClient::from_url(self.proxy_url.clone()));

        let RemoteClientHandle {
            client,
            notifications,
            requests,
        } = ap_client::RemoteClient::connect(
            Box::new(identity),
            Box::new(session_store),
            proxy_client,
        )
        .await
        .map_err(ClientError::from)?;

        // Forward notifications to event handler if provided
        if let Some(handler) = &self.event_handler {
            spawn_remote_notification_forwarder(notifications, Arc::clone(handler));
        }

        // Spawn request handler for fingerprint verification
        spawn_remote_request_handler(requests, self.fingerprint_verifier.as_ref().map(Arc::clone));

        *self.inner.lock().await = Some(client);

        Ok(())
    }

    /// Pair with a new device using a rendezvous code.
    ///
    /// * `code` — Rendezvous code (e.g. "ABC-DEF-GHI").
    ///
    /// Returns the 6-char handshake fingerprint as a hex string for out-of-band
    /// verification. No fingerprint verification is performed (headless mode).
    pub async fn pair_with_handshake(&self, code: String) -> Result<String, ClientError> {
        let client = self.get_client().await?;

        let verify = self.fingerprint_verifier.is_some();
        let fp = client
            .pair_with_handshake(code, verify)
            .await
            .map_err(ClientError::from)?;

        Ok(fp.to_hex())
    }

    /// Pair with a new device using a PSK token.
    ///
    /// * `psk_token` — PSK token string (`<64-hex-psk>_<64-hex-fingerprint>`).
    pub async fn pair_with_psk(&self, psk_token: String) -> Result<(), ClientError> {
        let client = self.get_client().await?;

        let parsed = PskToken::parse(&psk_token).map_err(|e| ClientError::InvalidArgument {
            message: format!("Invalid PSK token: {e}"),
        })?;
        let (psk, fingerprint) = parsed.into_parts();

        client
            .pair_with_psk(psk, fingerprint)
            .await
            .map_err(ClientError::from)?;

        Ok(())
    }

    /// Reconnect to a previously paired device using a cached connection.
    ///
    /// * `fingerprint_hex` — Hex-encoded identity fingerprint of the remote peer.
    pub async fn load_existing_connection(
        &self,
        fingerprint_hex: String,
    ) -> Result<(), ClientError> {
        let client = self.get_client().await?;

        let fingerprint = IdentityFingerprint::from_hex(&fingerprint_hex).map_err(|e| {
            ClientError::InvalidArgument {
                message: format!("Invalid fingerprint: {e}"),
            }
        })?;

        client
            .load_cached_connection(fingerprint)
            .await
            .map_err(ClientError::from)?;

        Ok(())
    }

    /// Request a credential.
    ///
    /// * `query` — The credential query (domain, ID, or search).
    /// * `timeout_secs` — Optional timeout in seconds (default: 120s).
    pub async fn request_credential(
        &self,
        query: FfiCredentialQuery,
        timeout_secs: Option<u64>,
    ) -> Result<FfiCredentialData, ClientError> {
        let client = self
            .get_client()
            .await
            .map_err(|_| ClientError::CredentialRequestFailed {
                message: "Not connected — call connect() first".to_string(),
            })?;

        let query = ap_client::CredentialQuery::from(query);
        let timeout = timeout_secs.map(Duration::from_secs);
        let cred = client
            .request_credential(&query, timeout)
            .await
            .map_err(ClientError::from)?;

        Ok(FfiCredentialData::from(cred))
    }

    /// List all cached connections.
    pub async fn list_connections(&self) -> Vec<FfiConnectionInfo> {
        let client = match self.get_client().await {
            Ok(client) => client,
            Err(_) => return Vec::new(),
        };

        client
            .list_connections()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(FfiConnectionInfo::from)
            .collect()
    }

    /// Returns this device's stable identity fingerprint (64-char hex string).
    ///
    /// This is the SHA256 hash of the device's public key — used for addressing,
    /// session lookup, and PSK token construction. Not to be confused with the
    /// 6-character handshake fingerprint used for MITM verification.
    pub fn get_identity_fingerprint(&self) -> Result<String, ClientError> {
        resolve_identity_fingerprint(self.identity_storage.as_ref()).map_err(ClientError::from)
    }

    /// Close the connection and release resources.
    pub async fn close(&self) {
        *self.inner.lock().await = None;
    }
}

impl RemoteClient {
    async fn get_client(&self) -> Result<ap_client::RemoteClient, ClientError> {
        let inner = self.inner.lock().await;
        inner
            .as_ref()
            .cloned()
            .ok_or(ClientError::ConnectionFailed {
                message: "Not connected — call connect() first".to_string(),
            })
    }
}

impl Drop for RemoteClient {
    fn drop(&mut self) {
        // Use try_lock to avoid blocking in Drop — if the lock is held,
        // the inner client will be dropped when the Mutex itself is dropped.
        if let Ok(mut inner) = self.inner.try_lock() {
            *inner = None;
        }
    }
}

/// Spawn a task that forwards `RemoteClientNotification`s to an `EventHandler`.
///
/// The task exits naturally when the notification channel closes, which happens
/// when the inner `ap_client::RemoteClient` is dropped via `close()`. No
/// `JoinHandle` is tracked because cleanup is driven by channel closure.
fn spawn_remote_notification_forwarder(
    mut rx: mpsc::Receiver<RemoteClientNotification>,
    handler: Arc<dyn EventHandler>,
) {
    crate::runtime().spawn(async move {
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
                        query: FfiCredentialQuery::from(&query),
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

/// Spawn a task that handles `RemoteClientRequest`s (fingerprint verification).
///
/// If no verifier is provided, fingerprints are auto-accepted.
fn spawn_remote_request_handler(
    mut requests: mpsc::Receiver<RemoteClientRequest>,
    verifier: Option<Arc<dyn FingerprintVerifier>>,
) {
    crate::runtime().spawn(async move {
        while let Some(request) = requests.recv().await {
            match request {
                RemoteClientRequest::VerifyFingerprint { fingerprint, reply } => {
                    let approved = if let Some(verifier) = &verifier {
                        let verifier = Arc::clone(verifier);
                        let fp = fingerprint.clone();

                        match tokio::task::spawn_blocking(move || {
                            verifier.verify_fingerprint(fp, None)
                        })
                        .await
                        {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!("verify_fingerprint callback panicked: {e}");
                                false
                            }
                        }
                    } else {
                        // No verifier provided — auto-accept
                        true
                    };
                    let _ = reply.send(RemoteClientFingerprintReply { approved });
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callbacks::FfiStoredConnection;
    use std::sync::Mutex as StdMutex;

    struct MemoryIdentityStorage {
        data: StdMutex<Option<Vec<u8>>>,
    }

    impl MemoryIdentityStorage {
        fn new() -> Self {
            Self {
                data: StdMutex::new(None),
            }
        }
    }

    impl IdentityStorage for MemoryIdentityStorage {
        fn load_identity(&self) -> Option<Vec<u8>> {
            self.data.lock().expect("identity storage lock").clone()
        }

        fn save_identity(&self, identity_bytes: Vec<u8>) -> Result<(), ClientError> {
            *self.data.lock().expect("identity storage lock") = Some(identity_bytes);
            Ok(())
        }
    }

    struct MemoryConnectionStorage;

    impl ConnectionStorage for MemoryConnectionStorage {
        fn get(&self, _fingerprint_hex: String) -> Option<FfiStoredConnection> {
            None
        }
        fn save(&self, _connection: FfiStoredConnection) -> Result<(), ClientError> {
            Ok(())
        }
        fn update(
            &self,
            _fingerprint_hex: String,
            _last_connected_at: u64,
        ) -> Result<(), ClientError> {
            Ok(())
        }
        fn list(&self) -> Vec<FfiStoredConnection> {
            Vec::new()
        }
    }

    fn make_client() -> RemoteClient {
        RemoteClient::new(
            "ws://localhost:9999".to_string(),
            Box::new(MemoryIdentityStorage::new()),
            Box::new(MemoryConnectionStorage),
            None,
            None,
        )
        .expect("should create client")
    }

    #[test]
    fn client_new_succeeds() {
        let client = RemoteClient::new(
            "ws://localhost:9999".to_string(),
            Box::new(MemoryIdentityStorage::new()),
            Box::new(MemoryConnectionStorage),
            None,
            None,
        );
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn client_request_credential_fails_before_connect() {
        let client = make_client();
        let result = client
            .request_credential(
                FfiCredentialQuery::Domain {
                    value: "example.com".to_string(),
                },
                None,
            )
            .await;
        assert!(matches!(
            result,
            Err(ClientError::CredentialRequestFailed { .. })
        ));
    }

    #[test]
    fn client_close_is_safe_before_connect() {
        let client = make_client();
        client.close();
    }

    #[tokio::test]
    async fn pair_methods_fail_before_connect() {
        let client = make_client();

        assert!(
            client
                .pair_with_handshake("ABC-DEF-GHI".to_string())
                .await
                .is_err()
        );
        assert!(client.pair_with_psk("x".repeat(129)).await.is_err());
        assert!(
            client
                .load_existing_connection("a".repeat(64))
                .await
                .is_err()
        );
    }
}
