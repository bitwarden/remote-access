use std::sync::{Arc, Mutex};

use ap_client::{
    CredentialQuery, DefaultProxyClient, IdentityFingerprint, PskToken,
    RemoteClientHandle, RemoteClientNotification,
};
use tokio::sync::mpsc;

use crate::EventHandler;
use crate::adapters::{CallbackConnectionStore, CallbackIdentityProvider};
use crate::callbacks::{ConnectionStorage, IdentityStorage};
use crate::error::ClientError;
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
pub struct RemoteClient {
    inner: Mutex<Option<ap_client::RemoteClient>>,
    event_handler: Option<Arc<dyn EventHandler>>,
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
    #[uniffi::constructor]
    pub fn new(
        proxy_url: String,
        identity_storage: Box<dyn IdentityStorage>,
        connection_storage: Box<dyn ConnectionStorage>,
        event_handler: Option<Box<dyn EventHandler>>,
    ) -> Result<Self, ClientError> {
        crate::init_tracing();

        Ok(Self {
            inner: Mutex::new(None),
            event_handler: event_handler.map(Arc::from),
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
        if let Ok(mut inner) = self.inner.lock() {
            *inner = None;
        }

        let identity = CallbackIdentityProvider::from_storage(self.identity_storage.as_ref())
            .map_err(ClientError::from)?;

        let session_store = CallbackConnectionStore::new(Arc::clone(&self.connection_storage));

        let proxy_client = Box::new(DefaultProxyClient::from_url(self.proxy_url.clone()));

        let RemoteClientHandle {
            client,
            notifications,
            requests: _requests,
        } = ap_client::RemoteClient::connect(Box::new(identity), Box::new(session_store), proxy_client)
            .await
            .map_err(ClientError::from)?;

        // Forward notifications to event handler if provided
        if let Some(handler) = &self.event_handler {
            spawn_remote_notification_forwarder(notifications, Arc::clone(handler));
        }

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ClientError::SessionError {
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
    pub async fn pair_with_handshake(&self, code: String) -> Result<String, ClientError> {
        let client = self.get_client()?;

        let fp = client
            .pair_with_handshake(code, false)
            .await
            .map_err(ClientError::from)?;

        Ok(fp.to_hex())
    }

    /// Pair with a new device using a PSK token.
    ///
    /// * `psk_token` — PSK token string (`<64-hex-psk>_<64-hex-fingerprint>`).
    pub async fn pair_with_psk(&self, psk_token: String) -> Result<(), ClientError> {
        let client = self.get_client()?;

        let parsed =
            PskToken::parse(&psk_token).map_err(|e| ClientError::InvalidArgument {
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
        let client = self.get_client()?;

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

    /// Request a credential for a domain.
    ///
    /// * `domain` — The domain to look up (e.g. "example.com").
    pub async fn request_credential(
        &self,
        domain: String,
    ) -> Result<FfiCredentialData, ClientError> {
        let client = self
            .get_client()
            .map_err(|_| ClientError::CredentialRequestFailed {
                message: "Not connected — call connect() first".to_string(),
            })?;

        let query = CredentialQuery::Domain(domain);
        let cred = client
            .request_credential(&query, None)
            .await
            .map_err(ClientError::from)?;

        Ok(FfiCredentialData::from(cred))
    }

    /// List all cached connections.
    pub async fn list_connections(&self) -> Vec<FfiConnectionInfo> {
        let client = match self.get_client() {
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

    /// Close the connection and release resources.
    pub fn close(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            *inner = None;
        }
    }
}

impl RemoteClient {
    fn get_client(&self) -> Result<ap_client::RemoteClient, ClientError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ClientError::SessionError {
                message: "Failed to acquire client lock".to_string(),
            })?;
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
        self.close();
    }
}

/// Spawn a task that forwards `RemoteClientNotification`s to an `EventHandler`.
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
                    let domain = match &query {
                        CredentialQuery::Domain(d) => d.clone(),
                        CredentialQuery::Id(id) => id.clone(),
                        CredentialQuery::Search(s) => s.clone(),
                    };
                    FfiEvent::CredentialRequestSent { domain }
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
        );
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn client_request_credential_fails_before_connect() {
        let client = make_client();
        let result = client.request_credential("example.com".to_string()).await;
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
