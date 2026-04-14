use std::sync::{Arc, Mutex};

use crate::adapters::{CallbackConnectionStore, CallbackIdentityProvider};
use crate::callbacks::{
    ConnectionStorage, CredentialProvider, EventHandler, FingerprintVerifier, IdentityStorage,
};
use crate::error::RemoteAccessError;
use crate::types::FfiEvent;
use ap_client::{
    CredentialData, CredentialRequestReply, DefaultProxyClient, FingerprintVerificationReply,
    UserClient, UserClientHandle, UserClientNotification, UserClientRequest,
};
use tokio::sync::mpsc;

/// A user-client (trusted device) that listens for incoming credential requests.
///
/// Wraps `ap_client::UserClient` behind an async FFI-safe API.
/// Credential requests are dispatched to `CredentialProvider`; fingerprint
/// verifications to the optional `FingerprintVerifier`.
#[derive(uniffi::Object)]
pub struct UserAccessClient {
    inner: Mutex<Option<UserClient>>,
    handler: Arc<dyn CredentialProvider>,
    fingerprint_verifier: Option<Arc<dyn FingerprintVerifier>>,
    event_handler: Option<Arc<dyn EventHandler>>,
    identity_storage: Arc<dyn IdentityStorage>,
    connection_storage: Arc<dyn ConnectionStorage>,
    proxy_url: String,
}

#[uniffi::export(async_runtime = "tokio")]
impl UserAccessClient {
    /// Create a new UserAccessClient.
    ///
    /// * `proxy_url` — WebSocket URL of the proxy server.
    /// * `identity_storage` — Callback for persistent identity keypair storage.
    /// * `connection_storage` — Callback for persistent connection cache storage.
    /// * `handler` — Callback for credential requests.
    /// * `fingerprint_verifier` — Optional callback for verifying handshake fingerprints
    ///   on rendezvous connections. If `None`, rendezvous fingerprints are auto-accepted.
    ///   TODO: Fingerprint verification only applies to rendezvous pairing — consider
    ///   moving this to `get_rendezvous_token()` or a dedicated method instead of
    ///   requiring it at construction time.
    /// * `event_handler` — Optional callback for status notifications.
    #[uniffi::constructor]
    pub fn new(
        proxy_url: String,
        identity_storage: Box<dyn IdentityStorage>,
        connection_storage: Box<dyn ConnectionStorage>,
        handler: Box<dyn CredentialProvider>,
        fingerprint_verifier: Option<Box<dyn FingerprintVerifier>>,
        event_handler: Option<Box<dyn EventHandler>>,
    ) -> Result<Self, RemoteAccessError> {
        crate::init_tracing();

        Ok(Self {
            inner: Mutex::new(None),
            handler: Arc::from(handler),
            fingerprint_verifier: fingerprint_verifier.map(Arc::from),
            event_handler: event_handler.map(Arc::from),
            identity_storage: Arc::from(identity_storage),
            connection_storage: Arc::from(connection_storage),
            proxy_url,
        })
    }

    /// Connect to the proxy server and start listening for incoming connections.
    ///
    /// Spawns a background event loop that dispatches credential requests and
    /// fingerprint verifications to the `CredentialProvider` callback.
    pub async fn connect(&self) -> Result<(), RemoteAccessError> {
        if let Ok(mut inner) = self.inner.lock() {
            *inner = None;
        }

        let identity = CallbackIdentityProvider::from_storage(self.identity_storage.as_ref())
            .map_err(RemoteAccessError::from)?;

        let session_store = CallbackConnectionStore::new(Arc::clone(&self.connection_storage));

        let proxy_client = Box::new(DefaultProxyClient::from_url(self.proxy_url.clone()));

        let UserClientHandle {
            client,
            notifications,
            requests,
        } = UserClient::connect(
            Box::new(identity),
            Box::new(session_store),
            proxy_client,
            None, // audit_log
            None, // psk_store
        )
        .await
        .map_err(RemoteAccessError::from)?;

        // Spawn request handler
        spawn_request_handler(
            requests,
            Arc::clone(&self.handler),
            self.fingerprint_verifier.as_ref().map(Arc::clone),
        );

        // Forward notifications to event handler if provided
        if let Some(handler) = &self.event_handler {
            spawn_user_notification_forwarder(notifications, Arc::clone(handler));
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

    /// Generate a PSK token for pairing.
    ///
    /// * `reusable` — If true, the token can be used multiple times.
    ///
    /// Returns the PSK token string (`<64-hex-psk>_<64-hex-fingerprint>`).
    pub async fn get_psk_token(&self, reusable: bool) -> Result<String, RemoteAccessError> {
        let client = self.get_client()?;

        client
            .get_psk_token(None, reusable)
            .await
            .map_err(RemoteAccessError::from)
    }

    /// Generate a rendezvous code for pairing.
    ///
    /// Returns the rendezvous code string (e.g. "ABC-DEF-GHI").
    pub async fn get_rendezvous_token(&self) -> Result<String, RemoteAccessError> {
        let client = self.get_client()?;

        let code = client
            .get_rendezvous_token(None)
            .await
            .map_err(RemoteAccessError::from)?;

        Ok(code.to_string())
    }

    /// Close the connection and release resources.
    pub fn close(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            *inner = None;
        }
    }
}

impl UserAccessClient {
    fn get_client(&self) -> Result<UserClient, RemoteAccessError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| RemoteAccessError::SessionError {
                message: "Failed to acquire client lock".to_string(),
            })?;
        inner
            .as_ref()
            .cloned()
            .ok_or(RemoteAccessError::ConnectionFailed {
                message: "Not connected — call connect() first".to_string(),
            })
    }
}

impl Drop for UserAccessClient {
    fn drop(&mut self) {
        self.close();
    }
}

/// Spawn a task that drains `UserClientRequest`s and dispatches to the callbacks.
fn spawn_request_handler(
    mut requests: mpsc::Receiver<UserClientRequest>,
    handler: Arc<dyn CredentialProvider>,
    verifier: Option<Arc<dyn FingerprintVerifier>>,
) {
    crate::runtime().spawn(async move {
        while let Some(request) = requests.recv().await {
            match request {
                UserClientRequest::CredentialRequest {
                    query,
                    identity,
                    reply,
                } => {
                    let (query_type, query_value) = match &query {
                        ap_client::CredentialQuery::Domain(d) => ("domain".to_string(), d.clone()),
                        ap_client::CredentialQuery::Id(id) => ("id".to_string(), id.clone()),
                        ap_client::CredentialQuery::Search(s) => ("search".to_string(), s.clone()),
                    };
                    let remote_fp = identity.to_hex();
                    let handler = Arc::clone(&handler);

                    let result = tokio::task::spawn_blocking(move || {
                        handler.handle_credential_request(query_type, query_value, remote_fp)
                    })
                    .await;

                    let credential_reply = match result {
                        Ok(Some(ffi_cred)) => CredentialRequestReply {
                            approved: true,
                            credential: Some(CredentialData::from(ffi_cred)),
                            credential_id: None,
                        },
                        Ok(None) => CredentialRequestReply {
                            approved: false,
                            credential: None,
                            credential_id: None,
                        },
                        Err(e) => {
                            tracing::warn!("CredentialProvider callback panicked: {e}");
                            CredentialRequestReply {
                                approved: false,
                                credential: None,
                                credential_id: None,
                            }
                        }
                    };
                    let _ = reply.send(credential_reply);
                }
                UserClientRequest::VerifyFingerprint {
                    fingerprint,
                    identity,
                    reply,
                } => {
                    let approved = if let Some(verifier) = &verifier {
                        let remote_fp = identity.to_hex();
                        let verifier = Arc::clone(verifier);
                        let fp = fingerprint.clone();

                        match tokio::task::spawn_blocking(move || {
                            verifier.verify_fingerprint(fp, remote_fp)
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
                    let _ = reply.send(FingerprintVerificationReply {
                        approved,
                        name: None,
                    });
                }
            }
        }
    });
}

/// Spawn a task that forwards `UserClientNotification`s to an `EventHandler`.
fn spawn_user_notification_forwarder(
    mut rx: mpsc::Receiver<UserClientNotification>,
    handler: Arc<dyn EventHandler>,
) {
    crate::runtime().spawn(async move {
        while let Some(notif) = rx.recv().await {
            let event = match notif {
                UserClientNotification::Listening {} => FfiEvent::Listening,
                UserClientNotification::HandshakeStart {} => FfiEvent::HandshakeStart,
                UserClientNotification::HandshakeProgress { message } => {
                    FfiEvent::HandshakeProgress { message }
                }
                UserClientNotification::HandshakeComplete {} => FfiEvent::HandshakeComplete,
                UserClientNotification::HandshakeFingerprint {
                    fingerprint,
                    identity,
                } => FfiEvent::HandshakeFingerprint {
                    fingerprint,
                    identity: Some(identity.to_hex()),
                },
                UserClientNotification::FingerprintVerified {} => FfiEvent::FingerprintVerified,
                UserClientNotification::FingerprintRejected { reason } => {
                    FfiEvent::FingerprintRejected { reason }
                }
                UserClientNotification::CredentialApproved {
                    domain,
                    credential_id,
                } => FfiEvent::CredentialApproved {
                    domain,
                    credential_id,
                },
                UserClientNotification::CredentialDenied {
                    domain,
                    credential_id,
                } => FfiEvent::CredentialDenied {
                    domain,
                    credential_id,
                },
                UserClientNotification::SessionRefreshed { fingerprint } => {
                    FfiEvent::SessionRefreshed {
                        fingerprint: fingerprint.to_hex(),
                    }
                }
                UserClientNotification::ClientDisconnected {} => FfiEvent::Disconnected {
                    reason: Some("Client disconnected".to_string()),
                },
                UserClientNotification::Reconnecting { attempt } => {
                    FfiEvent::Reconnecting { attempt }
                }
                UserClientNotification::Reconnected {} => FfiEvent::Reconnected,
                UserClientNotification::Error { message, context } => {
                    FfiEvent::Error { message, context }
                }
            };
            handler.on_event(event);
        }
    });
}
