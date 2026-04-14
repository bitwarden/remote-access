use std::sync::Arc;

use crate::adapters::{
    CallbackAuditLog, CallbackConnectionStore, CallbackIdentityProvider, CallbackPskStore,
};
use crate::callbacks::{
    AuditLogger, ConnectionStorage, CredentialProvider, EventHandler, FingerprintVerifier,
    IdentityStorage, PskStorage,
};
use crate::error::ClientError;
use crate::types::{FfiCredentialQuery, FfiEvent};
use ap_client::{
    CredentialData, CredentialRequestReply, DefaultProxyClient, FingerprintVerificationReply,
    UserClientHandle, UserClientNotification, UserClientRequest,
};
use tokio::sync::{Mutex, mpsc};

/// A user-client (trusted device) that listens for incoming credential requests.
///
/// Wraps `ap_client::UserClient` behind an async FFI-safe API.
/// Credential requests are dispatched to `CredentialProvider`; fingerprint
/// verifications to the optional `FingerprintVerifier`.
#[derive(uniffi::Object)]
pub struct UserClient {
    inner: Mutex<Option<ap_client::UserClient>>,
    handler: Arc<dyn CredentialProvider>,
    fingerprint_verifier: Option<Arc<dyn FingerprintVerifier>>,
    event_handler: Option<Arc<dyn EventHandler>>,
    audit_logger: Option<Arc<dyn AuditLogger>>,
    psk_storage: Option<Arc<dyn PskStorage>>,
    identity_storage: Arc<dyn IdentityStorage>,
    connection_storage: Arc<dyn ConnectionStorage>,
    proxy_url: String,
}

#[uniffi::export(async_runtime = "tokio")]
impl UserClient {
    /// Create a new UserClient.
    ///
    /// * `proxy_url` — WebSocket URL of the proxy server.
    /// * `identity_storage` — Callback for persistent identity keypair storage.
    /// * `connection_storage` — Callback for persistent connection cache storage.
    /// * `handler` — Callback for credential requests.
    /// * `fingerprint_verifier` — Optional callback for verifying handshake fingerprints
    ///   on rendezvous connections. If `None`, rendezvous fingerprints are auto-accepted.
    /// * `event_handler` — Optional callback for status notifications.
    /// * `audit_logger` — Optional callback for security-relevant audit events.
    /// * `psk_storage` — Optional callback for persistent reusable PSK storage.
    ///   Required when using `get_psk_token(reusable: true)`.
    #[uniffi::constructor]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proxy_url: String,
        identity_storage: Box<dyn IdentityStorage>,
        connection_storage: Box<dyn ConnectionStorage>,
        handler: Box<dyn CredentialProvider>,
        fingerprint_verifier: Option<Box<dyn FingerprintVerifier>>,
        event_handler: Option<Box<dyn EventHandler>>,
        audit_logger: Option<Box<dyn AuditLogger>>,
        psk_storage: Option<Box<dyn PskStorage>>,
    ) -> Result<Self, ClientError> {
        crate::init_tracing();

        Ok(Self {
            inner: Mutex::new(None),
            handler: Arc::from(handler),
            fingerprint_verifier: fingerprint_verifier.map(Arc::from),
            event_handler: event_handler.map(Arc::from),
            audit_logger: audit_logger.map(Arc::from),
            psk_storage: psk_storage.map(Arc::from),
            identity_storage: Arc::from(identity_storage),
            connection_storage: Arc::from(connection_storage),
            proxy_url,
        })
    }

    /// Connect to the proxy server and start listening for incoming connections.
    ///
    /// Spawns a background event loop that dispatches credential requests and
    /// fingerprint verifications to the `CredentialProvider` callback.
    pub async fn connect(&self) -> Result<(), ClientError> {
        // Clear any previous connection
        *self.inner.lock().await = None;

        let identity = CallbackIdentityProvider::from_storage(self.identity_storage.as_ref())
            .map_err(ClientError::from)?;

        let session_store = CallbackConnectionStore::new(Arc::clone(&self.connection_storage));

        let proxy_client = Box::new(DefaultProxyClient::from_url(self.proxy_url.clone()));

        let audit_log: Option<Box<dyn ap_client::AuditLog>> =
            self.audit_logger.as_ref().map(|logger| {
                Box::new(CallbackAuditLog::new(Arc::clone(logger))) as Box<dyn ap_client::AuditLog>
            });

        let psk_store: Option<Box<dyn ap_client::PskStore>> =
            self.psk_storage.as_ref().map(|storage| {
                Box::new(CallbackPskStore::new(Arc::clone(storage))) as Box<dyn ap_client::PskStore>
            });

        let UserClientHandle {
            client,
            notifications,
            requests,
        } = ap_client::UserClient::connect(
            Box::new(identity),
            Box::new(session_store),
            proxy_client,
            audit_log,
            psk_store,
        )
        .await
        .map_err(ClientError::from)?;

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

        *self.inner.lock().await = Some(client);

        Ok(())
    }

    /// Generate a PSK token for pairing.
    ///
    /// * `name` — Optional human-readable name for the connection (e.g. "Work Laptop").
    /// * `reusable` — If true, the token can be used multiple times.
    ///
    /// Returns the PSK token string (`<64-hex-psk>_<64-hex-fingerprint>`).
    pub async fn get_psk_token(
        &self,
        name: Option<String>,
        reusable: bool,
    ) -> Result<String, ClientError> {
        let client = self.get_client().await?;

        client
            .get_psk_token(name, reusable)
            .await
            .map_err(ClientError::from)
    }

    /// Generate a rendezvous code for pairing.
    ///
    /// * `name` — Optional human-readable name for the connection (e.g. "Work Laptop").
    ///
    /// Returns the rendezvous code string (e.g. "ABC-DEF-GHI").
    pub async fn get_rendezvous_token(&self, name: Option<String>) -> Result<String, ClientError> {
        let client = self.get_client().await?;

        let code = client
            .get_rendezvous_token(name)
            .await
            .map_err(ClientError::from)?;

        Ok(code.to_string())
    }

    /// Returns this device's stable identity fingerprint (64-char hex string).
    ///
    /// This is the SHA256 hash of the device's public key — used for addressing,
    /// session lookup, and PSK token construction. Not to be confused with the
    /// 6-character handshake fingerprint used for MITM verification.
    pub fn get_identity_fingerprint(&self) -> Result<String, ClientError> {
        let identity = CallbackIdentityProvider::from_storage(self.identity_storage.as_ref())
            .map_err(ClientError::from)?;
        Ok(identity.fingerprint_hex())
    }

    /// Close the connection and release resources.
    pub async fn close(&self) {
        *self.inner.lock().await = None;
    }
}

impl UserClient {
    async fn get_client(&self) -> Result<ap_client::UserClient, ClientError> {
        let inner = self.inner.lock().await;
        inner
            .as_ref()
            .cloned()
            .ok_or(ClientError::ConnectionFailed {
                message: "Not connected — call connect() first".to_string(),
            })
    }
}

impl Drop for UserClient {
    fn drop(&mut self) {
        // Use try_lock to avoid blocking in Drop — if the lock is held,
        // the inner client will be dropped when the Mutex itself is dropped.
        if let Ok(mut inner) = self.inner.try_lock() {
            *inner = None;
        }
    }
}

/// Spawn a task that drains `UserClientRequest`s and dispatches to the callbacks.
///
/// Exits when the request channel closes (inner client dropped via `close()`).
/// No `JoinHandle` tracked — cleanup is driven by channel closure.
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
                    let ffi_query = FfiCredentialQuery::from(&query);
                    let remote_fp = identity.to_hex();
                    let handler = Arc::clone(&handler);

                    let result = tokio::task::spawn_blocking(move || {
                        handler.handle_credential_request(ffi_query, remote_fp)
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
///
/// Exits when the notification channel closes (inner client dropped via `close()`).
/// No `JoinHandle` tracked — cleanup is driven by channel closure.
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
