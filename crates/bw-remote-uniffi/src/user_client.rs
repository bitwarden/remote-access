use std::sync::{Arc, Mutex};

use ap_client::{
    CredentialData, CredentialRequestReply, DefaultProxyClient, FingerprintVerificationReply,
    UserClient, UserClientHandle, UserClientNotification, UserClientRequest,
};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::callbacks::{CredentialProvider, EventHandler};
use crate::error::RemoteAccessError;
use crate::storage::{FileIdentityStorage, FileSessionCache};
use crate::types::{FfiCredentialData, FfiEvent};

/// A user-client (trusted device) that listens for incoming credential requests.
///
/// Wraps `ap_client::UserClient` behind a synchronous FFI-safe API.
/// Credential requests and fingerprint verifications are dispatched to the
/// `CredentialProvider` callback supplied at construction.
#[derive(uniffi::Object)]
pub struct UserAccessClient {
    runtime: tokio::runtime::Runtime,
    inner: Mutex<Option<UserClient>>,
    handler: Arc<dyn CredentialProvider>,
    event_handler: Option<Arc<dyn EventHandler>>,
    proxy_url: String,
    identity_name: String,
}

#[uniffi::export]
impl UserAccessClient {
    /// Create a new UserAccessClient.
    ///
    /// * `proxy_url` — WebSocket URL of the proxy server.
    /// * `identity_name` — Name for the identity keypair file.
    /// * `handler` — Callback for credential requests and fingerprint verification.
    /// * `event_handler` — Optional callback for status notifications.
    #[uniffi::constructor]
    pub fn new(
        proxy_url: String,
        identity_name: String,
        handler: Box<dyn CredentialProvider>,
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
            handler: Arc::from(handler),
            event_handler: event_handler.map(Arc::from),
            proxy_url,
            identity_name,
        })
    }

    /// Connect to the proxy server and start listening for incoming connections.
    ///
    /// Spawns a background event loop that dispatches credential requests and
    /// fingerprint verifications to the `CredentialProvider` callback.
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

        let UserClientHandle {
            client,
            notifications,
            requests,
        } = self
            .runtime
            .block_on(async {
                UserClient::connect(
                    Box::new(identity),
                    Box::new(session_store),
                    proxy_client,
                    None, // audit_log
                    None, // psk_store
                )
                .await
            })
            .map_err(RemoteAccessError::from)?;

        // Spawn request handler
        spawn_request_handler(&self.runtime, requests, Arc::clone(&self.handler));

        // Forward notifications to event handler if provided
        if let Some(handler) = &self.event_handler {
            spawn_user_notification_forwarder(&self.runtime, notifications, Arc::clone(handler));
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
    pub fn get_psk_token(&self, reusable: bool) -> Result<String, RemoteAccessError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| RemoteAccessError::SessionError {
                message: "Failed to acquire client lock".to_string(),
            })?;
        let client = inner.as_ref().ok_or(RemoteAccessError::ConnectionFailed {
            message: "Not connected — call connect() first".to_string(),
        })?;

        self.runtime
            .block_on(async { client.get_psk_token(None, reusable).await })
            .map_err(RemoteAccessError::from)
    }

    /// Generate a rendezvous code for pairing.
    ///
    /// Returns the rendezvous code string (e.g. "ABC-DEF-GHI").
    pub fn get_rendezvous_token(&self) -> Result<String, RemoteAccessError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| RemoteAccessError::SessionError {
                message: "Failed to acquire client lock".to_string(),
            })?;
        let client = inner.as_ref().ok_or(RemoteAccessError::ConnectionFailed {
            message: "Not connected — call connect() first".to_string(),
        })?;

        let code = self
            .runtime
            .block_on(async { client.get_rendezvous_token(None).await })
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

impl Drop for UserAccessClient {
    fn drop(&mut self) {
        self.close();
    }
}

/// Spawn a task that drains `UserClientRequest`s and dispatches to the callback.
fn spawn_request_handler(
    runtime: &tokio::runtime::Runtime,
    mut requests: mpsc::Receiver<UserClientRequest>,
    handler: Arc<dyn CredentialProvider>,
) {
    runtime.spawn(async move {
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
                            credential: Some(ffi_credential_to_internal(ffi_cred)),
                            credential_id: None,
                        },
                        _ => CredentialRequestReply {
                            approved: false,
                            credential: None,
                            credential_id: None,
                        },
                    };
                    let _ = reply.send(credential_reply);
                }
                UserClientRequest::VerifyFingerprint {
                    fingerprint,
                    identity,
                    reply,
                } => {
                    let remote_fp = identity.to_hex();
                    let handler = Arc::clone(&handler);
                    let fp = fingerprint.clone();

                    let result = tokio::task::spawn_blocking(move || {
                        handler.verify_fingerprint(fp, remote_fp)
                    })
                    .await;

                    let approved = result.unwrap_or(false);
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
    runtime: &tokio::runtime::Runtime,
    mut rx: mpsc::Receiver<UserClientNotification>,
    handler: Arc<dyn EventHandler>,
) {
    runtime.spawn(async move {
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

/// Convert FFI credential data back to the internal `CredentialData` type.
fn ffi_credential_to_internal(ffi: FfiCredentialData) -> CredentialData {
    CredentialData {
        username: ffi.username,
        password: ffi.password.map(Zeroizing::new),
        totp: ffi.totp,
        uri: ffi.uri,
        notes: ffi.notes,
        credential_id: ffi.credential_id,
        domain: ffi.domain,
    }
}
