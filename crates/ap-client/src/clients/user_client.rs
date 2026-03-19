use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
#[cfg(target_arch = "wasm32")]
use web_time::Instant;

use ap_noise::{Ciphersuite, MultiDeviceTransport, Psk, ResponderHandshake};
use ap_proxy_client::IncomingMessage;
use ap_proxy_protocol::{IdentityFingerprint, RendezvousCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tokio::sync::oneshot;

use crate::proxy::ProxyClient;
use crate::types::{CredentialData, PskId};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Base delay for reconnection backoff.
const RECONNECT_BASE_DELAY: Duration = Duration::from_secs(2);
/// Maximum delay between reconnection attempts (15 minutes).
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(15 * 60);
/// Maximum age for pending pairings before they are pruned.
const PENDING_PAIRING_MAX_AGE: Duration = Duration::from_secs(10 * 60);

/// The kind of pairing: rendezvous (null PSK) or PSK (real key).
pub(crate) enum PairingKind {
    /// Rendezvous pairing — uses a null PSK, requires fingerprint verification.
    ///
    /// The `reply` sender is `Some(...)` while waiting for the proxy's `RendezvousInfo`
    /// response, and becomes `None` once the rendezvous code has been delivered.
    Rendezvous {
        reply: Option<oneshot::Sender<Result<RendezvousCode, RemoteClientError>>>,
    },
    /// PSK pairing — uses a real pre-shared key, no fingerprint verification needed.
    Psk { psk: Psk, psk_id: PskId },
}

/// A pending pairing waiting for an incoming handshake.
pub(crate) struct PendingPairing {
    /// Friendly name to assign to the session once paired.
    connection_name: Option<String>,
    /// When this pairing was created (for pruning stale entries).
    created_at: Instant,
    /// The kind of pairing.
    kind: PairingKind,
}

use crate::{
    error::RemoteClientError,
    traits::{
        AuditConnectionType, AuditEvent, AuditLog, CredentialFieldSet, IdentityProvider,
        NoOpAuditLog, SessionStore,
    },
    types::{CredentialRequestPayload, CredentialResponsePayload, ProtocolMessage},
};

// =============================================================================
// Public types: Notifications (fire-and-forget) and Requests (with reply)
// =============================================================================

/// Fire-and-forget status updates emitted by the user client.
#[derive(Debug, Clone)]
pub enum UserClientNotification {
    /// Started listening for connections
    Listening {},
    /// Noise handshake started
    HandshakeStart {},
    /// Noise handshake progress
    HandshakeProgress {
        /// Progress message
        message: String,
    },
    /// Noise handshake complete
    HandshakeComplete {},
    /// Handshake fingerprint (informational, for PSK connections)
    HandshakeFingerprint {
        /// The 6-character hex fingerprint for visual verification
        fingerprint: String,
        /// The remote device's stable identity fingerprint
        identity: IdentityFingerprint,
    },
    /// Fingerprint was verified and connection accepted
    FingerprintVerified {},
    /// Fingerprint was rejected and connection discarded
    FingerprintRejected {
        /// Reason for rejection
        reason: String,
    },
    /// Credential was approved and sent
    CredentialApproved {
        /// Domain from the matched credential
        domain: Option<String>,
        /// Vault item ID
        credential_id: Option<String>,
    },
    /// Credential was denied
    CredentialDenied {
        /// Domain from the matched credential
        domain: Option<String>,
        /// Vault item ID
        credential_id: Option<String>,
    },
    /// A known/cached device reconnected — transport keys refreshed, no re-verification needed
    SessionRefreshed {
        /// The remote device's identity fingerprint
        fingerprint: IdentityFingerprint,
    },
    /// Client disconnected from proxy
    ClientDisconnected {},
    /// Attempting to reconnect to proxy
    Reconnecting {
        /// Current reconnection attempt number
        attempt: u32,
    },
    /// Successfully reconnected to proxy
    Reconnected {},
    /// An error occurred
    Error {
        /// Error message
        message: String,
        /// Context where error occurred
        context: Option<String>,
    },
}

/// Reply for fingerprint verification requests.
pub struct FingerprintVerificationReply {
    /// Whether user approved the fingerprint
    pub approved: bool,
    /// Optional friendly name to assign to the session
    pub name: Option<String>,
}

/// Reply for credential requests.
pub struct CredentialRequestReply {
    /// Whether approved
    pub approved: bool,
    /// The credential to send (if approved)
    pub credential: Option<CredentialData>,
    /// Vault item ID (for audit logging)
    pub credential_id: Option<String>,
}

/// Requests that require a caller response, carrying a oneshot reply channel.
pub enum UserClientRequest {
    /// Handshake fingerprint requires verification (rendezvous connections only).
    VerifyFingerprint {
        /// The 6-character hex fingerprint for visual verification
        fingerprint: String,
        /// The remote device's stable identity fingerprint
        identity: IdentityFingerprint,
        /// Channel to send the verification reply
        reply: oneshot::Sender<FingerprintVerificationReply>,
    },
    /// Credential request received — caller must approve/deny and provide the credential.
    CredentialRequest {
        /// The credential query
        query: crate::types::CredentialQuery,
        /// The requesting device's identity fingerprint
        identity: IdentityFingerprint,
        /// Channel to send the credential reply
        reply: oneshot::Sender<CredentialRequestReply>,
    },
}

// =============================================================================
// Internal types for pending reply tracking
// =============================================================================

/// Resolved reply from a pending oneshot, carrying the context needed to process it.
enum PendingReply {
    FingerprintVerification {
        source: IdentityFingerprint,
        transport: MultiDeviceTransport,
        connection_name: Option<String>,
        reply: Result<FingerprintVerificationReply, oneshot::error::RecvError>,
    },
    CredentialResponse {
        source: IdentityFingerprint,
        request_id: String,
        query: crate::types::CredentialQuery,
        reply: Result<CredentialRequestReply, oneshot::error::RecvError>,
    },
}

/// A boxed future that resolves to a `PendingReply`.
type PendingReplyFuture = Pin<Box<dyn Future<Output = PendingReply> + Send>>;

// =============================================================================
// Command channel for UserClient handle → event loop communication
// =============================================================================

/// Commands sent from a `UserClient` handle to the running event loop.
enum UserClientCommand {
    /// Generate a PSK token and register a pending pairing.
    GetPskToken {
        name: Option<String>,
        reply: oneshot::Sender<Result<String, RemoteClientError>>,
    },
    /// Request a rendezvous code from the proxy and register a pending pairing.
    GetRendezvousToken {
        name: Option<String>,
        reply: oneshot::Sender<Result<RendezvousCode, RemoteClientError>>,
    },
}

/// A cloneable handle for controlling the user client.
///
/// Obtained from [`UserClient::connect()`], which authenticates with the proxy,
/// spawns the event loop internally, and returns this handle. All methods
/// communicate with the event loop through an internal command channel.
///
/// `Clone` and `Send` — share freely across tasks and threads.
#[derive(Clone)]
pub struct UserClient {
    command_tx: mpsc::Sender<UserClientCommand>,
}

impl UserClient {
    /// Connect to the proxy server, spawn the event loop, and return a handle.
    ///
    /// This is the single entry point. After `connect()` returns, the client is
    /// already listening for incoming connections. Use `get_psk_token()` or
    /// `get_rendezvous_token()` to set up pairings, and receive events through
    /// the provided notification/request channels.
    ///
    /// Pass `None` for `audit_log` to use a no-op logger.
    pub async fn connect(
        identity_provider: Box<dyn IdentityProvider>,
        session_store: Box<dyn SessionStore>,
        mut proxy_client: Box<dyn ProxyClient>,
        notification_tx: mpsc::Sender<UserClientNotification>,
        request_tx: mpsc::Sender<UserClientRequest>,
        audit_log: Option<Box<dyn AuditLog>>,
    ) -> Result<Self, RemoteClientError> {
        // Authenticate with the proxy (the async part — before spawn)
        let incoming_rx = proxy_client.connect().await?;

        // Create command channel
        let (command_tx, command_rx) = mpsc::channel(32);

        // Cache fingerprint before spawning (avoids repeated async calls)
        let own_fingerprint = identity_provider.fingerprint().await;

        // Build the inner state
        let inner = UserClientInner {
            session_store,
            proxy_client,
            own_fingerprint,
            transports: HashMap::new(),
            pending_pairings: Vec::new(),
            audit_log: audit_log.unwrap_or_else(|| Box::new(NoOpAuditLog)),
        };

        // Spawn the event loop — use spawn_local on WASM (no Tokio runtime)
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(inner.run_event_loop(
            incoming_rx,
            command_rx,
            notification_tx,
            request_tx,
        ));
        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(inner.run_event_loop(incoming_rx, command_rx, notification_tx, request_tx));

        Ok(Self { command_tx })
    }

    /// Generate a PSK token for a new pairing.
    ///
    /// Returns the formatted token string (`<psk_hex>_<fingerprint_hex>`).
    /// Multiple PSK pairings are supported concurrently (each matched by `psk_id`).
    pub async fn get_psk_token(&self, name: Option<String>) -> Result<String, RemoteClientError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(UserClientCommand::GetPskToken { name, reply: tx })
            .await
            .map_err(|_| RemoteClientError::ChannelClosed)?;
        rx.await.map_err(|_| RemoteClientError::ChannelClosed)?
    }

    /// Request a rendezvous code from the proxy for a new pairing.
    ///
    /// Only one rendezvous pairing at a time — there's no way to distinguish
    /// incoming rendezvous handshakes.
    pub async fn get_rendezvous_token(
        &self,
        name: Option<String>,
    ) -> Result<RendezvousCode, RemoteClientError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(UserClientCommand::GetRendezvousToken { name, reply: tx })
            .await
            .map_err(|_| RemoteClientError::ChannelClosed)?;
        rx.await.map_err(|_| RemoteClientError::ChannelClosed)?
    }
}

// =============================================================================
// Internal state — lives inside the spawned event loop task
// =============================================================================

/// All mutable state for the user client, owned by the spawned event loop task.
struct UserClientInner {
    session_store: Box<dyn SessionStore>,
    proxy_client: Box<dyn ProxyClient>,
    /// Our own identity fingerprint (cached at construction time).
    own_fingerprint: IdentityFingerprint,
    /// Map of fingerprint -> transport
    transports: HashMap<IdentityFingerprint, MultiDeviceTransport>,
    /// Pending pairings awaiting incoming handshakes.
    pending_pairings: Vec<PendingPairing>,
    /// Audit logger for security-relevant events
    audit_log: Box<dyn AuditLog>,
}

impl UserClientInner {
    /// Run the main event loop (consumes self).
    async fn run_event_loop(
        mut self,
        mut incoming_rx: mpsc::UnboundedReceiver<IncomingMessage>,
        mut command_rx: mpsc::Receiver<UserClientCommand>,
        notification_tx: mpsc::Sender<UserClientNotification>,
        request_tx: mpsc::Sender<UserClientRequest>,
    ) {
        // Emit Listening notification
        notification_tx
            .send(UserClientNotification::Listening {})
            .await
            .ok();

        let mut pending_replies: FuturesUnordered<PendingReplyFuture> = FuturesUnordered::new();

        loop {
            tokio::select! {
                msg = incoming_rx.recv() => {
                    match msg {
                        Some(msg) => {
                            match self.handle_incoming(msg, &notification_tx, &request_tx).await {
                                Ok(Some(fut)) => pending_replies.push(fut),
                                Ok(None) => {}
                                Err(e) => {
                                    warn!("Error handling incoming message: {}", e);
                                    notification_tx.send(UserClientNotification::Error {
                                        message: e.to_string(),
                                        context: Some("handle_incoming".to_string()),
                                    }).await.ok();
                                }
                            }
                        }
                        None => {
                            // Incoming channel closed — proxy connection lost
                            notification_tx.send(UserClientNotification::ClientDisconnected {}).await.ok();
                            match self.attempt_reconnection(&notification_tx).await {
                                Ok(new_rx) => {
                                    incoming_rx = new_rx;
                                    notification_tx.send(UserClientNotification::Reconnected {}).await.ok();
                                }
                                Err(e) => {
                                    warn!("Reconnection failed permanently: {}", e);
                                    notification_tx.send(UserClientNotification::Error {
                                        message: e.to_string(),
                                        context: Some("reconnection".to_string()),
                                    }).await.ok();
                                    return;
                                }
                            }
                        }
                    }
                }
                Some(reply) = pending_replies.next() => {
                    if let Err(e) = self.process_pending_reply(reply, &notification_tx).await {
                        warn!("Error processing pending reply: {}", e);
                        notification_tx.send(UserClientNotification::Error {
                            message: e.to_string(),
                            context: Some("process_pending_reply".to_string()),
                        }).await.ok();
                    }
                }
                cmd = command_rx.recv() => {
                    match cmd {
                        Some(cmd) => self.handle_command(cmd, &notification_tx).await,
                        None => {
                            // All handles dropped — shut down
                            debug!("All UserClient handles dropped, shutting down event loop");
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Attempt to reconnect to the proxy server with exponential backoff.
    async fn attempt_reconnection(
        &mut self,
        notification_tx: &mpsc::Sender<UserClientNotification>,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, RemoteClientError> {
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::from_entropy();
        let mut attempt: u32 = 0;

        loop {
            attempt = attempt.saturating_add(1);

            // Disconnect (ignore errors — connection may already be dead)
            let _ = self.proxy_client.disconnect().await;

            match self.proxy_client.connect().await {
                Ok(new_rx) => {
                    debug!("Reconnected to proxy on attempt {}", attempt);
                    return Ok(new_rx);
                }
                Err(e) => {
                    debug!("Reconnection attempt {} failed: {}", attempt, e);
                    notification_tx
                        .send(UserClientNotification::Reconnecting { attempt })
                        .await
                        .ok();

                    // Exponential backoff with jitter
                    let exp_delay = RECONNECT_BASE_DELAY
                        .saturating_mul(2u32.saturating_pow(attempt.saturating_sub(1)));
                    let delay = exp_delay.min(RECONNECT_MAX_DELAY);
                    let jitter_max = (delay.as_millis() as u64) / 4;
                    let jitter = if jitter_max > 0 {
                        rng.gen_range(0..=jitter_max)
                    } else {
                        0
                    };
                    let total_delay = delay + Duration::from_millis(jitter);

                    crate::compat::sleep(total_delay).await;
                }
            }
        }
    }

    /// Handle incoming messages from proxy.
    async fn handle_incoming(
        &mut self,
        msg: IncomingMessage,
        notification_tx: &mpsc::Sender<UserClientNotification>,
        request_tx: &mpsc::Sender<UserClientRequest>,
    ) -> Result<Option<PendingReplyFuture>, RemoteClientError> {
        match msg {
            IncomingMessage::Send {
                source, payload, ..
            } => {
                // Parse payload as ProtocolMessage
                let text = String::from_utf8(payload)
                    .map_err(|e| RemoteClientError::Serialization(format!("Invalid UTF-8: {e}")))?;

                let protocol_msg: ProtocolMessage = serde_json::from_str(&text)?;

                match protocol_msg {
                    ProtocolMessage::HandshakeInit {
                        data,
                        ciphersuite,
                        psk_id,
                    } => {
                        self.handle_handshake_init(
                            source,
                            data,
                            ciphersuite,
                            psk_id,
                            notification_tx,
                            request_tx,
                        )
                        .await
                    }
                    ProtocolMessage::CredentialRequest { encrypted } => {
                        self.handle_credential_request(
                            source,
                            encrypted,
                            notification_tx,
                            request_tx,
                        )
                        .await
                    }
                    _ => {
                        debug!("Received unexpected message type from {:?}", source);
                        Ok(None)
                    }
                }
            }
            IncomingMessage::RendezvousInfo(code) => {
                // Find the pending rendezvous pairing that is still awaiting a reply
                let idx = self
                    .pending_pairings
                    .iter()
                    .position(|p| matches!(&p.kind, PairingKind::Rendezvous { reply: Some(_) }));

                if let Some(idx) = idx {
                    // Take the reply sender out, leaving the pairing in place with reply: None
                    let pairing = &mut self.pending_pairings[idx];
                    if let PairingKind::Rendezvous { reply } = &mut pairing.kind {
                        if let Some(sender) = reply.take() {
                            debug!("Completed rendezvous pairing via handle, code: {}", code);
                            let _ = sender.send(Ok(code));
                        }
                    }
                } else {
                    debug!("Received RendezvousInfo but no pending rendezvous pairing found");
                }
                Ok(None)
            }
            IncomingMessage::IdentityInfo { .. } => {
                // Only RemoteClient needs this
                debug!("Received unexpected IdentityInfo message");
                Ok(None)
            }
        }
    }

    /// Handle handshake init message.
    async fn handle_handshake_init(
        &mut self,
        source: IdentityFingerprint,
        data: String,
        ciphersuite: String,
        psk_id: Option<PskId>,
        notification_tx: &mpsc::Sender<UserClientNotification>,
        request_tx: &mpsc::Sender<UserClientRequest>,
    ) -> Result<Option<PendingReplyFuture>, RemoteClientError> {
        debug!("Received handshake init from source: {:?}", source);
        notification_tx
            .send(UserClientNotification::HandshakeStart {})
            .await
            .ok();

        // Check if this is an existing/cached session (bypass pairing lookup)
        let is_new_connection = !self.session_store.has_session(&source).await;

        // Determine which PSK to use and find the matching pairing.
        let (psk_for_handshake, matched_pairing_name, is_psk_connection) = if !is_new_connection {
            // Existing/cached session — no pairing lookup needed
            (None, None, false)
        } else {
            // New connection — look up and consume a pending pairing
            Self::prune_stale_pairings(&mut self.pending_pairings);

            match &psk_id {
                Some(id) => {
                    // PSK mode — find matching pairing by psk_id
                    let idx = self.pending_pairings.iter().position(
                        |p| matches!(&p.kind, PairingKind::Psk { psk_id: pid, .. } if pid == id),
                    );
                    if let Some(idx) = idx {
                        let pairing = self.pending_pairings.remove(idx);
                        let psk = match pairing.kind {
                            PairingKind::Psk { psk, .. } => psk,
                            PairingKind::Rendezvous { .. } => unreachable!(),
                        };
                        (Some(psk), pairing.connection_name, true)
                    } else {
                        warn!("No matching PSK pairing for psk_id: {}", id);
                        return Err(RemoteClientError::InvalidState {
                            expected: "matching PSK pairing".to_string(),
                            current: format!("no pairing for psk_id {id}"),
                        });
                    }
                }
                None => {
                    // Rendezvous mode — find a confirmed rendezvous pairing
                    // (one whose reply has already been sent, i.e. reply is None)
                    let idx = self
                        .pending_pairings
                        .iter()
                        .position(|p| matches!(p.kind, PairingKind::Rendezvous { reply: None }));
                    let connection_name =
                        idx.and_then(|i| self.pending_pairings.remove(i).connection_name);
                    (None, connection_name, false)
                }
            }
        };

        let (transport, fingerprint_str) = self
            .complete_handshake(source, &data, &ciphersuite, psk_for_handshake.as_ref())
            .await?;

        notification_tx
            .send(UserClientNotification::HandshakeComplete {})
            .await
            .ok();

        if is_new_connection && !is_psk_connection {
            // New rendezvous connection: require fingerprint verification.
            let (tx, rx) = oneshot::channel();

            request_tx
                .send(UserClientRequest::VerifyFingerprint {
                    fingerprint: fingerprint_str,
                    identity: source,
                    reply: tx,
                })
                .await
                .ok();

            let fut: PendingReplyFuture = Box::pin(async move {
                let result = rx.await;
                PendingReply::FingerprintVerification {
                    source,
                    transport,
                    connection_name: matched_pairing_name,
                    reply: result,
                }
            });

            Ok(Some(fut))
        } else if !is_new_connection {
            // Existing/cached session: already verified on first connection.
            self.transports.insert(source, transport.clone());
            self.session_store.cache_session(source).await?;
            self.session_store
                .save_transport_state(&source, transport)
                .await?;

            self.audit_log
                .write(AuditEvent::SessionRefreshed {
                    remote_identity: &source,
                })
                .await;

            notification_tx
                .send(UserClientNotification::SessionRefreshed {
                    fingerprint: source,
                })
                .await
                .ok();

            Ok(None)
        } else {
            // PSK connection: trust established via pre-shared key, no verification needed
            self.accept_new_connection(
                source,
                transport,
                matched_pairing_name.as_deref(),
                AuditConnectionType::Psk,
            )
            .await?;

            // Emit fingerprint as informational notification (no reply needed)
            notification_tx
                .send(UserClientNotification::HandshakeFingerprint {
                    fingerprint: fingerprint_str,
                    identity: source,
                })
                .await
                .ok();

            Ok(None)
        }
    }

    /// Remove pending pairings older than `PENDING_PAIRING_MAX_AGE`.
    fn prune_stale_pairings(pairings: &mut Vec<PendingPairing>) {
        pairings.retain(|p| p.created_at.elapsed() < PENDING_PAIRING_MAX_AGE);
    }

    /// Accept a new connection: cache session, store transport, set name, and audit
    async fn accept_new_connection(
        &mut self,
        fingerprint: IdentityFingerprint,
        transport: MultiDeviceTransport,
        session_name: Option<&str>,
        connection_type: AuditConnectionType,
    ) -> Result<(), RemoteClientError> {
        self.transports.insert(fingerprint, transport.clone());
        self.session_store.cache_session(fingerprint).await?;
        if let Some(name) = session_name {
            self.session_store
                .set_session_name(&fingerprint, name.to_owned())
                .await?;
        }
        self.session_store
            .save_transport_state(&fingerprint, transport)
            .await?;

        self.audit_log
            .write(AuditEvent::ConnectionEstablished {
                remote_identity: &fingerprint,
                remote_name: session_name,
                connection_type,
            })
            .await;

        Ok(())
    }

    /// Handle credential request.
    async fn handle_credential_request(
        &mut self,
        source: IdentityFingerprint,
        encrypted: String,
        notification_tx: &mpsc::Sender<UserClientNotification>,
        request_tx: &mpsc::Sender<UserClientRequest>,
    ) -> Result<Option<PendingReplyFuture>, RemoteClientError> {
        if !self.transports.contains_key(&source) {
            debug!("Loading transport state for source: {:?}", source);
            let session = self
                .session_store
                .load_transport_state(&source)
                .await?
                .ok_or_else(|| {
                    RemoteClientError::SessionCache(format!(
                        "Missing transport state for cached session {source:?}"
                    ))
                })?;
            self.transports.insert(source, session);
        }

        // Get transport for this source
        let transport = self
            .transports
            .get_mut(&source)
            .ok_or(RemoteClientError::SecureChannelNotEstablished)?;

        // Decrypt request
        let encrypted_bytes = STANDARD
            .decode(&encrypted)
            .map_err(|e| RemoteClientError::Serialization(format!("Invalid base64: {e}")))?;

        let packet = ap_noise::TransportPacket::decode(&encrypted_bytes)
            .map_err(|e| RemoteClientError::NoiseProtocol(format!("Invalid packet: {e}")))?;

        let decrypted = transport
            .decrypt(&packet)
            .map_err(|e| RemoteClientError::NoiseProtocol(e.to_string()))?;

        let request: CredentialRequestPayload = serde_json::from_slice(&decrypted)?;

        self.audit_log
            .write(AuditEvent::CredentialRequested {
                query: &request.query,
                remote_identity: &source,
                request_id: &request.request_id,
            })
            .await;

        // Create oneshot channel for the reply
        let (tx, rx) = oneshot::channel();

        // Send request to caller
        if request_tx
            .send(UserClientRequest::CredentialRequest {
                query: request.query.clone(),
                identity: source,
                reply: tx,
            })
            .await
            .is_err()
        {
            // Request channel closed — caller is gone
            warn!("Request channel closed, cannot send credential request");
            notification_tx
                .send(UserClientNotification::Error {
                    message: "Request channel closed".to_string(),
                    context: Some("handle_credential_request".to_string()),
                })
                .await
                .ok();
            return Ok(None);
        }

        // Return future that awaits the reply
        let request_id = request.request_id;
        let query = request.query;
        let fut: PendingReplyFuture = Box::pin(async move {
            let result = rx.await;
            PendingReply::CredentialResponse {
                source,
                request_id,
                query,
                reply: result,
            }
        });

        Ok(Some(fut))
    }

    /// Process a resolved pending reply from the `FuturesUnordered`.
    async fn process_pending_reply(
        &mut self,
        reply: PendingReply,
        notification_tx: &mpsc::Sender<UserClientNotification>,
    ) -> Result<(), RemoteClientError> {
        match reply {
            PendingReply::FingerprintVerification {
                source,
                transport,
                connection_name,
                reply,
            } => {
                self.process_fingerprint_reply(
                    source,
                    transport,
                    connection_name,
                    reply,
                    notification_tx,
                )
                .await
            }
            PendingReply::CredentialResponse {
                source,
                request_id,
                query,
                reply,
            } => {
                self.process_credential_reply(source, request_id, query, reply, notification_tx)
                    .await
            }
        }
    }

    /// Handle a command from a `UserClient` handle.
    async fn handle_command(
        &mut self,
        cmd: UserClientCommand,
        notification_tx: &mpsc::Sender<UserClientNotification>,
    ) {
        match cmd {
            UserClientCommand::GetPskToken { name, reply } => {
                let result = self.generate_psk_token(name).await;
                let _ = reply.send(result);
            }
            UserClientCommand::GetRendezvousToken { name, reply } => {
                if let Err(e) = self.proxy_client.request_rendezvous().await {
                    let _ = reply.send(Err(e));
                    return;
                }

                // Prune stale pairings
                Self::prune_stale_pairings(&mut self.pending_pairings);

                // If there's already a pending rendezvous pairing awaiting its code,
                // error the old one rather than silently overwriting it
                if let Some(old_idx) = self
                    .pending_pairings
                    .iter()
                    .position(|p| matches!(&p.kind, PairingKind::Rendezvous { reply: Some(_) }))
                {
                    let old = self.pending_pairings.remove(old_idx);
                    if let PairingKind::Rendezvous {
                        reply: Some(old_reply),
                    } = old.kind
                    {
                        warn!("Replacing existing pending rendezvous pairing");
                        let _ = old_reply.send(Err(RemoteClientError::InvalidState {
                            expected: "single pending rendezvous".to_string(),
                            current: "replaced by new rendezvous request".to_string(),
                        }));
                    }
                }

                // Push the new pairing immediately — reply will be completed
                // when RendezvousInfo arrives from the proxy
                self.pending_pairings.push(PendingPairing {
                    connection_name: name,
                    created_at: Instant::now(),
                    kind: PairingKind::Rendezvous { reply: Some(reply) },
                });

                // Emit notification so the caller knows a code is being requested
                notification_tx
                    .send(UserClientNotification::HandshakeProgress {
                        message: "Requesting rendezvous code from proxy...".to_string(),
                    })
                    .await
                    .ok();
            }
        }
    }

    /// Generate a PSK token internally.
    async fn generate_psk_token(
        &mut self,
        name: Option<String>,
    ) -> Result<String, RemoteClientError> {
        let psk = Psk::generate();
        let psk_id = psk.id();
        let token = format!("{}_{}", psk.to_hex(), hex::encode(self.own_fingerprint.0));

        let pairing = PendingPairing {
            connection_name: name,
            created_at: Instant::now(),
            kind: PairingKind::Psk { psk, psk_id },
        };

        Self::prune_stale_pairings(&mut self.pending_pairings);
        self.pending_pairings.push(pairing);
        debug!("Created PSK pairing, token generated");

        Ok(token)
    }

    /// Process a fingerprint verification reply.
    async fn process_fingerprint_reply(
        &mut self,
        source: IdentityFingerprint,
        transport: MultiDeviceTransport,
        connection_name: Option<String>,
        reply: Result<FingerprintVerificationReply, oneshot::error::RecvError>,
        notification_tx: &mpsc::Sender<UserClientNotification>,
    ) -> Result<(), RemoteClientError> {
        match reply {
            Ok(FingerprintVerificationReply {
                approved: true,
                name,
            }) => {
                // Use the name from the reply, falling back to the pairing name
                let session_name = name.or(connection_name);
                self.accept_new_connection(
                    source,
                    transport,
                    session_name.as_deref(),
                    AuditConnectionType::Rendezvous,
                )
                .await?;

                notification_tx
                    .send(UserClientNotification::FingerprintVerified {})
                    .await
                    .ok();
            }
            Ok(FingerprintVerificationReply {
                approved: false, ..
            }) => {
                self.audit_log
                    .write(AuditEvent::ConnectionRejected {
                        remote_identity: &source,
                    })
                    .await;

                notification_tx
                    .send(UserClientNotification::FingerprintRejected {
                        reason: "User rejected fingerprint verification".to_string(),
                    })
                    .await
                    .ok();
            }
            Err(_) => {
                // Oneshot sender was dropped without replying — treat as rejection
                warn!("Fingerprint verification reply channel dropped, treating as rejection");
                self.audit_log
                    .write(AuditEvent::ConnectionRejected {
                        remote_identity: &source,
                    })
                    .await;

                notification_tx
                    .send(UserClientNotification::FingerprintRejected {
                        reason: "Verification cancelled (reply dropped)".to_string(),
                    })
                    .await
                    .ok();
            }
        }

        Ok(())
    }

    /// Process a credential request reply.
    #[allow(clippy::too_many_arguments)]
    async fn process_credential_reply(
        &mut self,
        source: IdentityFingerprint,
        request_id: String,
        query: crate::types::CredentialQuery,
        reply: Result<CredentialRequestReply, oneshot::error::RecvError>,
        notification_tx: &mpsc::Sender<UserClientNotification>,
    ) -> Result<(), RemoteClientError> {
        let reply = match reply {
            Ok(r) => r,
            Err(_) => {
                // Oneshot sender was dropped — treat as denial
                warn!("Credential reply channel dropped, treating as denial");
                CredentialRequestReply {
                    approved: false,
                    credential: None,
                    credential_id: None,
                }
            }
        };

        let transport = self
            .transports
            .get_mut(&source)
            .ok_or(RemoteClientError::SecureChannelNotEstablished)?;

        // Extract domain and audit fields before credential is moved into the response payload
        let domain = reply.credential.as_ref().and_then(|c| c.domain.clone());
        let fields = reply
            .credential
            .as_ref()
            .map_or_else(CredentialFieldSet::default, |c| CredentialFieldSet {
                has_username: c.username.is_some(),
                has_password: c.password.is_some(),
                has_totp: c.totp.is_some(),
                has_uri: c.uri.is_some(),
                has_notes: c.notes.is_some(),
            });

        // Create response payload
        let response_payload = CredentialResponsePayload {
            credential: if reply.approved {
                reply.credential
            } else {
                None
            },
            error: if !reply.approved {
                Some("Request denied".to_string())
            } else {
                None
            },
            request_id: Some(request_id.clone()),
        };

        // Encrypt and send
        let response_json = serde_json::to_string(&response_payload)?;
        let encrypted = transport
            .encrypt(response_json.as_bytes())
            .map_err(|e| RemoteClientError::NoiseProtocol(e.to_string()))?;

        let msg = ProtocolMessage::CredentialResponse {
            encrypted: STANDARD.encode(encrypted.encode()),
        };

        let msg_json = serde_json::to_string(&msg)?;

        self.proxy_client
            .send_to(source, msg_json.into_bytes())
            .await?;

        // Send notification and audit
        if reply.approved {
            self.audit_log
                .write(AuditEvent::CredentialApproved {
                    query: &query,
                    domain: domain.as_deref(),
                    remote_identity: &source,
                    request_id: &request_id,
                    credential_id: reply.credential_id.as_deref(),
                    fields,
                })
                .await;

            notification_tx
                .send(UserClientNotification::CredentialApproved {
                    domain,
                    credential_id: reply.credential_id,
                })
                .await
                .ok();
        } else {
            self.audit_log
                .write(AuditEvent::CredentialDenied {
                    query: &query,
                    domain: domain.as_deref(),
                    remote_identity: &source,
                    request_id: &request_id,
                    credential_id: reply.credential_id.as_deref(),
                })
                .await;

            notification_tx
                .send(UserClientNotification::CredentialDenied {
                    domain,
                    credential_id: reply.credential_id,
                })
                .await
                .ok();
        }

        Ok(())
    }

    /// Complete Noise handshake as responder
    async fn complete_handshake(
        &self,
        remote_fingerprint: IdentityFingerprint,
        handshake_data: &str,
        ciphersuite_str: &str,
        psk: Option<&Psk>,
    ) -> Result<(MultiDeviceTransport, String), RemoteClientError> {
        // Parse ciphersuite
        let ciphersuite = match ciphersuite_str {
            s if s.contains("Kyber768") => Ciphersuite::PQNNpsk2_Kyber768_XChaCha20Poly1305,
            _ => Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035,
        };

        // Decode handshake data
        let init_bytes = STANDARD
            .decode(handshake_data)
            .map_err(|e| RemoteClientError::Serialization(format!("Invalid base64: {e}")))?;

        let init_packet = ap_noise::HandshakePacket::decode(&init_bytes)
            .map_err(|e| RemoteClientError::NoiseProtocol(format!("Invalid packet: {e}")))?;

        // Create responder handshake — with PSK if provided, otherwise null PSK (rendezvous)
        let mut handshake = if let Some(psk) = psk {
            ResponderHandshake::with_psk(psk.clone())
        } else {
            ResponderHandshake::new()
        };

        // Process init and generate response
        handshake.receive_start(&init_packet)?;
        let response_packet = handshake.send_finish()?;
        let (transport, fingerprint) = handshake.finalize()?;

        // Send response
        let msg = ProtocolMessage::HandshakeResponse {
            data: STANDARD.encode(response_packet.encode()?),
            ciphersuite: format!("{ciphersuite:?}"),
        };

        let msg_json = serde_json::to_string(&msg)?;

        self.proxy_client
            .send_to(remote_fingerprint, msg_json.into_bytes())
            .await?;

        debug!("Sent handshake response to {:?}", remote_fingerprint);

        Ok((transport, fingerprint.to_string()))
    }
}
