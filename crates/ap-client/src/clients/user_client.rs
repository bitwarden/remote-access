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
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair, RendezvousCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tokio::sync::oneshot;

use crate::proxy::ProxyClient;
use crate::types::{CredentialData, PskId, PskToken};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Base delay for reconnection backoff.
const RECONNECT_BASE_DELAY: Duration = Duration::from_secs(2);
/// Maximum delay between reconnection attempts (15 minutes).
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(15 * 60);
/// Maximum age for pending pairings before they are pruned.
const PENDING_PAIRING_MAX_AGE: Duration = Duration::from_secs(10 * 60);
/// Maximum number of messages buffered per peer while awaiting fingerprint verification.
const AWAITING_VERIFICATION_BUFFER_LIMIT: usize = 100;

/// A pending PSK pairing waiting for an incoming handshake.
struct PskPairing {
    connection_name: Option<String>,
    created_at: Instant,
    psk: Psk,
}

/// A pending rendezvous pairing waiting for an incoming handshake.
struct RendezvousPairing {
    connection_name: Option<String>,
    created_at: Instant,
    /// Channel to deliver the rendezvous code — `Some` while awaiting, `None` after delivery.
    code_tx: Option<oneshot::Sender<Result<RendezvousCode, ClientError>>>,
}

/// Manages pending pairings and verification message buffers.
///
/// Pairings track handshake setup (rendezvous codes, PSKs). Verification buffers
/// hold messages from peers whose fingerprint is awaiting user approval — once
/// approved the buffer is drained and replayed, on rejection it is discarded.
struct PendingPairings {
    /// PSK pairings keyed by their PskId for direct lookup.
    psk_pairings: HashMap<PskId, PskPairing>,
    /// At most one rendezvous pairing at a time.
    rendezvous: Option<RendezvousPairing>,
    /// Messages buffered per peer while awaiting fingerprint verification.
    buffered_messages: HashMap<IdentityFingerprint, Vec<IncomingMessage>>,
}

impl PendingPairings {
    fn new() -> Self {
        Self {
            psk_pairings: HashMap::new(),
            rendezvous: None,
            buffered_messages: HashMap::new(),
        }
    }

    /// Remove pairings older than `PENDING_PAIRING_MAX_AGE`.
    fn prune_stale(&mut self) {
        self.psk_pairings
            .retain(|_, p| p.created_at.elapsed() < PENDING_PAIRING_MAX_AGE);
        if self
            .rendezvous
            .as_ref()
            .is_some_and(|r| r.created_at.elapsed() >= PENDING_PAIRING_MAX_AGE)
        {
            self.rendezvous = None;
        }
    }

    /// Take the pending rendezvous pairing, if any.
    fn take_rendezvous(&mut self) -> Option<RendezvousPairing> {
        self.rendezvous.take()
    }

    /// Start buffering messages for a source that is awaiting fingerprint verification.
    fn prepare_buffering(&mut self, source: IdentityFingerprint) {
        self.buffered_messages.insert(source, Vec::new());
    }

    /// Try to buffer a message for a source awaiting fingerprint verification.
    /// Returns `None` if handled (buffered or dropped due to limit),
    /// or `Some(msg)` if the source is not awaiting verification.
    fn try_buffer_message(&mut self, msg: IncomingMessage) -> Option<IncomingMessage> {
        let source = match &msg {
            IncomingMessage::Send { source, .. } => source,
            _ => return Some(msg),
        };
        if let Some(buffer) = self.buffered_messages.get_mut(source) {
            if buffer.len() < AWAITING_VERIFICATION_BUFFER_LIMIT {
                debug!(
                    "Buffering message from {:?} pending fingerprint verification",
                    source
                );
                buffer.push(msg);
            } else {
                warn!("Buffer limit reached for {:?}, dropping message", source);
            }
            None
        } else {
            Some(msg)
        }
    }

    /// Remove and return buffered messages for a source.
    /// Used to replay on approval or discard on rejection.
    fn take_buffered_messages(&mut self, source: &IdentityFingerprint) -> Vec<IncomingMessage> {
        self.buffered_messages.remove(source).unwrap_or_default()
    }
}

use super::notify;
use crate::{
    error::ClientError,
    traits::{
        AuditConnectionType, AuditEvent, AuditLog, ConnectionInfo, ConnectionStore,
        CredentialFieldSet, IdentityProvider, NoOpAuditLog,
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
#[derive(Debug)]
pub struct FingerprintVerificationReply {
    /// Whether user approved the fingerprint
    pub approved: bool,
    /// Optional friendly name to assign to the session
    pub name: Option<String>,
}

/// Reply for credential requests.
#[derive(Debug)]
pub struct CredentialRequestReply {
    /// Whether approved
    pub approved: bool,
    /// The credential to send (if approved)
    pub credential: Option<CredentialData>,
    /// Vault item ID (for audit logging)
    pub credential_id: Option<String>,
}

/// Requests that require a caller response, carrying a oneshot reply channel.
#[derive(Debug)]
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
        reply: oneshot::Sender<Result<String, ClientError>>,
    },
    /// Request a rendezvous code from the proxy and register a pending pairing.
    GetRendezvousToken {
        name: Option<String>,
        reply: oneshot::Sender<Result<RendezvousCode, ClientError>>,
    },
}

/// A cloneable handle for controlling the user client.
///
/// Obtained from [`UserClient::connect()`], which authenticates with the proxy,
/// spawns the event loop internally, and returns this handle. All methods
/// communicate with the event loop through an internal command channel.
///
/// `Clone` and `Send` — share freely across tasks and threads.
/// Handle returned by [`UserClient::connect()`] containing the client and its
/// notification/request channels.
pub struct UserClientHandle {
    pub client: UserClient,
    pub notifications: mpsc::Receiver<UserClientNotification>,
    pub requests: mpsc::Receiver<UserClientRequest>,
}

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
    /// the returned handle's notification/request channels.
    ///
    /// Pass `None` for `audit_log` to use a no-op logger.
    pub async fn connect(
        identity_provider: Box<dyn IdentityProvider>,
        connection_store: Box<dyn ConnectionStore>,
        mut proxy_client: Box<dyn ProxyClient>,
        audit_log: Option<Box<dyn AuditLog>>,
    ) -> Result<UserClientHandle, ClientError> {
        // Extract identity once — used for proxy auth, reconnection, and own fingerprint
        let identity_keypair = identity_provider.identity().await;
        let own_fingerprint = identity_keypair.identity().fingerprint();

        // Authenticate with the proxy (the async part — before spawn)
        let incoming_rx = proxy_client.connect(identity_keypair.clone()).await?;

        // Create channels
        let (notification_tx, notification_rx) = mpsc::channel(32);
        let (request_tx, request_rx) = mpsc::channel(32);

        // Create command channel
        let (command_tx, command_rx) = mpsc::channel(32);

        // Build the inner state
        let inner = UserClientInner {
            connection_store,
            proxy_client,
            identity_keypair,
            own_fingerprint,
            transports: HashMap::new(),
            pending_pairings: PendingPairings::new(),
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

        Ok(UserClientHandle {
            client: Self { command_tx },
            notifications: notification_rx,
            requests: request_rx,
        })
    }

    /// Generate a PSK token for a new pairing.
    ///
    /// Returns the formatted token string (`<psk_hex>_<fingerprint_hex>`).
    /// Multiple PSK pairings are supported concurrently (each matched by `psk_id`).
    pub async fn get_psk_token(&self, name: Option<String>) -> Result<String, ClientError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(UserClientCommand::GetPskToken { name, reply: tx })
            .await
            .map_err(|_| ClientError::ChannelClosed)?;
        rx.await.map_err(|_| ClientError::ChannelClosed)?
    }

    /// Request a rendezvous code from the proxy for a new pairing.
    ///
    /// Only one rendezvous pairing at a time — there's no way to distinguish
    /// incoming rendezvous handshakes.
    pub async fn get_rendezvous_token(
        &self,
        name: Option<String>,
    ) -> Result<RendezvousCode, ClientError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(UserClientCommand::GetRendezvousToken { name, reply: tx })
            .await
            .map_err(|_| ClientError::ChannelClosed)?;
        rx.await.map_err(|_| ClientError::ChannelClosed)?
    }
}

// =============================================================================
// Internal state — lives inside the spawned event loop task
// =============================================================================

/// All mutable state for the user client, owned by the spawned event loop task.
struct UserClientInner {
    connection_store: Box<dyn ConnectionStore>,
    proxy_client: Box<dyn ProxyClient>,
    /// Our identity keypair (needed for reconnection).
    identity_keypair: IdentityKeyPair,
    /// Our own identity fingerprint (cached at construction time).
    own_fingerprint: IdentityFingerprint,
    /// Map of fingerprint -> transport
    transports: HashMap<IdentityFingerprint, MultiDeviceTransport>,
    /// Pending pairings and verification message buffers.
    pending_pairings: PendingPairings,
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
        notify!(notification_tx, UserClientNotification::Listening {});

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
                                    notify!(notification_tx, UserClientNotification::Error {
                                        message: e.to_string(),
                                        context: Some("handle_incoming".to_string()),
                                    });
                                }
                            }
                        }
                        None => {
                            // Incoming channel closed — proxy connection lost
                            notify!(notification_tx, UserClientNotification::ClientDisconnected {});
                            match self.attempt_reconnection(&notification_tx).await {
                                Ok(new_rx) => {
                                    incoming_rx = new_rx;
                                    notify!(notification_tx, UserClientNotification::Reconnected {});
                                }
                                Err(e) => {
                                    warn!("Reconnection failed permanently: {}", e);
                                    notify!(notification_tx, UserClientNotification::Error {
                                        message: e.to_string(),
                                        context: Some("reconnection".to_string()),
                                    });
                                    return;
                                }
                            }
                        }
                    }
                }
                Some(reply) = pending_replies.next() => {
                    match self.process_pending_reply(reply, &notification_tx, &request_tx).await {
                        Ok(futs) => {
                            for fut in futs {
                                pending_replies.push(fut);
                            }
                        }
                        Err(e) => {
                            warn!("Error processing pending reply: {}", e);
                            notify!(notification_tx, UserClientNotification::Error {
                                message: e.to_string(),
                                context: Some("process_pending_reply".to_string()),
                            });
                        }
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
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ClientError> {
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::from_entropy();
        let mut attempt: u32 = 0;

        loop {
            attempt = attempt.saturating_add(1);

            // Disconnect (ignore errors — connection may already be dead)
            let _ = self.proxy_client.disconnect().await;

            match self
                .proxy_client
                .connect(self.identity_keypair.clone())
                .await
            {
                Ok(new_rx) => {
                    debug!("Reconnected to proxy on attempt {}", attempt);
                    return Ok(new_rx);
                }
                Err(e) => {
                    debug!("Reconnection attempt {} failed: {}", attempt, e);
                    notify!(
                        notification_tx,
                        UserClientNotification::Reconnecting { attempt }
                    );

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
    ) -> Result<Option<PendingReplyFuture>, ClientError> {
        // If this source is awaiting fingerprint verification, buffer the message
        let Some(msg) = self.pending_pairings.try_buffer_message(msg) else {
            return Ok(None);
        };

        match msg {
            IncomingMessage::Send {
                source, payload, ..
            } => {
                let text = String::from_utf8(payload)
                    .map_err(|e| ClientError::Serialization(format!("Invalid UTF-8: {e}")))?;

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
                if let Some(pairing) = &mut self.pending_pairings.rendezvous {
                    if let Some(sender) = pairing.code_tx.take() {
                        debug!("Completed rendezvous pairing via handle, code: {}", code);
                        let _ = sender.send(Ok(code));
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
    ) -> Result<Option<PendingReplyFuture>, ClientError> {
        debug!("Received handshake init from source: {:?}", source);
        notify!(notification_tx, UserClientNotification::HandshakeStart {});

        // Check if this is an existing/cached connection (bypass pairing lookup)
        let is_new_connection = self.connection_store.get(&source).await.is_none();

        // Determine which PSK to use and find the matching pairing.
        let (psk_for_handshake, matched_pairing_name, is_psk_connection) = if !is_new_connection {
            // Existing/cached session — no pairing lookup needed
            (None, None, false)
        } else {
            // New connection — look up and consume a pending pairing
            self.pending_pairings.prune_stale();

            match &psk_id {
                Some(id) => {
                    // PSK mode — find matching pairing by psk_id
                    if let Some(pairing) = self.pending_pairings.psk_pairings.remove(id) {
                        (Some(pairing.psk), pairing.connection_name, true)
                    } else {
                        warn!("No matching PSK pairing for psk_id: {}", id);
                        return Err(ClientError::InvalidState {
                            expected: "matching PSK pairing".to_string(),
                            current: format!("no pairing for psk_id {id}"),
                        });
                    }
                }
                None => {
                    // Rendezvous mode — take the pending rendezvous pairing
                    if let Some(pairing) = self.pending_pairings.take_rendezvous() {
                        (None, pairing.connection_name, false)
                    } else {
                        return Err(ClientError::InvalidState {
                            expected: "pending rendezvous pairing".to_string(),
                            current: "no pending rendezvous pairing".to_string(),
                        });
                    }
                }
            }
        };

        let (transport, fingerprint_str) = self
            .complete_handshake(source, &data, &ciphersuite, psk_for_handshake.as_ref())
            .await?;

        notify!(
            notification_tx,
            UserClientNotification::HandshakeComplete {}
        );

        if is_new_connection && !is_psk_connection {
            // New rendezvous connection: require fingerprint verification.
            // Buffer messages from this source until verification completes.
            self.pending_pairings.prepare_buffering(source);

            let (tx, rx) = oneshot::channel();

            if request_tx.capacity() == 0 {
                warn!("Request channel full, waiting for consumer to drain");
            }
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
            // Existing/cached connection: already verified on first connection.
            // Get existing connection to preserve name and cached_at, update transport.
            let existing = self.connection_store.get(&source).await;
            let now = crate::compat::now_seconds();
            self.transports.insert(source, transport.clone());
            self.connection_store
                .save(ConnectionInfo {
                    fingerprint: source,
                    name: existing.as_ref().and_then(|s| s.name.clone()),
                    cached_at: existing.as_ref().map_or(now, |s| s.cached_at),
                    last_connected_at: now,
                    transport_state: Some(transport),
                })
                .await?;

            self.audit_log
                .write(AuditEvent::SessionRefreshed {
                    remote_identity: &source,
                })
                .await;

            notify!(
                notification_tx,
                UserClientNotification::SessionRefreshed {
                    fingerprint: source,
                }
            );

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
            notify!(
                notification_tx,
                UserClientNotification::HandshakeFingerprint {
                    fingerprint: fingerprint_str,
                    identity: source,
                }
            );

            Ok(None)
        }
    }

    /// Accept a new connection: cache connection, store transport, set name, and audit
    async fn accept_new_connection(
        &mut self,
        fingerprint: IdentityFingerprint,
        transport: MultiDeviceTransport,
        connection_name: Option<&str>,
        connection_type: AuditConnectionType,
    ) -> Result<(), ClientError> {
        let now = crate::compat::now_seconds();
        self.transports.insert(fingerprint, transport.clone());
        self.connection_store
            .save(ConnectionInfo {
                fingerprint,
                name: connection_name.map(|s| s.to_owned()),
                cached_at: now,
                last_connected_at: now,
                transport_state: Some(transport),
            })
            .await?;

        self.audit_log
            .write(AuditEvent::ConnectionEstablished {
                remote_identity: &fingerprint,
                remote_name: connection_name,
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
    ) -> Result<Option<PendingReplyFuture>, ClientError> {
        if !self.transports.contains_key(&source) {
            debug!("Loading transport state for source: {:?}", source);
            let connection = self.connection_store.get(&source).await.ok_or_else(|| {
                ClientError::ConnectionCache(format!("Missing cached connection {source:?}"))
            })?;
            let transport = connection.transport_state.ok_or_else(|| {
                ClientError::ConnectionCache(format!(
                    "Missing transport state for cached connection {source:?}"
                ))
            })?;
            self.transports.insert(source, transport);
        }

        // Get transport for this source
        let transport = self
            .transports
            .get_mut(&source)
            .ok_or(ClientError::SecureChannelNotEstablished)?;

        // Decrypt request
        let encrypted_bytes = STANDARD
            .decode(&encrypted)
            .map_err(|e| ClientError::Serialization(format!("Invalid base64: {e}")))?;

        let packet = ap_noise::TransportPacket::decode(&encrypted_bytes)
            .map_err(|e| ClientError::NoiseProtocol(format!("Invalid packet: {e}")))?;

        let decrypted = transport
            .decrypt(&packet)
            .map_err(|e| ClientError::NoiseProtocol(e.to_string()))?;

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
        if request_tx.capacity() == 0 {
            warn!("Request channel full, waiting for consumer to drain");
        }
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
            notify!(
                notification_tx,
                UserClientNotification::Error {
                    message: "Request channel closed".to_string(),
                    context: Some("handle_credential_request".to_string()),
                }
            );
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
        request_tx: &mpsc::Sender<UserClientRequest>,
    ) -> Result<Vec<PendingReplyFuture>, ClientError> {
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
                    request_tx,
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
                    .await?;
                Ok(Vec::new())
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
                self.pending_pairings.prune_stale();

                // Replace any existing rendezvous pairing — the old sender drops,
                // causing the receiver to get a RecvError (maps to ChannelClosed)
                self.pending_pairings.rendezvous = Some(RendezvousPairing {
                    connection_name: name,
                    created_at: Instant::now(),
                    code_tx: Some(reply),
                });

                // Emit notification so the caller knows a code is being requested
                notify!(
                    notification_tx,
                    UserClientNotification::HandshakeProgress {
                        message: "Requesting rendezvous code from proxy...".to_string(),
                    }
                );
            }
        }
    }

    /// Generate a PSK token internally.
    async fn generate_psk_token(&mut self, name: Option<String>) -> Result<String, ClientError> {
        let psk = Psk::generate();
        let psk_id = psk.id();
        let token = PskToken::new(psk.clone(), self.own_fingerprint).to_string();

        self.pending_pairings.prune_stale();
        self.pending_pairings.psk_pairings.insert(
            psk_id,
            PskPairing {
                connection_name: name,
                created_at: Instant::now(),
                psk,
            },
        );
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
        request_tx: &mpsc::Sender<UserClientRequest>,
    ) -> Result<Vec<PendingReplyFuture>, ClientError> {
        match reply {
            Ok(FingerprintVerificationReply {
                approved: true,
                name,
            }) => {
                // Use the name from the reply, falling back to the pairing name
                let conn_name = name.or(connection_name);
                self.accept_new_connection(
                    source,
                    transport,
                    conn_name.as_deref(),
                    AuditConnectionType::Rendezvous,
                )
                .await?;

                notify!(
                    notification_tx,
                    UserClientNotification::FingerprintVerified {}
                );

                // Drain and replay buffered messages
                let mut futures = Vec::new();
                for msg in self.pending_pairings.take_buffered_messages(&source) {
                    match self.handle_incoming(msg, notification_tx, request_tx).await {
                        Ok(Some(fut)) => futures.push(fut),
                        Ok(None) => {}
                        Err(e) => {
                            warn!("Error processing buffered message: {}", e);
                        }
                    }
                }

                Ok(futures)
            }
            Ok(FingerprintVerificationReply {
                approved: false, ..
            }) => {
                self.reject_fingerprint(
                    &source,
                    "User rejected fingerprint verification",
                    notification_tx,
                )
                .await;
                Ok(Vec::new())
            }
            Err(_) => {
                warn!("Fingerprint verification reply channel dropped, treating as rejection");
                self.reject_fingerprint(
                    &source,
                    "Verification cancelled (reply dropped)",
                    notification_tx,
                )
                .await;
                Ok(Vec::new())
            }
        }
    }

    /// Reject a fingerprint verification: discard buffered messages, audit, and notify.
    async fn reject_fingerprint(
        &mut self,
        source: &IdentityFingerprint,
        reason: &str,
        notification_tx: &mpsc::Sender<UserClientNotification>,
    ) {
        self.pending_pairings.take_buffered_messages(source);

        self.audit_log
            .write(AuditEvent::ConnectionRejected {
                remote_identity: source,
            })
            .await;

        notify!(
            notification_tx,
            UserClientNotification::FingerprintRejected {
                reason: reason.to_string(),
            }
        );
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
    ) -> Result<(), ClientError> {
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
            .ok_or(ClientError::SecureChannelNotEstablished)?;

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
            .map_err(|e| ClientError::NoiseProtocol(e.to_string()))?;

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

            notify!(
                notification_tx,
                UserClientNotification::CredentialApproved {
                    domain,
                    credential_id: reply.credential_id,
                }
            );
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

            notify!(
                notification_tx,
                UserClientNotification::CredentialDenied {
                    domain,
                    credential_id: reply.credential_id,
                }
            );
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
    ) -> Result<(MultiDeviceTransport, String), ClientError> {
        // Parse ciphersuite
        let ciphersuite = match ciphersuite_str {
            s if s.contains("Kyber768") => Ciphersuite::PQNNpsk2_Kyber768_XChaCha20Poly1305,
            _ => Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035,
        };

        // Decode handshake data
        let init_bytes = STANDARD
            .decode(handshake_data)
            .map_err(|e| ClientError::Serialization(format!("Invalid base64: {e}")))?;

        let init_packet = ap_noise::HandshakePacket::decode(&init_bytes)
            .map_err(|e| ClientError::NoiseProtocol(format!("Invalid packet: {e}")))?;

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
