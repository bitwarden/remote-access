use std::time::Duration;

use ap_noise::{InitiatorHandshake, MultiDeviceTransport, Psk};
use ap_proxy_client::IncomingMessage;
use ap_proxy_protocol::{IdentityFingerprint, RendezvousCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::RngCore;

use crate::compat::{now_millis, timeout};
use crate::proxy::ProxyClient;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use crate::traits::{IdentityProvider, SessionStore};
use crate::{
    error::RemoteClientError,
    types::{
        CredentialData, CredentialQuery, CredentialRequestPayload, CredentialResponsePayload,
        ProtocolMessage,
    },
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

// =============================================================================
// Public types: Notifications (fire-and-forget) and Requests (with reply)
// =============================================================================

/// Fire-and-forget status updates emitted by the remote client.
#[derive(Debug, Clone)]
pub enum RemoteClientNotification {
    /// Connecting to the proxy server
    Connecting,
    /// Successfully connected to the proxy
    Connected {
        /// The device's identity fingerprint (hex-encoded)
        fingerprint: IdentityFingerprint,
    },
    /// Reconnecting to an existing session
    ReconnectingToSession {
        /// The fingerprint being reconnected to
        fingerprint: IdentityFingerprint,
    },
    /// Rendezvous code resolution starting
    RendezvousResolving {
        /// The rendezvous code being resolved
        code: String,
    },
    /// Rendezvous code resolved to fingerprint
    RendezvousResolved {
        /// The resolved identity fingerprint
        fingerprint: IdentityFingerprint,
    },
    /// Using PSK mode for connection
    PskMode {
        /// The fingerprint being connected to
        fingerprint: IdentityFingerprint,
    },
    /// Noise handshake starting
    HandshakeStart,
    /// Noise handshake progress
    HandshakeProgress {
        /// Progress message
        message: String,
    },
    /// Noise handshake complete
    HandshakeComplete,
    /// Handshake fingerprint (informational — for PSK or non-verified connections)
    HandshakeFingerprint {
        /// The 6-character hex fingerprint
        fingerprint: String,
    },
    /// User verified the fingerprint
    FingerprintVerified,
    /// User rejected the fingerprint
    FingerprintRejected {
        /// Reason for rejection
        reason: String,
    },
    /// Client is ready for credential requests
    Ready {
        /// Whether credentials can be requested
        can_request_credentials: bool,
    },
    /// Credential request was sent
    CredentialRequestSent {
        /// The query used for the request
        query: CredentialQuery,
    },
    /// Credential was received
    CredentialReceived {
        /// The credential data
        credential: CredentialData,
    },
    /// An error occurred
    Error {
        /// Error message
        message: String,
        /// Context where error occurred
        context: Option<String>,
    },
    /// Client was disconnected
    Disconnected {
        /// Reason for disconnection
        reason: Option<String>,
    },
}

/// Reply for fingerprint verification requests.
#[derive(Debug)]
pub struct RemoteClientFingerprintReply {
    /// Whether user approved the fingerprint
    pub approved: bool,
}

/// Requests that require a caller response, carrying a oneshot reply channel.
#[derive(Debug)]
pub enum RemoteClientRequest {
    /// Handshake fingerprint requires verification.
    VerifyFingerprint {
        /// The 6-character hex fingerprint for visual verification
        fingerprint: String,
        /// Channel to send the verification reply
        reply: oneshot::Sender<RemoteClientFingerprintReply>,
    },
}

// =============================================================================
// Command channel for RemoteClient handle → event loop communication
// =============================================================================

/// Type alias matching `SessionStore::list_sessions()` return type.
type SessionList = Vec<(IdentityFingerprint, Option<String>, u64, u64)>;

/// Commands sent from a `RemoteClient` handle to the running event loop.
enum RemoteClientCommand {
    PairWithHandshake {
        rendezvous_code: String,
        verify_fingerprint: bool,
        reply: oneshot::Sender<Result<IdentityFingerprint, RemoteClientError>>,
    },
    PairWithPsk {
        psk: Psk,
        remote_fingerprint: IdentityFingerprint,
        reply: oneshot::Sender<Result<(), RemoteClientError>>,
    },
    LoadCachedSession {
        remote_fingerprint: IdentityFingerprint,
        reply: oneshot::Sender<Result<(), RemoteClientError>>,
    },
    RequestCredential {
        query: CredentialQuery,
        reply: oneshot::Sender<Result<CredentialData, RemoteClientError>>,
    },
    ListSessions {
        reply: oneshot::Sender<SessionList>,
    },
    HasSession {
        fingerprint: IdentityFingerprint,
        reply: oneshot::Sender<bool>,
    },
}

// =============================================================================
// Handle — cloneable, Send, all methods take &self
// =============================================================================

/// A cloneable handle for controlling the remote client.
///
/// Obtained from [`RemoteClient::connect()`], which authenticates with the proxy,
/// spawns the event loop internally, and returns this handle. All methods
/// communicate with the event loop through an internal command channel.
///
/// `Clone` and `Send` — share freely across tasks and threads.
/// Dropping all handles shuts down the event loop and disconnects from the proxy.
#[derive(Clone)]
pub struct RemoteClient {
    command_tx: mpsc::Sender<RemoteClientCommand>,
}

impl RemoteClient {
    /// Connect to the proxy server, spawn the event loop, and return a handle.
    ///
    /// This is the single entry point. After `connect()` returns, the client is
    /// authenticated with the proxy and ready for pairing. Use one of the pairing
    /// methods to establish a secure channel:
    /// - [`pair_with_handshake()`](Self::pair_with_handshake) for rendezvous-based pairing
    /// - [`pair_with_psk()`](Self::pair_with_psk) for PSK-based pairing
    /// - [`load_cached_session()`](Self::load_cached_session) for reconnecting with a cached session
    pub async fn connect(
        identity_provider: Box<dyn IdentityProvider>,
        session_store: Box<dyn SessionStore>,
        mut proxy_client: Box<dyn ProxyClient>,
        notification_tx: mpsc::Sender<RemoteClientNotification>,
        request_tx: mpsc::Sender<RemoteClientRequest>,
    ) -> Result<Self, RemoteClientError> {
        let own_fingerprint = identity_provider.fingerprint().await;

        debug!("Connecting to proxy with identity {:?}", own_fingerprint);

        notification_tx
            .send(RemoteClientNotification::Connecting)
            .await
            .ok();

        let incoming_rx = proxy_client.connect().await?;

        notification_tx
            .send(RemoteClientNotification::Connected {
                fingerprint: own_fingerprint,
            })
            .await
            .ok();

        debug!("Connected to proxy successfully");

        // Create command channel
        let (command_tx, command_rx) = mpsc::channel(32);

        // Build inner state
        let inner = RemoteClientInner {
            session_store,
            proxy_client,
            transport: None,
            remote_fingerprint: None,
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

    /// Pair with a remote device using a rendezvous code.
    ///
    /// Resolves the rendezvous code to a fingerprint, performs the Noise handshake,
    /// and optionally waits for user fingerprint verification. If `verify_fingerprint`
    /// is true, a [`RemoteClientRequest::VerifyFingerprint`] will be sent on the
    /// request channel and must be answered before this method returns.
    pub async fn pair_with_handshake(
        &self,
        rendezvous_code: String,
        verify_fingerprint: bool,
    ) -> Result<IdentityFingerprint, RemoteClientError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(RemoteClientCommand::PairWithHandshake {
                rendezvous_code,
                verify_fingerprint,
                reply: tx,
            })
            .await
            .map_err(|_| RemoteClientError::ChannelClosed)?;
        rx.await.map_err(|_| RemoteClientError::ChannelClosed)?
    }

    /// Pair with a remote device using a pre-shared key.
    ///
    /// Uses the PSK for authentication, skipping fingerprint verification
    /// since trust is established through the PSK.
    pub async fn pair_with_psk(
        &self,
        psk: Psk,
        remote_fingerprint: IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(RemoteClientCommand::PairWithPsk {
                psk,
                remote_fingerprint,
                reply: tx,
            })
            .await
            .map_err(|_| RemoteClientError::ChannelClosed)?;
        rx.await.map_err(|_| RemoteClientError::ChannelClosed)?
    }

    /// Reconnect to a remote device using a cached session.
    ///
    /// Verifies the session exists in the session store and reconnects
    /// without requiring fingerprint verification.
    pub async fn load_cached_session(
        &self,
        remote_fingerprint: IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(RemoteClientCommand::LoadCachedSession {
                remote_fingerprint,
                reply: tx,
            })
            .await
            .map_err(|_| RemoteClientError::ChannelClosed)?;
        rx.await.map_err(|_| RemoteClientError::ChannelClosed)?
    }

    /// Request a credential over the secure channel.
    pub async fn request_credential(
        &self,
        query: &CredentialQuery,
    ) -> Result<CredentialData, RemoteClientError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(RemoteClientCommand::RequestCredential {
                query: query.clone(),
                reply: tx,
            })
            .await
            .map_err(|_| RemoteClientError::ChannelClosed)?;
        rx.await.map_err(|_| RemoteClientError::ChannelClosed)?
    }

    /// List all cached sessions.
    pub async fn list_sessions(
        &self,
    ) -> Result<Vec<(IdentityFingerprint, Option<String>, u64, u64)>, RemoteClientError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(RemoteClientCommand::ListSessions { reply: tx })
            .await
            .map_err(|_| RemoteClientError::ChannelClosed)?;
        rx.await.map_err(|_| RemoteClientError::ChannelClosed)
    }

    /// Check if a session exists for a fingerprint.
    pub async fn has_session(
        &self,
        fingerprint: IdentityFingerprint,
    ) -> Result<bool, RemoteClientError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(RemoteClientCommand::HasSession {
                fingerprint,
                reply: tx,
            })
            .await
            .map_err(|_| RemoteClientError::ChannelClosed)?;
        rx.await.map_err(|_| RemoteClientError::ChannelClosed)
    }
}

// =============================================================================
// Internal state — lives inside the spawned event loop task
// =============================================================================

/// All mutable state for the remote client, owned by the spawned event loop task.
struct RemoteClientInner {
    session_store: Box<dyn SessionStore>,
    proxy_client: Box<dyn ProxyClient>,
    transport: Option<MultiDeviceTransport>,
    remote_fingerprint: Option<IdentityFingerprint>,
}

impl RemoteClientInner {
    /// Run the main event loop (consumes self).
    async fn run_event_loop(
        mut self,
        mut incoming_rx: mpsc::UnboundedReceiver<IncomingMessage>,
        mut command_rx: mpsc::Receiver<RemoteClientCommand>,
        notification_tx: mpsc::Sender<RemoteClientNotification>,
        request_tx: mpsc::Sender<RemoteClientRequest>,
    ) {
        loop {
            tokio::select! {
                msg = incoming_rx.recv() => {
                    match msg {
                        Some(_) => {
                            // Stray message while idle — ignore
                            debug!("Received message while idle");
                        }
                        None => {
                            // Proxy disconnected
                            notification_tx.send(RemoteClientNotification::Disconnected {
                                reason: Some("Proxy connection closed".to_string()),
                            }).await.ok();
                            return;
                        }
                    }
                }
                cmd = command_rx.recv() => {
                    match cmd {
                        Some(cmd) => {
                            self.handle_command(
                                cmd,
                                &mut incoming_rx,
                                &notification_tx,
                                &request_tx,
                            ).await;
                        }
                        None => {
                            // All handles dropped — shut down
                            debug!("All RemoteClient handles dropped, shutting down event loop");
                            self.proxy_client.disconnect().await.ok();
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Dispatch a command from the handle.
    async fn handle_command(
        &mut self,
        cmd: RemoteClientCommand,
        incoming_rx: &mut mpsc::UnboundedReceiver<IncomingMessage>,
        notification_tx: &mpsc::Sender<RemoteClientNotification>,
        request_tx: &mpsc::Sender<RemoteClientRequest>,
    ) {
        match cmd {
            RemoteClientCommand::PairWithHandshake {
                rendezvous_code,
                verify_fingerprint,
                reply,
            } => {
                let result = self
                    .do_pair_with_handshake(
                        rendezvous_code,
                        verify_fingerprint,
                        incoming_rx,
                        notification_tx,
                        request_tx,
                    )
                    .await;
                let _ = reply.send(result);
            }
            RemoteClientCommand::PairWithPsk {
                psk,
                remote_fingerprint,
                reply,
            } => {
                let result = self
                    .do_pair_with_psk(psk, remote_fingerprint, incoming_rx, notification_tx)
                    .await;
                let _ = reply.send(result);
            }
            RemoteClientCommand::LoadCachedSession {
                remote_fingerprint,
                reply,
            } => {
                let result = self
                    .do_load_cached_session(remote_fingerprint, notification_tx)
                    .await;
                let _ = reply.send(result);
            }
            RemoteClientCommand::RequestCredential { query, reply } => {
                let result = self
                    .do_request_credential(query, incoming_rx, notification_tx)
                    .await;
                let _ = reply.send(result);
            }
            RemoteClientCommand::ListSessions { reply } => {
                let sessions = self.session_store.list_sessions().await;
                let _ = reply.send(sessions);
            }
            RemoteClientCommand::HasSession { fingerprint, reply } => {
                let has = self.session_store.has_session(&fingerprint).await;
                let _ = reply.send(has);
            }
        }
    }

    // ── Pairing: Rendezvous handshake ────────────────────────────────

    async fn do_pair_with_handshake(
        &mut self,
        rendezvous_code: String,
        verify_fingerprint: bool,
        incoming_rx: &mut mpsc::UnboundedReceiver<IncomingMessage>,
        notification_tx: &mpsc::Sender<RemoteClientNotification>,
        request_tx: &mpsc::Sender<RemoteClientRequest>,
    ) -> Result<IdentityFingerprint, RemoteClientError> {
        // Resolve rendezvous code to fingerprint
        notification_tx
            .send(RemoteClientNotification::RendezvousResolving {
                code: rendezvous_code.clone(),
            })
            .await
            .ok();

        let remote_fingerprint =
            Self::resolve_rendezvous(self.proxy_client.as_ref(), incoming_rx, &rendezvous_code)
                .await?;

        notification_tx
            .send(RemoteClientNotification::RendezvousResolved {
                fingerprint: remote_fingerprint,
            })
            .await
            .ok();

        // Perform Noise handshake (no PSK)
        notification_tx
            .send(RemoteClientNotification::HandshakeStart)
            .await
            .ok();

        let (transport, fingerprint_str) = Self::perform_handshake(
            self.proxy_client.as_ref(),
            incoming_rx,
            remote_fingerprint,
            None,
        )
        .await?;

        notification_tx
            .send(RemoteClientNotification::HandshakeComplete)
            .await
            .ok();

        // Always emit fingerprint (informational or for verification)
        notification_tx
            .send(RemoteClientNotification::HandshakeFingerprint {
                fingerprint: fingerprint_str.clone(),
            })
            .await
            .ok();

        if verify_fingerprint {
            // Send verification request via request channel
            let (fp_tx, fp_rx) = oneshot::channel();
            request_tx
                .send(RemoteClientRequest::VerifyFingerprint {
                    fingerprint: fingerprint_str,
                    reply: fp_tx,
                })
                .await
                .map_err(|_| RemoteClientError::ChannelClosed)?;

            // Wait for user verification (60s timeout)
            match timeout(Duration::from_secs(60), fp_rx).await {
                Ok(Ok(RemoteClientFingerprintReply { approved: true })) => {
                    notification_tx
                        .send(RemoteClientNotification::FingerprintVerified)
                        .await
                        .ok();
                }
                Ok(Ok(RemoteClientFingerprintReply { approved: false })) => {
                    self.proxy_client.disconnect().await.ok();
                    notification_tx
                        .send(RemoteClientNotification::FingerprintRejected {
                            reason: "User rejected fingerprint verification".to_string(),
                        })
                        .await
                        .ok();
                    return Err(RemoteClientError::FingerprintRejected);
                }
                Ok(Err(_)) => {
                    return Err(RemoteClientError::ChannelClosed);
                }
                Err(_) => {
                    self.proxy_client.disconnect().await.ok();
                    return Err(RemoteClientError::Timeout(
                        "Fingerprint verification timeout".to_string(),
                    ));
                }
            }
        }

        // Finalize connection
        self.finalize_pairing(transport, remote_fingerprint, notification_tx)
            .await?;

        Ok(remote_fingerprint)
    }

    // ── Pairing: PSK ─────────────────────────────────────────────────

    async fn do_pair_with_psk(
        &mut self,
        psk: Psk,
        remote_fingerprint: IdentityFingerprint,
        incoming_rx: &mut mpsc::UnboundedReceiver<IncomingMessage>,
        notification_tx: &mpsc::Sender<RemoteClientNotification>,
    ) -> Result<(), RemoteClientError> {
        notification_tx
            .send(RemoteClientNotification::PskMode {
                fingerprint: remote_fingerprint,
            })
            .await
            .ok();

        // Perform Noise handshake with PSK
        notification_tx
            .send(RemoteClientNotification::HandshakeStart)
            .await
            .ok();

        let (transport, _fingerprint_str) = Self::perform_handshake(
            self.proxy_client.as_ref(),
            incoming_rx,
            remote_fingerprint,
            Some(psk),
        )
        .await?;

        notification_tx
            .send(RemoteClientNotification::HandshakeComplete)
            .await
            .ok();

        // Skip fingerprint verification (trust via PSK)
        notification_tx
            .send(RemoteClientNotification::FingerprintVerified)
            .await
            .ok();

        // Finalize connection
        self.finalize_pairing(transport, remote_fingerprint, notification_tx)
            .await?;

        Ok(())
    }

    // ── Cached session reconnection ──────────────────────────────────

    async fn do_load_cached_session(
        &mut self,
        remote_fingerprint: IdentityFingerprint,
        notification_tx: &mpsc::Sender<RemoteClientNotification>,
    ) -> Result<(), RemoteClientError> {
        if !self.session_store.has_session(&remote_fingerprint).await {
            return Err(RemoteClientError::SessionNotFound);
        }

        notification_tx
            .send(RemoteClientNotification::ReconnectingToSession {
                fingerprint: remote_fingerprint,
            })
            .await
            .ok();

        let transport = self
            .session_store
            .load_transport_state(&remote_fingerprint)
            .await?
            .ok_or(RemoteClientError::SessionNotFound)?;

        notification_tx
            .send(RemoteClientNotification::HandshakeComplete)
            .await
            .ok();

        // Skip fingerprint verification (already trusted)
        notification_tx
            .send(RemoteClientNotification::FingerprintVerified)
            .await
            .ok();

        // Update last_connected_at
        self.session_store
            .update_last_connected(&remote_fingerprint)
            .await?;

        // Save transport state and store locally
        self.session_store
            .save_transport_state(&remote_fingerprint, transport.clone())
            .await?;

        self.transport = Some(transport);
        self.remote_fingerprint = Some(remote_fingerprint);

        notification_tx
            .send(RemoteClientNotification::Ready {
                can_request_credentials: true,
            })
            .await
            .ok();

        debug!("Reconnected to cached session");
        Ok(())
    }

    // ── Shared pairing finalization ──────────────────────────────────

    async fn finalize_pairing(
        &mut self,
        transport: MultiDeviceTransport,
        remote_fingerprint: IdentityFingerprint,
        notification_tx: &mpsc::Sender<RemoteClientNotification>,
    ) -> Result<(), RemoteClientError> {
        // Cache session
        self.session_store.cache_session(remote_fingerprint).await?;

        // Save transport state for session resumption
        self.session_store
            .save_transport_state(&remote_fingerprint, transport.clone())
            .await?;

        // Store transport and remote fingerprint
        self.transport = Some(transport);
        self.remote_fingerprint = Some(remote_fingerprint);

        // Emit Ready event
        notification_tx
            .send(RemoteClientNotification::Ready {
                can_request_credentials: true,
            })
            .await
            .ok();

        debug!("Connection established successfully");
        Ok(())
    }

    // ── Credential request ───────────────────────────────────────────

    async fn do_request_credential(
        &mut self,
        query: CredentialQuery,
        incoming_rx: &mut mpsc::UnboundedReceiver<IncomingMessage>,
        notification_tx: &mpsc::Sender<RemoteClientNotification>,
    ) -> Result<CredentialData, RemoteClientError> {
        let remote_fingerprint = self
            .remote_fingerprint
            .ok_or(RemoteClientError::NotInitialized)?;

        // Sliced string is a UUID and isn't going to contain wide chars
        #[allow(clippy::string_slice)]
        let request_id = format!("req-{}-{}", now_millis(), &uuid_v4()[..8]);

        debug!("Requesting credential for query: {:?}", query);

        // Create and encrypt request
        let request = CredentialRequestPayload {
            request_type: "credential_request".to_string(),
            query: query.clone(),
            timestamp: now_millis(),
            request_id: request_id.clone(),
        };

        let request_json = serde_json::to_string(&request)?;

        let encrypted_data = {
            let transport = self
                .transport
                .as_mut()
                .ok_or(RemoteClientError::SecureChannelNotEstablished)?;
            let encrypted_packet = transport
                .encrypt(request_json.as_bytes())
                .map_err(|e| RemoteClientError::NoiseProtocol(e.to_string()))?;
            STANDARD.encode(encrypted_packet.encode())
        };

        let msg = ProtocolMessage::CredentialRequest {
            encrypted: encrypted_data,
        };

        // Send via proxy
        let msg_json = serde_json::to_string(&msg)?;
        self.proxy_client
            .send_to(remote_fingerprint, msg_json.into_bytes())
            .await?;

        // Emit event
        notification_tx
            .send(RemoteClientNotification::CredentialRequestSent {
                query: query.clone(),
            })
            .await
            .ok();

        // Wait for matching response inline
        match timeout(
            DEFAULT_TIMEOUT,
            self.receive_credential_response(&request_id, incoming_rx, notification_tx),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(RemoteClientError::Timeout(format!(
                "Timeout waiting for credential response for query: {query:?}"
            ))),
        }
    }

    /// Wait for a credential response matching the given request_id.
    ///
    /// Stale responses from previous requests (e.g. duplicate multi-device
    /// responses) are decrypted, logged, and silently discarded.
    async fn receive_credential_response(
        &mut self,
        request_id: &str,
        incoming_rx: &mut mpsc::UnboundedReceiver<IncomingMessage>,
        notification_tx: &mpsc::Sender<RemoteClientNotification>,
    ) -> Result<CredentialData, RemoteClientError> {
        loop {
            match incoming_rx.recv().await {
                Some(IncomingMessage::Send { payload, .. }) => {
                    if let Ok(text) = String::from_utf8(payload)
                        && let Ok(ProtocolMessage::CredentialResponse { encrypted }) =
                            serde_json::from_str::<ProtocolMessage>(&text)
                    {
                        match self
                            .decrypt_credential_response(&encrypted, request_id, notification_tx)
                            .await
                        {
                            Ok(credential) => return Ok(credential),
                            Err(RemoteClientError::CredentialRequestFailed(ref msg))
                                if msg.contains("request_id mismatch") =>
                            {
                                // Stale response from a previous request — skip it
                                debug!("Skipping stale credential response: {msg}");
                                continue;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
                Some(_) => {
                    // Non-Send messages (RendezvousInfo, IdentityInfo) — ignore
                }
                None => {
                    return Err(RemoteClientError::ChannelClosed);
                }
            }
        }
    }

    /// Decrypt and validate a credential response.
    async fn decrypt_credential_response(
        &mut self,
        encrypted: &str,
        request_id: &str,
        notification_tx: &mpsc::Sender<RemoteClientNotification>,
    ) -> Result<CredentialData, RemoteClientError> {
        let encrypted_bytes = STANDARD
            .decode(encrypted)
            .map_err(|e| RemoteClientError::Serialization(format!("Invalid base64: {e}")))?;

        let packet = ap_noise::TransportPacket::decode(&encrypted_bytes)
            .map_err(|e| RemoteClientError::NoiseProtocol(format!("Invalid packet: {e}")))?;

        let transport = self
            .transport
            .as_mut()
            .ok_or(RemoteClientError::SecureChannelNotEstablished)?;

        let decrypted = transport
            .decrypt(&packet)
            .map_err(|e| RemoteClientError::NoiseProtocol(e.to_string()))?;

        let response: CredentialResponsePayload = serde_json::from_slice(&decrypted)?;

        // Verify request_id matches
        if response.request_id.as_deref() != Some(request_id) {
            warn!(
                "Ignoring response with mismatched request_id: {:?}",
                response.request_id
            );
            return Err(RemoteClientError::CredentialRequestFailed(
                "Response request_id mismatch".to_string(),
            ));
        }

        if let Some(error) = response.error {
            return Err(RemoteClientError::CredentialRequestFailed(error));
        }

        if let Some(credential) = response.credential {
            notification_tx
                .send(RemoteClientNotification::CredentialReceived {
                    credential: credential.clone(),
                })
                .await
                .ok();
            Ok(credential)
        } else {
            Err(RemoteClientError::CredentialRequestFailed(
                "Response contains neither credential nor error".to_string(),
            ))
        }
    }

    // ── Handshake helpers (associated functions) ─────────────────────

    /// Resolve rendezvous code to identity fingerprint.
    async fn resolve_rendezvous(
        proxy_client: &dyn ProxyClient,
        incoming_rx: &mut mpsc::UnboundedReceiver<IncomingMessage>,
        rendezvous_code: &str,
    ) -> Result<IdentityFingerprint, RemoteClientError> {
        // Send GetIdentity request
        proxy_client
            .request_identity(RendezvousCode::from_string(rendezvous_code.to_string()))
            .await
            .map_err(|e| RemoteClientError::RendezvousResolutionFailed(e.to_string()))?;

        // Wait for IdentityInfo response with timeout
        let timeout_duration = Duration::from_secs(10);
        match timeout(timeout_duration, async {
            while let Some(msg) = incoming_rx.recv().await {
                if let IncomingMessage::IdentityInfo { fingerprint, .. } = msg {
                    return Some(fingerprint);
                }
            }
            None
        })
        .await
        {
            Ok(Some(fingerprint)) => Ok(fingerprint),
            Ok(None) => Err(RemoteClientError::RendezvousResolutionFailed(
                "Connection closed while waiting for identity response".to_string(),
            )),
            Err(_) => Err(RemoteClientError::RendezvousResolutionFailed(
                "Timeout waiting for identity response. The rendezvous code may be invalid, expired, or the target client may be disconnected.".to_string(),
            )),
        }
    }

    /// Perform Noise handshake as initiator.
    async fn perform_handshake(
        proxy_client: &dyn ProxyClient,
        incoming_rx: &mut mpsc::UnboundedReceiver<IncomingMessage>,
        remote_fingerprint: IdentityFingerprint,
        psk: Option<Psk>,
    ) -> Result<(MultiDeviceTransport, String), RemoteClientError> {
        // Compute PSK ID before moving the PSK into the handshake
        let psk_id = psk.as_ref().map(|p| p.id());

        // Create initiator handshake (with or without PSK)
        let mut handshake = if let Some(psk) = psk {
            InitiatorHandshake::with_psk(psk)
        } else {
            InitiatorHandshake::new()
        };

        // Generate handshake init
        let init_packet = handshake.send_start()?;

        // Send HandshakeInit message
        let msg = ProtocolMessage::HandshakeInit {
            data: STANDARD.encode(init_packet.encode()?),
            ciphersuite: format!("{:?}", handshake.ciphersuite()),
            psk_id,
        };

        let msg_json = serde_json::to_string(&msg)?;
        proxy_client
            .send_to(remote_fingerprint, msg_json.into_bytes())
            .await?;

        debug!("Sent handshake init");

        // Wait for HandshakeResponse
        let response_timeout = Duration::from_secs(10);
        let response: String = timeout(response_timeout, async {
            loop {
                if let Some(incoming) = incoming_rx.recv().await {
                    match incoming {
                        IncomingMessage::Send { payload, .. } => {
                            // Try to parse as ProtocolMessage
                            if let Ok(text) = String::from_utf8(payload)
                                && let Ok(ProtocolMessage::HandshakeResponse { data, .. }) =
                                    serde_json::from_str::<ProtocolMessage>(&text)
                            {
                                return Ok::<String, RemoteClientError>(data);
                            }
                        }
                        _ => continue,
                    }
                }
            }
        })
        .await
        .map_err(|_| RemoteClientError::Timeout("Waiting for handshake response".to_string()))??;

        // Decode and process response
        let response_bytes = STANDARD
            .decode(&response)
            .map_err(|e| RemoteClientError::Serialization(format!("Invalid base64: {e}")))?;

        let response_packet = ap_noise::HandshakePacket::decode(&response_bytes)
            .map_err(|e| RemoteClientError::NoiseProtocol(format!("Invalid packet: {e}")))?;

        // Complete handshake
        handshake.receive_finish(&response_packet)?;
        let (transport, fingerprint) = handshake.finalize()?;

        debug!("Handshake complete");
        Ok((transport, fingerprint.to_string()))
    }
}

fn uuid_v4() -> String {
    // Simple UUID v4 generation without external dependency
    let mut bytes = [0u8; 16];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut bytes);

    // Set version (4) and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}
