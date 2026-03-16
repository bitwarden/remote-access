use std::collections::HashMap;
use std::time::Duration;

use ap_noise::{Ciphersuite, MultiDeviceTransport, Psk, ResponderHandshake};
use ap_proxy_client::IncomingMessage;
use ap_proxy_protocol::{IdentityFingerprint, RendevouzCode};
use base64::{Engine, engine::general_purpose::STANDARD};

use crate::proxy::ProxyClient;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Base delay for reconnection backoff.
const RECONNECT_BASE_DELAY: Duration = Duration::from_secs(2);
/// Maximum delay between reconnection attempts (15 minutes).
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(15 * 60);

/// Holds the state of a handshake pending fingerprint verification
struct PendingHandshakeVerification {
    /// The remote device's fingerprint
    source: IdentityFingerprint,
    /// The established transport (not yet cached)
    transport: MultiDeviceTransport,
}

use crate::{
    error::RemoteClientError,
    traits::{
        AuditConnectionType, AuditEvent, AuditLog, CredentialFieldSet, IdentityProvider,
        NoOpAuditLog, SessionStore,
    },
    types::ProtocolMessage,
};

/// Events emitted by the user client during operation
#[derive(Debug, Clone)]
pub enum UserClientEvent {
    /// Started listening for connections
    Listening {},
    /// Rendezvous code was generated
    RendevouzCodeGenerated {
        /// The 8-character rendezvous code to share
        code: String,
    },
    /// PSK token was generated
    PskTokenGenerated {
        /// The PSK token to share (format: <psk_hex>_<fingerprint_hex>)
        token: String,
    },
    /// Noise handshake started
    HandshakeStart {},
    /// Noise handshake progress
    HandshakeProgress {
        /// Progress message
        message: String,
    },
    /// Noise handshake complete
    HandshakeComplete {},
    /// Handshake fingerprint requires verification
    HandshakeFingerprint {
        /// The 6-character hex fingerprint
        fingerprint: String,
    },
    /// Fingerprint was verified and connection accepted
    FingerprintVerified {},
    /// Fingerprint was rejected and connection discarded
    FingerprintRejected {
        /// Reason for rejection
        reason: String,
    },
    /// Credential request received
    CredentialRequest {
        /// Domain being requested
        domain: String,
        /// Request ID
        request_id: String,
        /// Session ID for routing responses (fingerprint)
        session_id: String,
    },
    /// Credential was approved and sent
    CredentialApproved {
        /// Domain
        domain: String,
        /// Vault item ID
        credential_id: Option<String>,
    },
    /// Credential was denied
    CredentialDenied {
        /// Domain
        domain: String,
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

/// Response actions for events requiring user decision
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum UserClientResponse {
    /// Respond to fingerprint verification prompt
    VerifyFingerprint {
        /// Whether user approved the fingerprint
        approved: bool,
        /// Optional friendly name to assign to the session
        name: Option<String>,
    },
    /// Respond to a credential request
    RespondCredential {
        /// Request ID
        request_id: String,
        /// Session ID for routing to correct transport (fingerprint)
        session_id: String,
        /// The requested domain
        domain: String,
        /// Whether approved
        approved: bool,
        /// The credential to send (if approved)
        credential: Option<CredentialData>,
        /// Vault item ID (for audit logging)
        credential_id: Option<String>,
    },
}

/// Credential data to send to remote client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialData {
    /// Username for the credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password for the credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// TOTP code if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    /// URI associated with the credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Additional notes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Vault item ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
}

/// Credential request payload (decrypted)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialRequestPayload {
    #[serde(rename = "type")]
    request_type: Option<String>,
    domain: String,
    timestamp: Option<u64>,
    #[serde(rename = "requestId")]
    request_id: String,
}

/// Credential response payload (to be encrypted)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialResponsePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<CredentialData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(rename = "requestId")]
    request_id: String,
}

/// User client for acting as trusted device
pub struct UserClient {
    identity_provider: Box<dyn IdentityProvider>,
    session_store: Box<dyn SessionStore>,
    proxy_client: Option<Box<dyn ProxyClient>>,
    /// Map of fingerprint -> transport
    transports: HashMap<IdentityFingerprint, MultiDeviceTransport>,
    /// Current rendezvous code
    rendezvous_code: Option<RendevouzCode>,
    /// Current PSK (if in PSK mode)
    psk: Option<Psk>,
    /// Incoming message receiver from proxy
    incoming_rx: Option<mpsc::UnboundedReceiver<IncomingMessage>>,
    /// Pending handshake awaiting fingerprint verification
    pending_verification: Option<PendingHandshakeVerification>,
    /// Name to assign to the next newly-paired session
    pending_session_name: Option<String>,
    /// Audit logger for security-relevant events
    audit_log: Box<dyn AuditLog>,
}

impl UserClient {
    /// Connect to proxy server and return a connected client
    ///
    /// This is an associated function (constructor) that:
    /// - Creates the client with provided identity provider and session store
    /// - Connects to the proxy server
    /// - Returns a connected client ready for `enable_psk` or `enable_rendezvous`
    pub async fn listen(
        identity_provider: Box<dyn IdentityProvider>,
        session_store: Box<dyn SessionStore>,
        mut proxy_client: Box<dyn ProxyClient>,
    ) -> Result<Self, RemoteClientError> {
        let incoming_rx = proxy_client.connect().await?;

        Ok(Self {
            identity_provider,
            session_store,
            proxy_client: Some(proxy_client),
            transports: HashMap::new(),
            rendezvous_code: None,
            psk: None,
            incoming_rx: Some(incoming_rx),
            pending_verification: None,
            pending_session_name: None,
            audit_log: Box::new(NoOpAuditLog),
        })
    }

    /// Set a custom audit logger. If not called, a no-op logger is used.
    pub fn with_audit_log(mut self, audit_log: Box<dyn AuditLog>) -> Self {
        self.audit_log = audit_log;
        self
    }

    /// Listen for cached sessions only (no new pairing code generated)
    ///
    /// Emits a Listening event and runs the event loop. Cached sessions can
    /// still reconnect via the normal handshake/credential request flow.
    pub async fn listen_cached_only(
        &mut self,
        event_tx: mpsc::Sender<UserClientEvent>,
        response_rx: mpsc::Receiver<UserClientResponse>,
    ) -> Result<(), RemoteClientError> {
        debug!("User client listening for cached sessions only (no new pairing code)");

        // Emit Listening event
        event_tx.send(UserClientEvent::Listening {}).await.ok();

        // Run event loop
        self.run_event_loop(event_tx, response_rx).await
    }

    /// Enable PSK mode and run the event loop
    ///
    /// Generates a PSK and token, emits events, and runs the main event loop.
    pub async fn enable_psk(
        &mut self,
        event_tx: mpsc::Sender<UserClientEvent>,
        response_rx: mpsc::Receiver<UserClientResponse>,
    ) -> Result<(), RemoteClientError> {
        // Generate PSK and token
        let psk = Psk::generate();
        let fingerprint = self.identity_provider.fingerprint();
        let token = format!("{}_{}", psk.to_hex(), hex::encode(fingerprint.0));

        self.psk = Some(psk);

        event_tx
            .send(UserClientEvent::PskTokenGenerated { token })
            .await
            .ok();

        debug!("User client listening in PSK mode");

        // Emit Listening event
        event_tx.send(UserClientEvent::Listening {}).await.ok();

        // Run event loop
        self.run_event_loop(event_tx, response_rx).await
    }

    /// Enable rendezvous mode and run the event loop
    ///
    /// Requests a rendezvous code from the proxy, emits events, and runs the main event loop.
    pub async fn enable_rendezvous(
        &mut self,
        event_tx: mpsc::Sender<UserClientEvent>,
        response_rx: mpsc::Receiver<UserClientResponse>,
    ) -> Result<(), RemoteClientError> {
        let proxy_client = self
            .proxy_client
            .as_ref()
            .ok_or(RemoteClientError::NotInitialized)?;

        // Request rendezvous code
        proxy_client.request_rendezvous().await?;

        // Wait for rendezvous code
        let incoming_rx = self
            .incoming_rx
            .as_mut()
            .ok_or(RemoteClientError::NotInitialized)?;

        let code = loop {
            if let Some(IncomingMessage::RendevouzInfo(c)) = incoming_rx.recv().await {
                break c;
            }
        };

        self.rendezvous_code = Some(code.clone());

        event_tx
            .send(UserClientEvent::RendevouzCodeGenerated {
                code: code.as_str().to_string(),
            })
            .await
            .ok();

        debug!("User client listening with rendezvous code: {}", code);

        // Emit Listening event
        event_tx.send(UserClientEvent::Listening {}).await.ok();

        // Run event loop
        self.run_event_loop(event_tx, response_rx).await
    }

    /// Run the main event loop
    async fn run_event_loop(
        &mut self,
        event_tx: mpsc::Sender<UserClientEvent>,
        mut response_rx: mpsc::Receiver<UserClientResponse>,
    ) -> Result<(), RemoteClientError> {
        // Take the receiver out of self to avoid borrow checker issues
        let mut incoming_rx = self
            .incoming_rx
            .take()
            .ok_or(RemoteClientError::NotInitialized)?;

        loop {
            tokio::select! {
                msg = incoming_rx.recv() => {
                    match msg {
                        Some(msg) => {
                            if let Err(e) = self.handle_incoming(msg, &event_tx).await {
                                warn!("Error handling incoming message: {}", e);
                                event_tx.send(UserClientEvent::Error {
                                    message: e.to_string(),
                                    context: Some("handle_incoming".to_string()),
                                }).await.ok();
                            }
                        }
                        None => {
                            // Incoming channel closed — proxy connection lost
                            event_tx.send(UserClientEvent::ClientDisconnected {}).await.ok();
                            match self.attempt_reconnection(&event_tx).await {
                                Ok(new_rx) => {
                                    incoming_rx = new_rx;
                                    event_tx.send(UserClientEvent::Reconnected {}).await.ok();
                                }
                                Err(e) => {
                                    warn!("Reconnection failed permanently: {}", e);
                                    return Err(e);
                                }
                            }
                        }
                    }
                }
                Some(response) = response_rx.recv() => {
                    if let Err(e) = self.handle_response(response, &event_tx).await {
                        warn!("Error handling response: {}", e);
                        event_tx.send(UserClientEvent::Error {
                            message: e.to_string(),
                            context: Some("handle_response".to_string()),
                        }).await.ok();
                    }
                }
            }
        }
    }

    /// Attempt to reconnect to the proxy server with exponential backoff.
    ///
    /// Base delay: 2s, multiplier: 2x, max delay: 15 minutes, with jitter.
    /// Retries indefinitely until successful.
    async fn attempt_reconnection(
        &mut self,
        event_tx: &mpsc::Sender<UserClientEvent>,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, RemoteClientError> {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut attempt: u32 = 0;

        loop {
            attempt = attempt.saturating_add(1);

            let proxy_client = self
                .proxy_client
                .as_mut()
                .ok_or(RemoteClientError::NotInitialized)?;

            // Disconnect (ignore errors — connection may already be dead)
            let _ = proxy_client.disconnect().await;

            match proxy_client.connect().await {
                Ok(new_rx) => {
                    debug!("Reconnected to proxy on attempt {}", attempt);
                    return Ok(new_rx);
                }
                Err(e) => {
                    debug!("Reconnection attempt {} failed: {}", attempt, e);
                    event_tx
                        .send(UserClientEvent::Reconnecting { attempt })
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

                    tokio::time::sleep(total_delay).await;
                }
            }
        }
    }

    /// Handle incoming messages from proxy
    async fn handle_incoming(
        &mut self,
        msg: IncomingMessage,
        event_tx: &mpsc::Sender<UserClientEvent>,
    ) -> Result<(), RemoteClientError> {
        match msg {
            IncomingMessage::Send {
                source, payload, ..
            } => {
                // Parse payload as ProtocolMessage
                let text = String::from_utf8(payload)
                    .map_err(|e| RemoteClientError::Serialization(format!("Invalid UTF-8: {e}")))?;

                let protocol_msg: ProtocolMessage = serde_json::from_str(&text)?;

                match protocol_msg {
                    ProtocolMessage::HandshakeInit { data, ciphersuite } => {
                        self.handle_handshake_init(source, data, ciphersuite, event_tx)
                            .await?;
                    }
                    ProtocolMessage::CredentialRequest { encrypted } => {
                        self.handle_credential_request(source, encrypted, event_tx)
                            .await?;
                    }
                    _ => {
                        debug!("Received unexpected message type from {:?}", source);
                    }
                }
            }
            IncomingMessage::RendevouzInfo(_) => {
                // Already handled in listen()
            }
            IncomingMessage::IdentityInfo { .. } => {
                // Only RemoteClient needs this
                debug!("Received unexpected IdentityInfo message");
            }
        }
        Ok(())
    }

    /// Handle handshake init message
    async fn handle_handshake_init(
        &mut self,
        source: IdentityFingerprint,
        data: String,
        ciphersuite: String,
        event_tx: &mpsc::Sender<UserClientEvent>,
    ) -> Result<(), RemoteClientError> {
        debug!("Received handshake init from source: {:?}", source);
        event_tx.send(UserClientEvent::HandshakeStart {}).await.ok();

        let (transport, fingerprint_str) =
            self.complete_handshake(source, &data, &ciphersuite).await?;

        event_tx
            .send(UserClientEvent::HandshakeComplete {})
            .await
            .ok();

        // Check if this is a new connection (not in cache)
        let is_new_connection = !self.session_store.has_session(&source);
        // PSK connections are already trusted — no fingerprint verification needed
        let is_psk_connection = self.psk.is_some();

        if is_new_connection && !is_psk_connection {
            // New rendezvous connection: require fingerprint verification before caching
            self.pending_verification = Some(PendingHandshakeVerification { source, transport });

            event_tx
                .send(UserClientEvent::HandshakeFingerprint {
                    fingerprint: fingerprint_str,
                })
                .await
                .ok();
        } else if !is_new_connection {
            // Existing/cached session: already verified on first connection.
            // Re-cache to update timestamps (cached_at / last_connected_at),
            // and save the new transport state from the fresh handshake.
            self.transports.insert(source, transport.clone());
            self.session_store.cache_session(source)?;
            // Apply pending name if user explicitly re-paired (e.g. `/pair MyName`).
            // During passive reconnections, pending_session_name is None so this is a no-op.
            if let Some(name) = self.pending_session_name.take() {
                self.session_store.set_session_name(&source, name)?;
            }
            self.session_store
                .save_transport_state(&source, transport)?;

            self.audit_log
                .write(AuditEvent::SessionRefreshed {
                    remote_identity: &source,
                })
                .await;

            event_tx
                .send(UserClientEvent::SessionRefreshed {
                    fingerprint: source,
                })
                .await
                .ok();
        } else if is_psk_connection {
            // PSK connection: trust established via pre-shared key, no verification needed
            let session_name = self.pending_session_name.take();
            self.accept_new_connection(
                source,
                transport,
                session_name.as_deref(),
                AuditConnectionType::Psk,
            )
            .await?;

            event_tx
                .send(UserClientEvent::HandshakeFingerprint {
                    fingerprint: fingerprint_str,
                })
                .await
                .ok();
        }

        Ok(())
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
        self.session_store.cache_session(fingerprint)?;
        if let Some(name) = session_name {
            self.session_store
                .set_session_name(&fingerprint, name.to_owned())?;
        }
        self.session_store
            .save_transport_state(&fingerprint, transport)?;

        self.audit_log
            .write(AuditEvent::ConnectionEstablished {
                remote_identity: &fingerprint,
                remote_name: session_name,
                connection_type,
            })
            .await;

        Ok(())
    }

    /// Handle fingerprint verification response
    async fn handle_fingerprint_verification(
        &mut self,
        approved: bool,
        name: Option<String>,
        event_tx: &mpsc::Sender<UserClientEvent>,
    ) -> Result<(), RemoteClientError> {
        let pending = self
            .pending_verification
            .take()
            .ok_or(RemoteClientError::InvalidState {
                expected: "pending verification".to_string(),
                current: "no pending verification".to_string(),
            })?;

        if approved {
            let session_name = name.or(self.pending_session_name.take());
            self.accept_new_connection(
                pending.source,
                pending.transport,
                session_name.as_deref(),
                AuditConnectionType::Rendezvous,
            )
            .await?;

            event_tx
                .send(UserClientEvent::FingerprintVerified {})
                .await
                .ok();
        } else {
            self.audit_log
                .write(AuditEvent::ConnectionRejected {
                    remote_identity: &pending.source,
                })
                .await;

            event_tx
                .send(UserClientEvent::FingerprintRejected {
                    reason: "User rejected fingerprint verification".to_string(),
                })
                .await
                .ok();
        }

        Ok(())
    }

    /// Handle credential request
    async fn handle_credential_request(
        &mut self,
        source: IdentityFingerprint,
        encrypted: String,
        event_tx: &mpsc::Sender<UserClientEvent>,
    ) -> Result<(), RemoteClientError> {
        if !self.transports.contains_key(&source) {
            debug!("Loading transport state for source: {:?}", source);
            let session = self
                .session_store
                .load_transport_state(&source)?
                .expect("Transport state should exist for cached session");
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
                domain: &request.domain,
                remote_identity: &source,
                request_id: &request.request_id,
            })
            .await;

        // Send credential request event
        event_tx
            .send(UserClientEvent::CredentialRequest {
                domain: request.domain.clone(),
                request_id: request.request_id.clone(),
                session_id: format!("{source:?}"),
            })
            .await
            .ok();

        Ok(())
    }

    /// Handle user responses
    async fn handle_response(
        &mut self,
        response: UserClientResponse,
        event_tx: &mpsc::Sender<UserClientEvent>,
    ) -> Result<(), RemoteClientError> {
        match response {
            UserClientResponse::VerifyFingerprint { approved, name } => {
                self.handle_fingerprint_verification(approved, name, event_tx)
                    .await?;
            }
            UserClientResponse::RespondCredential {
                request_id,
                session_id,
                domain,
                approved,
                credential,
                credential_id,
            } => {
                self.handle_credential_response(
                    request_id,
                    session_id,
                    domain,
                    approved,
                    credential,
                    credential_id,
                    event_tx,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Handle credential response
    #[allow(clippy::too_many_arguments)]
    async fn handle_credential_response(
        &mut self,
        request_id: String,
        session_id: String,
        domain: String,
        approved: bool,
        credential: Option<CredentialData>,
        credential_id: Option<String>,
        event_tx: &mpsc::Sender<UserClientEvent>,
    ) -> Result<(), RemoteClientError> {
        // Parse session_id as fingerprint
        let fingerprint = self
            .transports
            .keys()
            .find(|fp| format!("{fp:?}") == session_id)
            .copied()
            .ok_or(RemoteClientError::NotInitialized)?;

        let transport = self
            .transports
            .get_mut(&fingerprint)
            .ok_or(RemoteClientError::SecureChannelNotEstablished)?;

        // Compute audit fields before credential is moved into the response payload
        let fields = credential
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
            credential: if approved { credential } else { None },
            error: if !approved {
                Some("Request denied".to_string())
            } else {
                None
            },
            request_id: request_id.clone(),
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

        let proxy_client = self
            .proxy_client
            .as_ref()
            .ok_or(RemoteClientError::NotInitialized)?;

        proxy_client
            .send_to(fingerprint, msg_json.into_bytes())
            .await?;

        // Send event
        if approved {
            self.audit_log
                .write(AuditEvent::CredentialApproved {
                    domain: &domain,
                    remote_identity: &fingerprint,
                    request_id: &request_id,
                    credential_id: credential_id.as_deref(),
                    fields,
                })
                .await;

            event_tx
                .send(UserClientEvent::CredentialApproved {
                    domain,
                    credential_id,
                })
                .await
                .ok();
        } else {
            self.audit_log
                .write(AuditEvent::CredentialDenied {
                    domain: &domain,
                    remote_identity: &fingerprint,
                    request_id: &request_id,
                    credential_id: credential_id.as_deref(),
                })
                .await;

            event_tx
                .send(UserClientEvent::CredentialDenied {
                    domain,
                    credential_id,
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

        // Create responder handshake (with PSK if available)
        let mut handshake = if let Some(ref psk) = self.psk {
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

        let proxy_client = self
            .proxy_client
            .as_ref()
            .ok_or(RemoteClientError::NotInitialized)?;

        proxy_client
            .send_to(remote_fingerprint, msg_json.into_bytes())
            .await?;

        debug!("Sent handshake response to {:?}", remote_fingerprint);

        Ok((transport, fingerprint.to_string()))
    }

    /// Get the current rendezvous code
    pub fn rendezvous_code(&self) -> Option<&RendevouzCode> {
        self.rendezvous_code.as_ref()
    }

    /// Set a friendly name to assign to the next newly-paired session
    pub fn set_pending_session_name(&mut self, name: String) {
        self.pending_session_name = Some(name);
    }
}
