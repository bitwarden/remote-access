use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use bw_noise_protocol::{InitiatorHandshake, MultiDeviceTransport, Psk};
use bw_proxy_protocol::IncomingMessage;
use bw_proxy_protocol::{IdentityFingerprint, RendevouzCode};
use rand::RngCore;

use crate::proxy::ProxyClient;
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    time::timeout,
};
use tracing::{debug, info, warn};

use crate::traits::{IdentityProvider, SessionStore};
use crate::{
    error::RemoteClientError,
    types::{
        CredentialData, CredentialRequestPayload, CredentialResponsePayload, ProtocolMessage,
        RemoteClientEvent, RemoteClientResponse,
    },
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Type alias for pending credential request senders
type PendingRequestMap =
    HashMap<String, oneshot::Sender<Result<CredentialData, RemoteClientError>>>;

/// Remote client for connecting to a user-client through a proxy
pub struct RemoteClient {
    session_store: Box<dyn SessionStore>,
    proxy_client: Box<dyn ProxyClient>,
    incoming_rx: Option<mpsc::UnboundedReceiver<IncomingMessage>>,
    transport: Option<Arc<Mutex<MultiDeviceTransport>>>,
    remote_fingerprint: Option<IdentityFingerprint>,
    pending_requests: Arc<Mutex<PendingRequestMap>>,
    event_tx: mpsc::Sender<RemoteClientEvent>,
    response_rx: Option<mpsc::Receiver<RemoteClientResponse>>,
}

impl RemoteClient {
    /// Create a new remote client and connect to the proxy server
    ///
    /// This establishes the WebSocket connection and authenticates with the proxy.
    /// After calling this, use one of the pairing methods:
    /// - `pair_with_handshake()` for new rendezvous-based pairing
    /// - `pair_with_psk()` for PSK-based pairing
    /// - `load_cached_session()` for reconnecting with a cached session
    ///
    /// # Arguments
    /// * `identity_provider` - Provider for the client's identity
    /// * `session_store` - Store for caching sessions
    /// * `event_tx` - Channel sender for client events
    /// * `response_rx` - Channel receiver for client responses
    /// * `proxy_client` - The proxy client implementation to use for communication
    pub async fn new(
        identity_provider: Box<dyn IdentityProvider>,
        session_store: Box<dyn SessionStore>,
        event_tx: mpsc::Sender<RemoteClientEvent>,
        response_rx: mpsc::Receiver<RemoteClientResponse>,
        mut proxy_client: Box<dyn ProxyClient>,
    ) -> Result<Self, RemoteClientError> {
        let identity = identity_provider.identity().to_owned();

        info!(
            "Connecting to proxy with identity {:?}",
            identity.identity().fingerprint()
        );

        event_tx
            .send(RemoteClientEvent::Connecting {
                proxy_url: String::new(),
            })
            .await
            .ok();

        let incoming_rx = proxy_client.connect().await?;

        event_tx
            .send(RemoteClientEvent::Connected {
                fingerprint: identity.identity().fingerprint(),
            })
            .await
            .ok();

        info!("Connected to proxy successfully");

        Ok(Self {
            session_store,
            proxy_client,
            incoming_rx: Some(incoming_rx),
            transport: None,
            remote_fingerprint: None,
            pending_requests: Arc::new(Mutex::new(HashMap::new())),
            event_tx,
            response_rx: Some(response_rx),
        })
    }

    /// Pair with a remote device using a rendezvous code
    ///
    /// This resolves the rendezvous code to a fingerprint, performs the Noise handshake,
    /// and optionally waits for user fingerprint verification.
    ///
    /// # Arguments
    /// * `rendezvous_code` - The rendezvous code to resolve
    /// * `verify_fingerprint` - If true, emit fingerprint event and wait for user verification.
    ///   If false, emit fingerprint event informationally and proceed immediately.
    pub async fn pair_with_handshake(
        &mut self,
        rendezvous_code: &str,
        verify_fingerprint: bool,
    ) -> Result<IdentityFingerprint, RemoteClientError> {
        let incoming_rx =
            self.incoming_rx
                .as_mut()
                .ok_or_else(|| RemoteClientError::InvalidState {
                    expected: "proxy connected".to_string(),
                    current: "not connected".to_string(),
                })?;

        let event_tx = self.event_tx.clone();

        let response_rx = self
            .response_rx
            .as_mut()
            .ok_or(RemoteClientError::NotInitialized)?;

        // Resolve rendezvous code to fingerprint
        event_tx
            .send(RemoteClientEvent::RendevouzResolving {
                code: rendezvous_code.to_string(),
            })
            .await
            .ok();

        let remote_fingerprint =
            Self::resolve_rendezvous(self.proxy_client.as_ref(), incoming_rx, rendezvous_code)
                .await?;

        event_tx
            .send(RemoteClientEvent::RendevouzResolved {
                fingerprint: remote_fingerprint,
            })
            .await
            .ok();

        // Perform Noise handshake (no PSK)
        event_tx.send(RemoteClientEvent::HandshakeStart).await.ok();

        let (transport, fingerprint_str) = Self::perform_handshake(
            self.proxy_client.as_ref(),
            incoming_rx,
            remote_fingerprint,
            None,
        )
        .await?;

        event_tx
            .send(RemoteClientEvent::HandshakeComplete)
            .await
            .ok();

        // Always emit fingerprint event (informational or for verification)
        event_tx
            .send(RemoteClientEvent::HandshakeFingerprint {
                fingerprint: fingerprint_str,
            })
            .await
            .ok();

        if verify_fingerprint {
            // Wait for user verification (60s timeout)
            match timeout(Duration::from_secs(60), response_rx.recv()).await {
                Ok(Some(RemoteClientResponse::VerifyFingerprint { approved: true })) => {
                    event_tx
                        .send(RemoteClientEvent::FingerprintVerified)
                        .await
                        .ok();
                }
                Ok(Some(RemoteClientResponse::VerifyFingerprint { approved: false })) => {
                    self.proxy_client.disconnect().await.ok();
                    event_tx
                        .send(RemoteClientEvent::FingerprintRejected {
                            reason: "User rejected fingerprint verification".to_string(),
                        })
                        .await
                        .ok();
                    return Err(RemoteClientError::FingerprintRejected);
                }
                Ok(None) => {
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

        // Cache new session
        self.session_store.cache_session(remote_fingerprint)?;

        // Finalize connection
        self.finalize_connection(transport, remote_fingerprint, event_tx)
            .await?;

        Ok(remote_fingerprint)
    }

    /// Pair with a remote device using a pre-shared key
    ///
    /// This uses the PSK for authentication, skipping fingerprint verification
    /// since trust is established through the PSK.
    pub async fn pair_with_psk(
        &mut self,
        psk: Psk,
        remote_fingerprint: IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        let incoming_rx =
            self.incoming_rx
                .as_mut()
                .ok_or_else(|| RemoteClientError::InvalidState {
                    expected: "proxy connected".to_string(),
                    current: "not connected".to_string(),
                })?;

        let event_tx = self.event_tx.clone();

        // Emit PskMode event
        event_tx
            .send(RemoteClientEvent::PskMode {
                fingerprint: remote_fingerprint,
            })
            .await
            .ok();

        // Perform Noise handshake with PSK
        event_tx.send(RemoteClientEvent::HandshakeStart).await.ok();

        let (transport, _fingerprint_str) = Self::perform_handshake(
            self.proxy_client.as_ref(),
            incoming_rx,
            remote_fingerprint,
            Some(psk),
        )
        .await?;

        event_tx
            .send(RemoteClientEvent::HandshakeComplete)
            .await
            .ok();

        // Skip fingerprint verification (trust via PSK)
        event_tx
            .send(RemoteClientEvent::FingerprintVerified)
            .await
            .ok();

        // Cache new session
        self.session_store.cache_session(remote_fingerprint)?;

        // Finalize connection
        self.finalize_connection(transport, remote_fingerprint, event_tx)
            .await?;

        Ok(())
    }

    /// Reconnect to a remote device using a cached session
    ///
    /// This verifies the session exists in the session store and reconnects
    /// without requiring fingerprint verification.
    pub async fn load_cached_session(
        &mut self,
        remote_fingerprint: IdentityFingerprint,
    ) -> Result<(), RemoteClientError> {
        let event_tx = self.event_tx.clone();

        // Verify session exists in session store
        if !self.session_store.has_session(&remote_fingerprint) {
            return Err(RemoteClientError::SessionNotFound);
        }

        // Emit reconnecting event
        event_tx
            .send(RemoteClientEvent::ReconnectingToSession {
                fingerprint: remote_fingerprint,
            })
            .await
            .ok();

        let transport_state = self
            .session_store
            .load_transport_state(&remote_fingerprint)?
            .expect("Transport state should exist for cached session");

        event_tx
            .send(RemoteClientEvent::HandshakeComplete)
            .await
            .ok();

        // Skip fingerprint verification (already trusted)
        event_tx
            .send(RemoteClientEvent::FingerprintVerified)
            .await
            .ok();

        // Update last_connected_at
        self.session_store
            .update_last_connected(&remote_fingerprint)?;

        // Finalize connection
        self.finalize_connection(transport_state, remote_fingerprint, event_tx)
            .await?;

        Ok(())
    }

    /// Finalize the connection after successful pairing
    ///
    /// This stores the transport and remote fingerprint, emits the Ready event,
    /// and spawns the message loop task.
    async fn finalize_connection(
        &mut self,
        transport: MultiDeviceTransport,
        remote_fingerprint: IdentityFingerprint,
        event_tx: mpsc::Sender<RemoteClientEvent>,
    ) -> Result<(), RemoteClientError> {
        // Save transport state for session resumption
        self.session_store
            .save_transport_state(&remote_fingerprint, transport.clone())?;

        // Store transport and remote fingerprint
        let transport = Arc::new(Mutex::new(transport));
        self.transport = Some(Arc::clone(&transport));
        self.remote_fingerprint = Some(remote_fingerprint);

        // Emit Ready event
        event_tx
            .send(RemoteClientEvent::Ready {
                can_request_credentials: true,
            })
            .await
            .ok();

        // Take incoming_rx for the message loop
        let incoming_rx = self
            .incoming_rx
            .take()
            .ok_or(RemoteClientError::NotInitialized)?;

        // Spawn message handler
        let pending_requests_clone = Arc::clone(&self.pending_requests);
        tokio::spawn(async move {
            Self::message_loop(incoming_rx, event_tx, transport, pending_requests_clone).await;
        });

        info!("Connection established successfully");
        Ok(())
    }

    /// Request a credential over the secure channel
    pub async fn request_credential(
        &mut self,
        domain: &str,
    ) -> Result<CredentialData, RemoteClientError> {
        let transport = self
            .transport
            .as_ref()
            .ok_or(RemoteClientError::SecureChannelNotEstablished)?;

        let remote_fingerprint = self
            .remote_fingerprint
            .ok_or(RemoteClientError::NotInitialized)?;

        // Sliced string is a UUID and isn't going to contain wide chars
        #[allow(clippy::string_slice)]
        let request_id = format!("req-{}-{}", now_millis(), &uuid_v4()[..8]);

        info!("Requesting credential for domain: {}", domain);

        // Create and encrypt request
        let request = CredentialRequestPayload {
            request_type: "credential_request".to_string(),
            domain: domain.to_string(),
            timestamp: now_millis(),
            request_id: request_id.clone(),
        };

        let request_json = serde_json::to_string(&request)?;
        let mut transport_guard = transport.lock().await;
        let encrypted_packet = transport_guard
            .encrypt(request_json.as_bytes())
            .map_err(|e| RemoteClientError::NoiseProtocol(e.to_string()))?;
        drop(transport_guard);

        let msg = ProtocolMessage::CredentialRequest {
            encrypted: STANDARD.encode(encrypted_packet.encode()),
        };

        // Send via proxy
        let msg_json = serde_json::to_string(&msg)?;
        self.proxy_client
            .send_to(remote_fingerprint, msg_json.into_bytes())
            .await?;

        // Emit event
        self.event_tx
            .send(RemoteClientEvent::CredentialRequestSent {
                domain: domain.to_string(),
            })
            .await
            .ok();

        // Create oneshot channel for this request
        let (response_tx, response_rx) = oneshot::channel();

        // Store sender in pending_requests map
        self.pending_requests
            .lock()
            .await
            .insert(request_id.clone(), response_tx);

        // Wait for response with timeout
        match timeout(DEFAULT_TIMEOUT, response_rx).await {
            Ok(Ok(Ok(credential))) => {
                // Success - sender already removed by handler
                info!("Received credential for domain: {}", domain);
                Ok(credential)
            }
            Ok(Ok(Err(e))) => {
                // Error response from user client
                Err(e)
            }
            Ok(Err(_)) => {
                // Sender dropped - connection lost or handler error
                self.pending_requests.lock().await.remove(&request_id);
                Err(RemoteClientError::ChannelClosed)
            }
            Err(_) => {
                // Timeout - clean up pending request
                self.pending_requests.lock().await.remove(&request_id);
                Err(RemoteClientError::Timeout(format!(
                    "Timeout waiting for credential response for domain: {domain}"
                )))
            }
        }
    }

    /// Check if the secure channel is established
    pub fn is_ready(&self) -> bool {
        self.transport.is_some()
    }

    /// Close the connection
    pub async fn close(&mut self) {
        // Clear pending requests
        let mut pending = self.pending_requests.lock().await;
        pending.clear(); // Drops all senders, causing receivers to get Err
        drop(pending);

        self.proxy_client.disconnect().await.ok();
        self.transport = None;
        self.remote_fingerprint = None;
        self.incoming_rx = None;
        self.response_rx = None;
        info!("Connection closed");
    }

    /// Get the session store for management operations
    pub fn session_store(&self) -> &dyn SessionStore {
        self.session_store.as_ref()
    }

    /// Get a mutable reference to the session store
    pub fn session_store_mut(&mut self) -> &mut dyn SessionStore {
        self.session_store.as_mut()
    }

    /// Resolve rendezvous code to identity fingerprint
    async fn resolve_rendezvous(
        proxy_client: &dyn ProxyClient,
        incoming_rx: &mut mpsc::UnboundedReceiver<IncomingMessage>,
        rendezvous_code: &str,
    ) -> Result<IdentityFingerprint, RemoteClientError> {
        // Send GetIdentity request
        proxy_client
            .request_identity(RendevouzCode::from_string(rendezvous_code.to_string()))
            .await
            .map_err(|e| RemoteClientError::RendevouzResolutionFailed(e.to_string()))?;

        // Wait for IdentityInfo response with timeout
        let timeout_duration = tokio::time::Duration::from_secs(10);
        match tokio::time::timeout(timeout_duration, async {
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
            Ok(None) => Err(RemoteClientError::RendevouzResolutionFailed(
                "Connection closed while waiting for identity response".to_string(),
            )),
            Err(_) => Err(RemoteClientError::RendevouzResolutionFailed(
                "Timeout waiting for identity response. The rendezvous code may be invalid, expired, or the target client may be disconnected.".to_string(),
            )),
        }
    }

    /// Perform Noise handshake as initiator
    async fn perform_handshake(
        proxy_client: &dyn ProxyClient,
        incoming_rx: &mut mpsc::UnboundedReceiver<IncomingMessage>,
        remote_fingerprint: IdentityFingerprint,
        psk: Option<Psk>,
    ) -> Result<(MultiDeviceTransport, String), RemoteClientError> {
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

        let response_packet = bw_noise_protocol::HandshakePacket::decode(&response_bytes)
            .map_err(|e| RemoteClientError::NoiseProtocol(format!("Invalid packet: {e}")))?;

        // Complete handshake
        handshake.receive_finish(&response_packet)?;
        let (transport, fingerprint) = handshake.finalize()?;

        debug!("Handshake complete");
        Ok((transport, fingerprint.to_string()))
    }

    /// Background message loop
    async fn message_loop(
        mut incoming_rx: mpsc::UnboundedReceiver<IncomingMessage>,
        event_tx: mpsc::Sender<RemoteClientEvent>,
        transport: Arc<Mutex<MultiDeviceTransport>>,
        pending_requests: Arc<Mutex<PendingRequestMap>>,
    ) {
        while let Some(msg) = incoming_rx.recv().await {
            match msg {
                IncomingMessage::Send { payload, .. } => {
                    // Parse payload and route to appropriate handler
                    if let Ok(text) = String::from_utf8(payload) {
                        if let Ok(protocol_msg) = serde_json::from_str::<ProtocolMessage>(&text) {
                            match protocol_msg {
                                ProtocolMessage::CredentialResponse { encrypted } => {
                                    if let Err(e) = Self::handle_credential_response(
                                        encrypted,
                                        &transport,
                                        &pending_requests,
                                        &event_tx,
                                    )
                                    .await
                                    {
                                        warn!("Error handling credential response: {:?}", e);
                                        event_tx
                                            .send(RemoteClientEvent::Error {
                                                message: e.to_string(),
                                                context: Some("credential_response".to_string()),
                                            })
                                            .await
                                            .ok();
                                    }
                                }
                                _ => {
                                    debug!("Received other message type");
                                }
                            }
                        }
                    }
                }
                IncomingMessage::RendevouzInfo(_) => {
                    // Ignore - only UserClient needs this
                }
                IncomingMessage::IdentityInfo { .. } => {
                    // Consumed during resolve_rendezvous(), but handle here for race conditions
                    debug!("Received IdentityInfo message");
                }
            }
        }
    }

    /// Handle credential response processing
    async fn handle_credential_response(
        encrypted: String,
        transport: &Arc<Mutex<MultiDeviceTransport>>,
        pending_requests: &Arc<Mutex<PendingRequestMap>>,
        event_tx: &mpsc::Sender<RemoteClientEvent>,
    ) -> Result<(), RemoteClientError> {
        // 1. Decrypt the encrypted response
        let encrypted_bytes = STANDARD
            .decode(&encrypted)
            .map_err(|e| RemoteClientError::Serialization(format!("Invalid base64: {e}")))?;

        let packet = bw_noise_protocol::TransportPacket::decode(&encrypted_bytes)
            .map_err(|e| RemoteClientError::NoiseProtocol(format!("Invalid packet: {e}")))?;

        let mut transport_guard = transport.lock().await;
        let decrypted = transport_guard
            .decrypt(&packet)
            .map_err(|e| RemoteClientError::NoiseProtocol(e.to_string()))?;
        drop(transport_guard);

        // 2. Deserialize the response payload
        let response: CredentialResponsePayload = serde_json::from_slice(&decrypted)?;

        // 3. Find and remove the pending request by request_id
        let mut pending = pending_requests.lock().await;
        let sender = match response.request_id {
            Some(ref req_id) => pending.remove(req_id),
            None => {
                warn!("Received credential response without request_id");
                return Ok(()); // Ignore malformed response
            }
        };
        drop(pending);

        // 4. Send result through oneshot channel
        if let Some(sender) = sender {
            let result = if let Some(error) = response.error {
                Err(RemoteClientError::CredentialRequestFailed(error))
            } else if let Some(credential) = response.credential {
                // Emit success event
                event_tx
                    .send(RemoteClientEvent::CredentialReceived {
                        domain: "unknown".to_string(), // Could be enhanced by tracking domain in pending requests
                        credential: credential.clone(),
                    })
                    .await
                    .ok();

                Ok(credential)
            } else {
                Err(RemoteClientError::CredentialRequestFailed(
                    "Response contains neither credential nor error".to_string(),
                ))
            };

            sender.send(result).ok(); // Ignore if receiver dropped (timeout)
        } else {
            // Response for unknown/expired request_id - already timed out
            debug!(
                "Received response for unknown request_id: {:?}",
                response.request_id
            );
        }

        Ok(())
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
