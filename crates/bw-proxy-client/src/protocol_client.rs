use bw_proxy_protocol::{
    IdentityFingerprint, IdentityKeyPair, Messages, ProxyError, RendevouzCode,
};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_tungstenite::{WebSocketStream, connect_async, tungstenite::Message};

use super::config::{ClientState, IncomingMessage, ProxyClientConfig};

/// Convert tungstenite errors into ProxyError (replaces the From impl that
/// was removed from bw-proxy-protocol to keep it free of tungstenite deps).
fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> ProxyError {
    ProxyError::WebSocket(e.to_string())
}

type WsStream = WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = futures_util::stream::SplitSink<WsStream, Message>;
type WsSource = futures_util::stream::SplitStream<WsStream>;

/// Client for connecting to and communicating through a bw-proxy server.
///
/// This is the main client API for connecting to a proxy server, authenticating,
/// discovering peers via rendezvous codes, and sending messages.
///
/// # Lifecycle
///
/// 1. Create client with [`new()`](ProxyProtocolClient::new)
/// 2. Connect and authenticate with [`connect()`](ProxyProtocolClient::connect)
/// 3. Perform operations (send messages, request rendezvous codes, etc.)
/// 4. Disconnect with [`disconnect()`](ProxyProtocolClient::disconnect)
///
/// # Examples
///
/// Basic usage:
///
/// ```no_run
/// use bw_proxy_client::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create and connect
/// let config = ProxyClientConfig {
///     proxy_url: "ws://localhost:8080".to_string(),
///     identity_keypair: None,
/// };
/// let mut client = ProxyProtocolClient::new(config);
/// let mut incoming = client.connect().await?;
///
/// // Handle messages
/// tokio::spawn(async move {
///     while let Some(msg) = incoming.recv().await {
///         match msg {
///             IncomingMessage::Send { source, payload, .. } => {
///                 println!("Got message from {:?}", source);
///             }
///             _ => {}
///         }
///     }
/// });
///
/// // Send a message
/// // client.send_to(target_fingerprint, b"Hello".to_vec()).await?;
/// # Ok(())
/// # }
/// ```
pub struct ProxyProtocolClient {
    // Configuration
    config: ProxyClientConfig,
    identity: Arc<IdentityKeyPair>,

    // Connection state
    state: Arc<Mutex<ClientState>>,

    // WebSocket components (None when disconnected)
    outgoing_tx: Option<mpsc::UnboundedSender<Message>>,

    // Task handles for cleanup
    read_task_handle: Option<JoinHandle<()>>,
    write_task_handle: Option<JoinHandle<()>>,
}

impl ProxyProtocolClient {
    /// Create a new proxy client with the given configuration.
    ///
    /// This does not establish a connection - call [`connect()`](ProxyProtocolClient::connect)
    /// to connect and authenticate.
    ///
    /// If `config.identity_keypair` is `None`, a new random identity will be generated.
    /// Otherwise, the provided identity will be used for authentication.
    ///
    /// # Examples
    ///
    /// Create client with new identity:
    ///
    /// ```
    /// use bw_proxy_client::{ProxyClientConfig, ProxyProtocolClient};
    ///
    /// let config = ProxyClientConfig {
    ///     proxy_url: "ws://localhost:8080".to_string(),
    ///     identity_keypair: None, // Will generate new identity
    /// };
    /// let client = ProxyProtocolClient::new(config);
    /// println!("Client fingerprint: {:?}", client.fingerprint());
    /// ```
    ///
    /// Create client with existing identity:
    ///
    /// ```
    /// use bw_proxy_client::{ProxyClientConfig, ProxyProtocolClient, IdentityKeyPair};
    ///
    /// let keypair = IdentityKeyPair::generate();
    /// let config = ProxyClientConfig {
    ///     proxy_url: "ws://localhost:8080".to_string(),
    ///     identity_keypair: Some(keypair),
    /// };
    /// let client = ProxyProtocolClient::new(config);
    /// ```
    pub fn new(mut config: ProxyClientConfig) -> Self {
        let identity = Arc::new(
            config
                .identity_keypair
                .take()
                .unwrap_or_else(IdentityKeyPair::generate),
        );

        Self {
            config,
            identity,
            state: Arc::new(Mutex::new(ClientState::Disconnected)),
            outgoing_tx: None,
            read_task_handle: None,
            write_task_handle: None,
        }
    }

    /// Connect to the proxy server and perform authentication.
    ///
    /// Establishes a WebSocket connection, completes the challenge-response authentication,
    /// and returns a channel for receiving incoming messages.
    ///
    /// # Authentication Flow
    ///
    /// 1. Connect to WebSocket at the configured URL
    /// 2. Receive authentication challenge from server
    /// 3. Sign challenge with client's private key
    /// 4. Send signed response to server
    /// 5. Server verifies signature and accepts connection
    ///
    /// # Timeout
    ///
    /// Authentication must complete within 5 seconds or this method returns
    /// [`ProxyError::AuthenticationTimeout`].
    ///
    /// # Errors
    ///
    /// - [`ProxyError::AlreadyConnected`] if already connected
    /// - [`ProxyError::WebSocket`] if connection fails
    /// - [`ProxyError::AuthenticationFailed`] if signature verification fails
    /// - [`ProxyError::AuthenticationTimeout`] if authentication takes too long
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bw_proxy_client::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ProxyClientConfig {
    ///     proxy_url: "ws://localhost:8080".to_string(),
    ///     identity_keypair: None,
    /// };
    /// let mut client = ProxyProtocolClient::new(config);
    ///
    /// // Connect and get incoming message channel
    /// let mut incoming = client.connect().await?;
    ///
    /// // Handle messages
    /// while let Some(msg) = incoming.recv().await {
    ///     println!("Received: {:?}", msg);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ProxyError> {
        // Check not already connected
        {
            let state = self.state.lock().await;
            if !matches!(*state, ClientState::Disconnected) {
                return Err(ProxyError::AlreadyConnected);
            }
        }

        // Connect WebSocket
        let (ws_stream, _) = connect_async(&self.config.proxy_url)
            .await
            .map_err(ws_err)?;

        // Split into read/write
        let (ws_sink, ws_source) = ws_stream.split();

        // Update state to Connected
        *self.state.lock().await = ClientState::Connected;

        // Create channels
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel::<Message>();
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel::<IncomingMessage>();
        let (auth_tx, mut auth_rx) = mpsc::unbounded_channel::<Result<(), ProxyError>>();

        // Spawn write task
        let write_handle = tokio::spawn(Self::write_task(ws_sink, outgoing_rx));

        // Spawn read task (handles auth + message routing)
        let read_handle = tokio::spawn(Self::read_task(
            ws_source,
            outgoing_tx.clone(),
            incoming_tx,
            Arc::clone(&self.identity),
            self.state.clone(),
            auth_tx,
        ));

        // Wait for authentication to complete
        match tokio::time::timeout(tokio::time::Duration::from_secs(5), auth_rx.recv()).await {
            Ok(Some(Ok(()))) => {
                // Authentication succeeded
            }
            Ok(Some(Err(e))) => {
                // Authentication failed
                self.read_task_handle = Some(read_handle);
                self.write_task_handle = Some(write_handle);
                self.disconnect().await?;
                return Err(e);
            }
            Ok(None) | Err(_) => {
                // Channel closed or timeout
                self.read_task_handle = Some(read_handle);
                self.write_task_handle = Some(write_handle);
                self.disconnect().await?;
                return Err(ProxyError::AuthenticationTimeout);
            }
        }

        // Store handles and tx
        self.outgoing_tx = Some(outgoing_tx);
        self.read_task_handle = Some(read_handle);
        self.write_task_handle = Some(write_handle);

        Ok(incoming_rx)
    }

    /// Send a message to another authenticated client.
    ///
    /// The message is routed through the proxy server to the destination client.
    /// The proxy validates the source identity but cannot inspect the payload.
    ///
    /// # Authentication Required
    ///
    /// This method requires an active authenticated connection. Call
    /// [`connect()`](ProxyProtocolClient::connect) first.
    ///
    /// # Payload Encryption
    ///
    /// The proxy does not encrypt message payloads. Clients should implement
    /// end-to-end encryption (e.g., using the Noise protocol) before calling this method.
    ///
    /// # Errors
    ///
    /// - [`ProxyError::NotConnected`] if not connected or not authenticated
    /// - [`ProxyError::DestinationNotFound`] if the destination client is not connected
    /// - [`ProxyError::Serialization`] if message encoding fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bw_proxy_client::{ProxyClientConfig, ProxyProtocolClient};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = ProxyClientConfig {
    /// #     proxy_url: "ws://localhost:8080".to_string(),
    /// #     identity_keypair: None,
    /// # };
    /// let mut client = ProxyProtocolClient::new(config);
    /// client.connect().await?;
    ///
    /// // Get destination fingerprint from rendezvous lookup
    /// // let destination = ...; // from IncomingMessage::IdentityInfo
    ///
    /// // Send encrypted message
    /// // let payload = encrypt_message(b"Hello!")?;
    /// // client.send_to(destination, payload).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_to(
        &self,
        destination: IdentityFingerprint,
        payload: Vec<u8>,
    ) -> Result<(), ProxyError> {
        // Check authenticated
        {
            let state = self.state.lock().await;
            if !matches!(*state, ClientState::Authenticated { .. }) {
                return Err(ProxyError::NotConnected);
            }
        }

        // Create Send message without source (server will add it)
        let msg = Messages::Send {
            source: None,
            destination,
            payload,
        };

        let json = serde_json::to_string(&msg)?;

        // Send via outgoing_tx channel
        if let Some(tx) = &self.outgoing_tx {
            tx.send(Message::Text(json))
                .map_err(|_| ProxyError::ChannelSendFailed)?;
            Ok(())
        } else {
            Err(ProxyError::NotConnected)
        }
    }

    /// Request a rendezvous code from the server.
    ///
    /// The server will generate a temporary code (format: "ABC-DEF-GHI") that maps to your
    /// identity. The code will be delivered via [`IncomingMessage::RendevouzInfo`] on the
    /// channel returned by [`connect()`](ProxyProtocolClient::connect).
    ///
    /// # Rendezvous Code Properties
    ///
    /// - Format: 9 alphanumeric characters (e.g., "ABC-DEF-GHI")
    /// - Lifetime: 5 minutes
    /// - Single-use: deleted after lookup
    /// - Enables peer discovery without sharing long-lived identifiers
    ///
    /// # Usage Pattern
    ///
    /// 1. Call this method to request a code
    /// 2. Receive the code via [`IncomingMessage::RendevouzInfo`]
    /// 3. Share the code with a peer (e.g., display as QR code)
    /// 4. Peer uses [`request_identity()`](ProxyProtocolClient::request_identity) to look up your identity
    ///
    /// # Authentication Required
    ///
    /// This method requires an active authenticated connection.
    ///
    /// # Errors
    ///
    /// - [`ProxyError::NotConnected`] if not connected or not authenticated
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bw_proxy_client::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = ProxyClientConfig {
    /// #     proxy_url: "ws://localhost:8080".to_string(),
    /// #     identity_keypair: None,
    /// # };
    /// let mut client = ProxyProtocolClient::new(config);
    /// let mut incoming = client.connect().await?;
    ///
    /// // Request a code
    /// client.request_rendezvous().await?;
    ///
    /// // Wait for response
    /// if let Some(IncomingMessage::RendevouzInfo(code)) = incoming.recv().await {
    ///     println!("Share this code: {}", code.as_str());
    ///     // Display as QR code, send via messaging, etc.
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn request_rendezvous(&self) -> Result<(), ProxyError> {
        // Check authenticated
        {
            let state = self.state.lock().await;
            if !matches!(*state, ClientState::Authenticated { .. }) {
                return Err(ProxyError::NotConnected);
            }
        }

        // Send GetRendevouz message
        let msg = Messages::GetRendevouz;
        let json = serde_json::to_string(&msg)?;

        // Send via outgoing_tx channel
        if let Some(tx) = &self.outgoing_tx {
            tx.send(Message::Text(json))
                .map_err(|_| ProxyError::ChannelSendFailed)?;
            Ok(())
        } else {
            Err(ProxyError::NotConnected)
        }
    }

    /// Look up a peer's identity using a rendezvous code.
    ///
    /// Queries the server for the identity associated with a rendezvous code.
    /// If the code is valid and hasn't expired, the server responds with
    /// [`IncomingMessage::IdentityInfo`] containing the peer's identity and fingerprint.
    ///
    /// # Code Consumption
    ///
    /// Rendezvous codes are single-use. After successful lookup, the server deletes
    /// the code and it cannot be used again.
    ///
    /// # Authentication Required
    ///
    /// This method requires an active authenticated connection.
    ///
    /// # Errors
    ///
    /// - [`ProxyError::NotConnected`] if not connected or not authenticated
    ///
    /// The server may not respond if the code is invalid, expired, or already used.
    /// Implement a timeout when waiting for the response.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bw_proxy_client::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage, RendevouzCode};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = ProxyClientConfig {
    /// #     proxy_url: "ws://localhost:8080".to_string(),
    /// #     identity_keypair: None,
    /// # };
    /// let mut client = ProxyProtocolClient::new(config);
    /// let mut incoming = client.connect().await?;
    ///
    /// // Get code from user (e.g., QR scan, text input)
    /// let code = RendevouzCode::from_string("ABC-DEF-GHI".to_string());
    ///
    /// // Look up the identity
    /// client.request_identity(code).await?;
    ///
    /// // Wait for response with timeout
    /// match tokio::time::timeout(
    ///     tokio::time::Duration::from_secs(5),
    ///     incoming.recv()
    /// ).await {
    ///     Ok(Some(IncomingMessage::IdentityInfo { fingerprint, identity })) => {
    ///         println!("Found peer: {:?}", fingerprint);
    ///         // Now you can send messages to this peer
    ///         // client.send_to(fingerprint, payload).await?;
    ///     }
    ///     _ => {
    ///         println!("Code not found or expired");
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn request_identity(&self, rendezvous_code: RendevouzCode) -> Result<(), ProxyError> {
        // Check authenticated
        {
            let state = self.state.lock().await;
            if !matches!(*state, ClientState::Authenticated { .. }) {
                return Err(ProxyError::NotConnected);
            }
        }

        // Send GetIdentity message
        let msg = Messages::GetIdentity(rendezvous_code);
        let json = serde_json::to_string(&msg)?;

        // Send via outgoing_tx channel
        if let Some(tx) = &self.outgoing_tx {
            tx.send(Message::Text(json))
                .map_err(|_| ProxyError::ChannelSendFailed)?;
            Ok(())
        } else {
            Err(ProxyError::NotConnected)
        }
    }

    /// Get this client's identity fingerprint.
    ///
    /// Returns the SHA256 fingerprint of the client's public key. This is the
    /// identifier that other clients use to send messages to this client.
    ///
    /// The fingerprint is available immediately after creating the client, before
    /// connecting.
    ///
    /// # Examples
    ///
    /// ```
    /// use bw_proxy_client::{ProxyClientConfig, ProxyProtocolClient};
    ///
    /// let config = ProxyClientConfig {
    ///     proxy_url: "ws://localhost:8080".to_string(),
    ///     identity_keypair: None,
    /// };
    /// let client = ProxyProtocolClient::new(config);
    /// println!("My fingerprint: {:?}", client.fingerprint());
    /// ```
    pub fn fingerprint(&self) -> IdentityFingerprint {
        self.identity.identity().fingerprint()
    }

    /// Check if the client is currently authenticated.
    ///
    /// Returns `true` if the client has completed authentication and can send/receive
    /// messages. Returns `false` if disconnected or still connecting.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bw_proxy_client::{ProxyClientConfig, ProxyProtocolClient};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = ProxyClientConfig {
    /// #     proxy_url: "ws://localhost:8080".to_string(),
    /// #     identity_keypair: None,
    /// # };
    /// let mut client = ProxyProtocolClient::new(config);
    ///
    /// assert!(!client.is_authenticated().await);
    ///
    /// client.connect().await?;
    /// assert!(client.is_authenticated().await);
    ///
    /// client.disconnect().await?;
    /// assert!(!client.is_authenticated().await);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn is_authenticated(&self) -> bool {
        matches!(*self.state.lock().await, ClientState::Authenticated { .. })
    }

    /// Disconnect from the proxy server and clean up resources.
    ///
    /// Aborts background tasks, closes the WebSocket connection, and resets state.
    /// After disconnecting, you can call [`connect()`](ProxyProtocolClient::connect)
    /// again to reconnect.
    ///
    /// This method is automatically called when the client is dropped, but calling it
    /// explicitly allows you to handle errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bw_proxy_client::{ProxyClientConfig, ProxyProtocolClient};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = ProxyClientConfig {
    /// #     proxy_url: "ws://localhost:8080".to_string(),
    /// #     identity_keypair: None,
    /// # };
    /// let mut client = ProxyProtocolClient::new(config);
    /// client.connect().await?;
    ///
    /// // Do work...
    ///
    /// // Clean disconnect
    /// client.disconnect().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn disconnect(&mut self) -> Result<(), ProxyError> {
        // Abort tasks
        if let Some(handle) = self.read_task_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.write_task_handle.take() {
            handle.abort();
        }

        // Clear state
        *self.state.lock().await = ClientState::Disconnected;

        // Close channels
        self.outgoing_tx = None;

        Ok(())
    }

    /// Write task: sends messages from channel to WebSocket
    async fn write_task(mut ws_sink: WsSink, mut outgoing_rx: mpsc::UnboundedReceiver<Message>) {
        while let Some(msg) = outgoing_rx.recv().await {
            if ws_sink.send(msg).await.is_err() {
                break;
            }
        }
    }

    /// Read task: handles authentication and routes messages
    async fn read_task(
        mut ws_source: WsSource,
        outgoing_tx: mpsc::UnboundedSender<Message>,
        incoming_tx: mpsc::UnboundedSender<IncomingMessage>,
        identity: Arc<IdentityKeyPair>,
        state: Arc<Mutex<ClientState>>,
        auth_tx: mpsc::UnboundedSender<Result<(), ProxyError>>,
    ) {
        // Handle authentication
        match Self::handle_authentication(&mut ws_source, &outgoing_tx, &identity).await {
            Ok(fingerprint) => {
                *state.lock().await = ClientState::Authenticated { fingerprint };
                // Notify that authentication succeeded
                let _ = auth_tx.send(Ok(()));
            }
            Err(e) => {
                tracing::error!("Authentication failed: {}", e);
                *state.lock().await = ClientState::Disconnected;
                // Notify that authentication failed
                let _ = auth_tx.send(Err(e));
                return;
            }
        }

        // Enter message loop
        if let Err(e) = Self::message_loop(ws_source, incoming_tx).await {
            tracing::error!("Message loop error: {}", e);
        }

        *state.lock().await = ClientState::Disconnected;
    }

    /// Handle authentication challenge-response
    async fn handle_authentication(
        ws_source: &mut WsSource,
        outgoing_tx: &mpsc::UnboundedSender<Message>,
        identity: &Arc<IdentityKeyPair>,
    ) -> Result<IdentityFingerprint, ProxyError> {
        // Receive AuthChallenge
        let challenge_msg = ws_source
            .next()
            .await
            .ok_or(ProxyError::ConnectionClosed)?
            .map_err(ws_err)?;

        let challenge = match challenge_msg {
            Message::Text(text) => match serde_json::from_str::<Messages>(&text)? {
                Messages::AuthChallenge(c) => c,
                _ => return Err(ProxyError::InvalidMessage("Expected AuthChallenge".into())),
            },
            _ => return Err(ProxyError::InvalidMessage("Expected text message".into())),
        };

        // Sign challenge
        let response = challenge.sign(identity);
        let auth_response = Messages::AuthResponse(identity.identity(), response);
        let auth_json = serde_json::to_string(&auth_response)?;

        // Send auth response
        outgoing_tx
            .send(Message::Text(auth_json))
            .map_err(|_| ProxyError::ChannelSendFailed)?;

        // Authentication complete - server doesn't send confirmation
        Ok(identity.identity().fingerprint())
    }

    /// Message loop: routes incoming messages to channel
    async fn message_loop(
        mut ws_source: WsSource,
        incoming_tx: mpsc::UnboundedSender<IncomingMessage>,
    ) -> Result<(), ProxyError> {
        while let Some(msg_result) = ws_source.next().await {
            let msg = msg_result.map_err(ws_err)?;

            match msg {
                Message::Text(text) => {
                    let parsed: Messages = serde_json::from_str(&text)?;
                    match parsed {
                        Messages::Send {
                            source,
                            destination,
                            payload,
                        } => {
                            // Server always includes source when forwarding messages
                            if let Some(source) = source {
                                incoming_tx
                                    .send(IncomingMessage::Send {
                                        source,
                                        destination,
                                        payload,
                                    })
                                    .ok();
                            } else {
                                tracing::warn!("Received Send message without source");
                            }
                        }
                        Messages::RendevouzInfo(code) => {
                            incoming_tx.send(IncomingMessage::RendevouzInfo(code)).ok();
                        }
                        Messages::IdentityInfo {
                            fingerprint,
                            identity,
                        } => {
                            incoming_tx
                                .send(IncomingMessage::IdentityInfo {
                                    fingerprint,
                                    identity,
                                })
                                .ok();
                        }
                        Messages::GetIdentity(_) => {
                            tracing::warn!("Received GetIdentity (client should not receive this)");
                        }
                        _ => tracing::warn!("Unexpected message type: {:?}", parsed),
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }

        Ok(())
    }
}
