use crate::{
    auth::{Identity, IdentityFingerprint},
    rendevouz::RendevouzCode,
};
#[cfg(feature = "native")]
use crate::auth::IdentityKeyPair;

/// Configuration for creating a proxy client.
///
/// # Examples
///
/// Create a client with a new identity:
///
/// ```
/// use bw_proxy::ProxyClientConfig;
///
/// let config = ProxyClientConfig {
///     proxy_url: "ws://localhost:8080".to_string(),
///     identity_keypair: None, // Will generate a new identity
/// };
/// ```
///
/// Create a client with an existing identity:
///
/// ```
/// use bw_proxy::{ProxyClientConfig, IdentityKeyPair};
///
/// let keypair = IdentityKeyPair::generate();
/// let config = ProxyClientConfig {
///     proxy_url: "ws://localhost:8080".to_string(),
///     identity_keypair: Some(keypair),
/// };
/// ```
#[cfg(feature = "native")]
pub struct ProxyClientConfig {
    /// WebSocket URL of the proxy server.
    ///
    /// Format: `ws://host:port` or `wss://host:port` for TLS.
    ///
    /// # Examples
    /// - `"ws://localhost:8080"` - Local development
    /// - `"wss://proxy.example.com:443"` - Production with TLS
    pub proxy_url: String,

    /// Optional identity keypair.
    ///
    /// If `None`, a new random identity will be generated on each connection.
    /// If `Some`, the provided identity will be used for authentication.
    ///
    /// Use [`IdentityKeyPair::generate()`] to create a new identity, or
    /// [`IdentityKeyPair::from_seed()`] to restore a previously saved identity.
    pub identity_keypair: Option<IdentityKeyPair>,
}

/// Messages received by the client from the proxy server.
///
/// These messages are delivered via the channel returned by
/// [`ProxyProtocolClient::connect()`](crate::ProxyProtocolClient::connect).
///
/// # Examples
///
/// ```no_run
/// use bw_proxy::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ProxyClientConfig {
///     proxy_url: "ws://localhost:8080".to_string(),
///     identity_keypair: None,
/// };
/// let mut client = ProxyProtocolClient::new(config);
/// let mut incoming = client.connect().await?;
///
/// while let Some(msg) = incoming.recv().await {
///     match msg {
///         IncomingMessage::Send { source, payload, .. } => {
///             println!("Message from {:?}: {} bytes", source, payload.len());
///         }
///         IncomingMessage::RendevouzInfo(code) => {
///             println!("Your rendezvous code: {}", code.as_str());
///         }
///         IncomingMessage::IdentityInfo { identity, .. } => {
///             println!("Found peer: {:?}", identity.fingerprint());
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub enum IncomingMessage {
    /// Server responded with a rendezvous code.
    ///
    /// Received in response to [`ProxyProtocolClient::request_rendezvous()`](crate::ProxyProtocolClient::request_rendezvous).
    /// The code can be shared with other clients to enable them to discover your identity.
    ///
    /// Codes expire after 5 minutes and are single-use.
    RendevouzInfo(RendevouzCode),

    /// Server responded with a peer's identity.
    ///
    /// Received in response to [`ProxyProtocolClient::request_identity()`](crate::ProxyProtocolClient::request_identity).
    /// Contains the full identity and fingerprint of the peer who created the rendezvous code.
    ///
    /// After receiving this, you can send messages to the peer using their fingerprint.
    IdentityInfo {
        /// SHA256 fingerprint of the peer's identity
        fingerprint: IdentityFingerprint,
        /// The peer's full public identity
        identity: Identity,
    },

    /// Received a message from another client.
    ///
    /// The `source` is cryptographically verified by the proxy server - it cannot be forged.
    /// The `payload` should be decrypted or validated by the receiving client, as the proxy
    /// does not inspect message contents.
    Send {
        /// The sender's fingerprint (validated by proxy)
        source: IdentityFingerprint,
        /// Your fingerprint (the recipient)
        destination: IdentityFingerprint,
        /// Arbitrary message payload (should be encrypted by clients)
        payload: Vec<u8>,
    },
}

/// Internal client connection state
#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientState {
    Disconnected,
    Connected,
    Authenticated { fingerprint: IdentityFingerprint },
}
