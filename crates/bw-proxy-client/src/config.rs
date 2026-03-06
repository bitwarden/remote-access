use bw_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};

/// Configuration for creating a proxy client.
///
/// # Examples
///
/// Create a client with a new identity:
///
/// ```
/// use bw_proxy_client::ProxyClientConfig;
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
/// use bw_proxy_client::{ProxyClientConfig, IdentityKeyPair};
///
/// let keypair = IdentityKeyPair::generate();
/// let config = ProxyClientConfig {
///     proxy_url: "ws://localhost:8080".to_string(),
///     identity_keypair: Some(keypair),
/// };
/// ```
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

/// Internal client connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientState {
    Disconnected,
    Connected,
    Authenticated { fingerprint: IdentityFingerprint },
}
