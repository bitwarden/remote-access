//! Error types for the remote client

use ap_error::ap_error;
use thiserror::Error;

/// Errors that can occur in the remote client
#[ap_error(flat)]
#[derive(Debug, Error)]
pub enum ClientError {
    /// Failed to connect to the proxy server
    #[error("Failed to connect to proxy: {0}")]
    ConnectionFailed(String),

    /// WebSocket error occurred
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    /// Authentication with proxy failed
    #[error("Proxy authentication failed: {0}")]
    ProxyAuthFailed(String),

    /// Invalid pairing code format
    #[error("Invalid pairing code: {0}")]
    InvalidPairingCode(String),

    /// Noise protocol error
    #[error("Noise protocol error: {0}")]
    NoiseProtocol(String),

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Timeout waiting for response
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Secure channel not established
    #[error("Secure channel not established")]
    SecureChannelNotEstablished,

    /// Client not initialized
    #[error("Client not initialized - call connect() first")]
    NotInitialized,

    /// Credential request failed
    #[error("Credential request failed: {0}")]
    CredentialRequestFailed(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Connection cache error
    #[error("Connection cache error: {0}")]
    ConnectionCache(String),

    /// Keypair storage error
    #[error("Keypair storage error: {0}")]
    KeypairStorage(String),

    /// Channel closed unexpectedly
    #[error("Channel closed")]
    ChannelClosed,

    /// Identity storage error
    #[error("Identity storage error: {0}")]
    IdentityStorageFailed(String),

    /// Rendezvous code resolution failed
    #[error("Rendezvous resolution failed: {0}")]
    RendezvousResolutionFailed(String),

    /// Invalid rendezvous code format
    #[error("Invalid rendezvous code: {0}")]
    InvalidRendezvousCode(String),

    /// User rejected fingerprint verification
    #[error("Fingerprint verification rejected by user")]
    FingerprintRejected,

    /// Invalid state for operation
    #[error("Invalid state: expected {expected}, got {current}")]
    InvalidState { expected: String, current: String },

    /// Connection not found for fingerprint
    #[error("Connection not found for fingerprint")]
    ConnectionNotFound,
}

impl From<ap_noise::error::NoiseProtocolError> for ClientError {
    fn from(err: ap_noise::error::NoiseProtocolError) -> Self {
        ClientError::NoiseProtocol(err.to_string())
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(err: serde_json::Error) -> Self {
        ClientError::Serialization(err.to_string())
    }
}

impl From<ap_proxy_protocol::ProxyError> for ClientError {
    fn from(err: ap_proxy_protocol::ProxyError) -> Self {
        ClientError::ConnectionFailed(err.to_string())
    }
}
