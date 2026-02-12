//! Error types for the remote client

use bw_error::bw_error;
use thiserror::Error;

/// Errors that can occur in the remote client
#[bw_error(flat)]
#[derive(Debug, Error)]
pub enum RemoteClientError {
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

    /// Session cache error
    #[error("Session cache error: {0}")]
    SessionCache(String),

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
    RendevouzResolutionFailed(String),

    /// Invalid rendezvous code format
    #[error("Invalid rendezvous code: {0}")]
    InvalidRendevouzCode(String),

    /// User rejected fingerprint verification
    #[error("Fingerprint verification rejected by user")]
    FingerprintRejected,

    /// Invalid state for operation
    #[error("Invalid state: expected {expected}, got {current}")]
    InvalidState { expected: String, current: String },

    /// Session not found for fingerprint
    #[error("Session not found for fingerprint")]
    SessionNotFound,
}

impl From<bw_noise_protocol::error::NoiseProtocolError> for RemoteClientError {
    fn from(err: bw_noise_protocol::error::NoiseProtocolError) -> Self {
        RemoteClientError::NoiseProtocol(err.to_string())
    }
}

impl From<serde_json::Error> for RemoteClientError {
    fn from(err: serde_json::Error) -> Self {
        RemoteClientError::Serialization(err.to_string())
    }
}

impl From<bw_proxy::ProxyError> for RemoteClientError {
    fn from(err: bw_proxy::ProxyError) -> Self {
        RemoteClientError::ConnectionFailed(err.to_string())
    }
}
