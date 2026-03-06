//! Error types for proxy operations.
//!
//! This module defines all error conditions that can occur during proxy client
//! and server operations.

use crate::auth::IdentityFingerprint;
use thiserror::Error;

/// Errors that can occur during proxy client or server operations.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// WebSocket connection or communication error.
    ///
    /// Occurs when the underlying WebSocket connection fails, including network
    /// errors, protocol violations, or connection drops.
    ///
    /// # Example
    /// ```text
    /// WebSocket error: Connection refused (os error 61)
    /// ```
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    /// Client authentication failed.
    ///
    /// Occurs when:
    /// - The client's signature verification fails
    /// - The challenge response is invalid
    /// - The authentication handshake times out
    ///
    /// # Example
    /// ```text
    /// Authentication failed: Invalid signature
    /// ```
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Attempted to send a message to a client that is not connected.
    ///
    /// Occurs when sending a message to a fingerprint that:
    /// - Never connected to the proxy
    /// - Has disconnected
    /// - Does not exist
    ///
    /// # Example
    /// ```text
    /// Destination not found: IdentityFingerprint("abc123...")
    /// ```
    #[error("Destination not found: {0:?}")]
    DestinationNotFound(IdentityFingerprint),

    /// Failed to serialize or deserialize a message.
    ///
    /// Occurs when JSON encoding/decoding fails, usually due to:
    /// - Corrupted message data
    /// - Protocol version mismatch
    /// - Invalid message format
    #[error("Message serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The WebSocket connection has been closed.
    ///
    /// Occurs when attempting operations on a closed connection, either due to:
    /// - Normal disconnection
    /// - Network failure
    /// - Server shutdown
    #[error("Connection closed")]
    ConnectionClosed,

    /// Received a message that violates the protocol.
    ///
    /// Occurs when:
    /// - A message is received in the wrong protocol phase
    /// - Required authentication is missing
    /// - Message format is invalid
    ///
    /// # Example
    /// ```text
    /// Invalid message: Cannot send messages before authentication
    /// ```
    #[error("Invalid message: {0}")]
    InvalidMessage(String),

    /// Underlying I/O operation failed.
    ///
    /// Occurs during file operations, socket operations, or other I/O tasks.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Attempted an operation that requires an active connection.
    ///
    /// Occurs when calling methods like `send_to()` before calling `connect()`.
    #[error("Not connected")]
    NotConnected,

    /// Attempted to connect when already connected.
    ///
    /// Occurs when calling `connect()` multiple times without disconnecting.
    #[error("Already connected")]
    AlreadyConnected,

    /// Authentication handshake did not complete within the timeout period.
    ///
    /// Occurs when the client fails to respond to the authentication challenge
    /// in time. Default timeout is implementation-defined.
    #[error("Authentication timeout")]
    AuthenticationTimeout,

    /// Failed to send a message through an internal channel.
    ///
    /// Occurs when internal message passing fails, usually because:
    /// - The receiving end has been dropped
    /// - The channel is closed
    ///
    /// This typically indicates a programming error or resource cleanup issue.
    #[error("Channel send failed")]
    ChannelSendFailed,
}

#[cfg(feature = "native")]
impl From<tokio_tungstenite::tungstenite::Error> for ProxyError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        ProxyError::WebSocket(err.to_string())
    }
}
