//! Error types for the Noise Protocol implementation

use bw_error::bw_error;
use thiserror::Error;

/// Errors that can occur during Noise Protocol operations
#[bw_error(flat)]
#[derive(Debug, Error)]
pub enum NoiseProtocolError {
    /// Error writing handshake message
    #[error("Write error during handshake")]
    HandshakeWriteError,

    /// Error reading handshake message
    #[error("Read error during handshake")]
    HandshakeReadError,

    /// Failed to split handshake into transport mode
    #[error("Failed to split handshake")]
    HandshakeSplit,

    /// Handshake is not yet complete
    #[error("Handshake not complete")]
    HandshakeNotComplete,

    /// Message decryption failed
    #[error("Decryption failed")]
    DecryptionFailed,

    // Multi-device protocol errors
    /// Unsupported ciphersuite ID
    #[error("Unsupported ciphersuite: {0}")]
    UnsupportedCiphersuite(u8),

    /// Invalid message type
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    /// Ciphersuite mismatch between peers
    #[error("Ciphersuite mismatch")]
    CiphersuiteMismatch,

    /// CBOR encode failed
    #[error("CBOR encode failed")]
    CborEncodeFailed,

    /// CBOR decode failed
    #[error("CBOR decode failed")]
    CborDecodeFailed,

    /// Chain counter desynchronization
    #[error("Desynchronized")]
    Desynchronized,

    /// Message too old (timestamp-based replay protection)
    #[error("Message too old: timestamp={timestamp}, now={now}")]
    MessageTooOld { timestamp: u64, now: u64 },

    /// Message from future (timestamp-based validation)
    #[error("Message from future: timestamp={timestamp}, now={now}")]
    MessageFromFuture { timestamp: u64, now: u64 },

    /// Replay detected (duplicate nonce)
    #[error("Replay detected: duplicate nonce")]
    ReplayDetected,

    /// Rekey operation failed
    #[error("Rekey operation failed")]
    RekeyFailed,

    /// Encryption failed during transport
    #[error("Transport encryption failed")]
    TransportEncryptionFailed,

    /// Decryption failed during transport
    #[error("Transport decryption failed")]
    TransportDecryptionFailed,

    /// Invalid PSK length (must be 32 bytes)
    #[error("Invalid PSK length")]
    InvalidPskLength,

    /// Invalid PSK encoding (e.g., invalid base64)
    #[error("Invalid PSK encoding")]
    InvalidPskEncoding,
}
