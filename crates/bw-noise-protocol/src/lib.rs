//! Noise Protocol implementation for bw_remote.
//!
//! This crate provides a multi-device Noise Protocol implementation using the NNpsk2 pattern
//! for secure channel establishment with PSK-based authentication.
//!
//! Provides protocol with forward secrecy and break-in recovery,
//! supporting both classical and post-quantum cryptography.
//!
#![doc = include_str!("../README.md")]

/// Error types for the Noise Protocol implementation
pub mod error;

mod ciphersuite;
mod handshake;
mod packet;
mod persistence;
mod psk;
mod symmetric_key;
mod transport;

// Re-export error types
pub use error::NoiseProtocolError;

// Re-export protocol types for convenience
pub use ciphersuite::Ciphersuite;
pub use handshake::{HandshakeFingerprint, InitiatorHandshake, ResponderHandshake};
pub use packet::{HandshakePacket, MessageType, TransportPacket};
pub use persistence::PersistentTransportState;
pub use psk::Psk;
pub use transport::MultiDeviceTransport;

const MAX_NOISE_MESSAGE_SIZE: usize = 65535;
