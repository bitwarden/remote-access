//! Wire format packet encoding/decoding for multi-device Noise protocol
//!
//! Defines the on-the-wire packet formats for handshake and transport messages.

use ciborium::{de, ser};
use serde::{Deserialize, Serialize};

use super::ciphersuite::Ciphersuite;
use crate::error::NoiseProtocolError;

/// Message type discriminator (1 byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake message 1 (I → R)
    HandshakeStart = 0x01,
    /// Handshake message 2 (R → I)
    HandshakeFinish = 0x02,

    /// Transport mode encrypted data
    Transport = 0x10,
}

/// Handshake packet format
///
/// Wire format: CBOR-encoded structure containing message type, ciphersuite, and payload
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakePacket {
    pub(crate) message_type: MessageType,
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) payload: Vec<u8>,
}

impl HandshakePacket {
    /// Create a new handshake packet
    pub(crate) fn new(
        message_type: MessageType,
        ciphersuite: Ciphersuite,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            message_type,
            ciphersuite,
            payload,
        }
    }

    /// Encode to wire format using CBOR
    pub fn encode(&self) -> Result<Vec<u8>, NoiseProtocolError> {
        let mut buf = Vec::new();
        ser::into_writer(self, &mut buf).map_err(|_| NoiseProtocolError::CborEncodeFailed)?;
        Ok(buf)
    }

    /// Decode from wire format using CBOR
    pub fn decode(data: &[u8]) -> Result<Self, NoiseProtocolError> {
        de::from_reader(data).map_err(|_| NoiseProtocolError::CborDecodeFailed)
    }
}

/// Transport packet format
///
/// Wire format: CBOR-encoded structure containing ciphersuite, nonce, timestamp, ciphertext, and AAD
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportPacket {
    pub(crate) nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) aad: Vec<u8>,
}

impl TransportPacketAad {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ser::into_writer(self, &mut buf).expect("should encode");
        buf
    }

    pub(crate) fn decode(data: &[u8]) -> Result<Self, NoiseProtocolError> {
        de::from_reader(data).map_err(|_| NoiseProtocolError::CborDecodeFailed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportPacketAad {
    pub(crate) timestamp: u64,
    pub(crate) chain_counter: u64,
    pub(crate) ciphersuite: Ciphersuite,
}

impl TransportPacket {
    /// Encode to wire format using CBOR
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ser::into_writer(self, &mut buf).expect("should encode");
        buf
    }

    /// Decode from wire format using CBOR
    pub fn decode(data: &[u8]) -> Result<Self, NoiseProtocolError> {
        de::from_reader(data).map_err(|_| NoiseProtocolError::CborDecodeFailed)
    }
}

#[cfg(test)]
mod tests {
    use crate::{HandshakePacket, MessageType, TransportPacket, ciphersuite::Ciphersuite};

    #[test]
    fn handshake_packet_roundtrip() {
        let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let packet = HandshakePacket::new(
            MessageType::HandshakeFinish,
            Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035,
            payload,
        );
        let encoded = packet.encode().expect("should encode packet");
        let decoded = HandshakePacket::decode(&encoded).expect("should decode packet");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn transport_packet_roundtrip() {
        let packet = TransportPacket {
            nonce: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            ciphertext: vec![0x10, 0x20, 0x30, 0x40],
            aad: vec![0xAA, 0xBB],
        };
        let encoded = packet.encode();
        let decoded = TransportPacket::decode(&encoded).expect("should decode packet");
        assert_eq!(decoded, packet);
    }
}
