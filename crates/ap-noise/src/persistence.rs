//! State persistence for multi-device transport
//!
//! This module provides serialization and deserialization of transport state
//! using CBOR encoding. Only transport state can be persisted - handshake state
//! contains ephemeral keys and cannot be safely serialized.

use serde::{Deserialize, Serialize};

use super::ciphersuite::Ciphersuite;
use super::transport::MultiDeviceTransport;
use crate::error::NoiseProtocolError;
use crate::symmetric_key::SymmetricKey;

/// Persistent transport state
///
/// Contains all necessary information to restore a transport session:
/// - Cipher suite in use
/// - Send and receive keys
/// - Send and receive rekey counters
/// - Last rekeyed timestamp
/// - Rekey interval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentTransportState {
    /// Cipher suite
    ciphersuite: Ciphersuite,
    /// Send key (32 bytes)
    send_key: SymmetricKey,
    /// Receive key (32 bytes)
    recv_key: SymmetricKey,
    /// Send rekey counter
    send_rekey_counter: u64,
    /// Receive rekey counter
    recv_rekey_counter: u64,
    /// Last rekeyed timestamp
    last_rekeyed_time: u64,
    /// Rekey interval in seconds
    rekey_interval: u64,
}

impl From<&MultiDeviceTransport> for PersistentTransportState {
    fn from(transport: &MultiDeviceTransport) -> Self {
        let (send_key, recv_key) = transport.keys();

        Self {
            ciphersuite: transport.ciphersuite(),
            send_key,
            recv_key,
            send_rekey_counter: transport.send_rekey_counter(),
            recv_rekey_counter: transport.recv_rekey_counter(),
            last_rekeyed_time: transport.last_rekeyed_time(),
            rekey_interval: transport.rekey_interval(),
        }
    }
}

impl From<PersistentTransportState> for MultiDeviceTransport {
    fn from(state: PersistentTransportState) -> Self {
        MultiDeviceTransport::restore_from_state(
            state.ciphersuite,
            state.send_key,
            state.recv_key,
            state.send_rekey_counter,
            state.recv_rekey_counter,
            state.last_rekeyed_time,
            state.rekey_interval,
        )
    }
}

impl PersistentTransportState {
    /// Serialize to CBOR bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, NoiseProtocolError> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes)
            .map_err(|_| NoiseProtocolError::CborEncodeFailed)?;
        Ok(bytes)
    }

    /// Deserialize from CBOR bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NoiseProtocolError> {
        ciborium::de::from_reader(bytes).map_err(|_| NoiseProtocolError::CborDecodeFailed)
    }
}

/// Convenience functions for direct transport serialization
impl MultiDeviceTransport {
    /// Serialize transport state to CBOR bytes
    pub fn save_state(&self) -> Result<Vec<u8>, NoiseProtocolError> {
        let persistent: PersistentTransportState = self.into();
        persistent.to_bytes()
    }

    /// Restore transport state from CBOR bytes
    pub fn restore_state(bytes: &[u8]) -> Result<Self, NoiseProtocolError> {
        let persistent = PersistentTransportState::from_bytes(bytes)?;
        Ok(persistent.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric_key::{SYMMETRIC_KEY_TEST_VECTOR_1, SYMMETRIC_KEY_TEST_VECTOR_2};

    fn setup_sender_receiver() -> (MultiDeviceTransport, MultiDeviceTransport) {
        let send_key = SYMMETRIC_KEY_TEST_VECTOR_1;
        let recv_key = SYMMETRIC_KEY_TEST_VECTOR_2;

        // Use variables for swapped keys
        let sender_send_key = send_key.clone();
        let sender_recv_key = recv_key.clone();
        let receiver_send_key = recv_key.clone();
        let receiver_recv_key = send_key.clone();

        let sender = MultiDeviceTransport::new(
            Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035,
            sender_send_key,
            sender_recv_key,
        );

        let receiver = MultiDeviceTransport::new(
            Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035,
            receiver_send_key,
            receiver_recv_key,
        );

        (sender, receiver)
    }

    #[test]
    fn test_persistent_state_roundtrip() {
        let (mut sender, _) = setup_sender_receiver();
        sender.set_send_rekey_counter(42);
        sender.set_recv_rekey_counter(43);
        sender.set_last_rekeyed_time(1000);

        // Convert to persistent state
        let persistent: PersistentTransportState = (&sender).into();
        let restored: MultiDeviceTransport = persistent.into();

        assert_eq!(
            restored.ciphersuite(),
            Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035
        );
        assert_eq!(restored.send_rekey_counter(), 42);
        assert_eq!(restored.recv_rekey_counter(), 43);
        assert_eq!(restored.last_rekeyed_time(), 1000);

        assert_eq!(sender.send_key(), restored.send_key());
        assert_eq!(sender.recv_key(), restored.recv_key());
    }
}
