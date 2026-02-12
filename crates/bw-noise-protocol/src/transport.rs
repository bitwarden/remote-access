//! Custom transport state with random nonces for multi-device support
//!
//! This module implements transport-layer encryption. In the current implementation, XChaCha20Poly1305
//! is used with with random nonces instead of counter-based nonces. This allows multiple
//! devices to encrypt messages without coordination.
//!
//! Replay protection is implemented using timestamps and a buffer of seen nonces.

use std::collections::BTreeMap;
#[cfg(not(test))]
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use tracing::{error, instrument};

use super::ciphersuite::Ciphersuite;
use super::packet::TransportPacket;
use crate::packet::TransportPacketAad;
use crate::{error::NoiseProtocolError, symmetric_key::SymmetricKey};

/// Maximum message age in seconds (1 day)
const MAX_MESSAGE_AGE: u64 = 86400;
/// Maximum message time in the future (1 minute)
const CLOCK_SKEW_TOLERANCE: u64 = 60;

/// Maximum allowed gap in rekey counter before treating as desynchronized
const MAX_REKEY_GAP: u64 = 1024;

/// Interval between automatic re-keys in seconds
/// Rekey every 24 hours
const REKEY_INTERVAL: u64 = 86400;

/// Transport state for multi-device Noise protocol
///
/// This wraps transport keys extracted from the handshake and provides
/// custom encryption/decryption with random nonces and timestamp-based replay protection.
///
/// # Nonces
/// Nonces are randomly generated for each message. A buffer to protect against replay attacks
/// is maintained. Nonces older than `MAX_MESSAGE_AGE` are pruned periodically. Note: These are stored
/// separately from the persistent device transport state and can be accessed via `seen_nonces()` and `set_seen_nonces()`.
#[derive(Clone, Debug)]
pub struct MultiDeviceTransport {
    /// Cipher suite in use
    ciphersuite: Ciphersuite,

    /// Key for sending (encrypting) messages
    send_key: SymmetricKey,
    /// Send re-key counter
    send_rekey_counter: u64,
    /// Last re-keyed timestamp
    last_rekeyed_time: u64,
    /// Interval between automatic re-keys in seconds
    rekey_interval: u64,

    /// Key for receiving (decrypting) messages
    recv_key: SymmetricKey,
    /// Receive re-key counter
    recv_rekey_counter: u64,

    /// Buffer of seen nonces with their timestamps (for replay protection)
    seen_nonces: BTreeMap<Vec<u8>, u64>,

    timeprovider: Timeprovider,
}

#[derive(Clone, Debug)]
struct Timeprovider {
    #[cfg(test)]
    now: u64,
}

impl Timeprovider {
    fn new() -> Self {
        Timeprovider {
            #[cfg(test)]
            now: 0,
        }
    }

    #[cfg(not(test))]
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before Unix epoch")
            .as_secs()
    }

    #[cfg(test)]
    fn now(&self) -> u64 {
        self.now
    }

    #[cfg(test)]
    fn set_now(&mut self, now: u64) {
        self.now = now;
    }
}

impl MultiDeviceTransport {
    /// Create a new transport state with extracted keys
    pub(crate) fn new(
        ciphersuite: Ciphersuite,
        send_key: SymmetricKey,
        recv_key: SymmetricKey,
    ) -> Self {
        let timeprovider = Timeprovider::new();
        Self {
            ciphersuite,
            send_key,
            send_rekey_counter: 1,
            last_rekeyed_time: timeprovider.now(),
            rekey_interval: REKEY_INTERVAL,
            recv_key,
            recv_rekey_counter: 1,
            seen_nonces: BTreeMap::new(),
            timeprovider: timeprovider,
        }
    }

    /// Prune old nonces from the seen_nonces buffer
    fn prune_old_nonces(&mut self) {
        let now = self.timeprovider.now();
        let cutoff = now.saturating_sub(MAX_MESSAGE_AGE);
        self.seen_nonces
            .retain(|_, &mut timestamp| timestamp >= cutoff);
    }

    /// Check if a nonce has been seen and record it
    fn check_and_record_nonce(
        &mut self,
        packet_aad: &TransportPacketAad,
        packet: &TransportPacket,
    ) -> Result<(), NoiseProtocolError> {
        self.prune_old_nonces();
        if self.seen_nonces.contains_key(&packet.nonce) {
            return Err(NoiseProtocolError::ReplayDetected);
        }
        self.seen_nonces
            .insert(packet.nonce.clone(), packet_aad.timestamp);
        Ok(())
    }

    /// Get a serialized view of seen nonces for persistence
    pub fn seen_nonces(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&self.seen_nonces, &mut buf)
            .expect("should serialize seen nonces");
        buf
    }

    /// Set seen nonces from persisted data
    pub fn set_seen_nonces(&mut self, data: &[u8]) -> Result<(), NoiseProtocolError> {
        let nonces: BTreeMap<Vec<u8>, u64> =
            ciborium::de::from_reader(data).map_err(|_| NoiseProtocolError::CborDecodeFailed)?;
        self.seen_nonces = nonces;
        Ok(())
    }

    /// Get ciphersuite
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    fn rekey_send_if_needed(&mut self) -> Result<(), NoiseProtocolError> {
        // A re-key on the send site happens on the rekey_interval
        let now = self.timeprovider.now();
        while now.saturating_sub(self.last_rekeyed_time) >= self.rekey_interval {
            self.send_key = XChaCha20Poly1305RandomNonceCipher::rekey(&mut self.send_key)?;
            self.send_rekey_counter = self.send_rekey_counter.wrapping_add(1);
            self.last_rekeyed_time += self.rekey_interval;
        }

        Ok(())
    }

    /// Encrypt plaintext into a transport packet
    ///
    /// Uses a random nonce with current timestamp for replay protection.
    #[instrument(level = "debug", fields(ciphersuite = ?self.ciphersuite))]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<TransportPacket, NoiseProtocolError> {
        // Advance the re-key counter if needed
        self.rekey_send_if_needed()?;

        // Make the AAD
        let aad = TransportPacketAad {
            timestamp: self.timeprovider.now(),
            chain_counter: self.send_rekey_counter,
            ciphersuite: self.ciphersuite,
        };

        // Encrypt the message
        let (nonce, ciphertext) =
            XChaCha20Poly1305RandomNonceCipher::encrypt(&self.send_key, plaintext, &aad.encode())?;

        // Encode packet
        let packet = TransportPacket {
            nonce: nonce.to_vec(),
            ciphertext,
            aad: aad.encode(),
        };

        Ok(packet)
    }

    /// Decrypt a transport packet
    #[instrument(level = "debug", fields(ciphersuite = ?self.ciphersuite))]
    pub fn decrypt(&mut self, packet: &TransportPacket) -> Result<Vec<u8>, NoiseProtocolError> {
        let packet_aad = TransportPacketAad::decode(&packet.aad)
            .map_err(|_| NoiseProtocolError::DecryptionFailed)?;

        // Validation
        if packet_aad.ciphersuite != self.ciphersuite {
            error!("Ciphersuite mismatch detected");
            return Err(NoiseProtocolError::CiphersuiteMismatch);
        }
        self.validate_message_timestamp(&packet_aad)?;
        self.check_and_record_nonce(&packet_aad, packet)?;
        self.rekey_receive(&packet_aad)?;

        let packet_decryption_key = if packet_aad.chain_counter == self.recv_rekey_counter {
            self.recv_key.clone()
        } else {
            XChaCha20Poly1305RandomNonceCipher::rekey(&mut self.recv_key)?.clone()
        };

        // Validated, now decrypt
        XChaCha20Poly1305RandomNonceCipher::decrypt(
            &packet_decryption_key,
            &XChaCha20Poly1305Nonce::from_slice(&packet.nonce),
            &packet.ciphertext,
            &packet.aad,
        )
    }

    fn rekey_receive(&mut self, packet_aad: &TransportPacketAad) -> Result<(), NoiseProtocolError> {
        // On receiving a packet, both on the single-device and the device-group-device, scenarios are possible where
        // the message arrives with a *slightly* older key or a much newer key.
        //
        // Scenarios:
        // 1) Single-device sends M messages, device-group-device receives it. Only one device takes message M, and another device takes M+1.
        //    The device-group-device must be able to catch up to M+1 from M-1
        // 2) Device-group-devices A, B send messages to single-device.
        //
        // To fix this, the re-key is time based, so that at maximum two keys are possible, during the transition period. The re-key period
        // must not be too small. Once re-keyed, the old key cannot be re-derived, so we must always be *before* the incoming key or at most
        // equal to in, when viewing the re-keys as a chain of keys. Because of this, we catch up to one before the incoming key, and during decryption
        // optionally re-key once more if needed.

        // If it is older than current, error, if it is the same or one newer do nothing, else catch up until it is 1 under
        if packet_aad.chain_counter < self.recv_rekey_counter {
            // We cannot get older keys, and must discard
            Err(NoiseProtocolError::Desynchronized)
        } else if packet_aad.chain_counter > self.recv_rekey_counter + MAX_REKEY_GAP {
            // Gap is too large, consider desynchronized
            Err(NoiseProtocolError::Desynchronized)
        } else {
            // Rekey up to the needed counter. We want to be one before the incoming packet, just in case the respones arrive
            // slightly out of order / the device group is not synchronized.
            while self.recv_rekey_counter < packet_aad.chain_counter - 1 {
                self.recv_key = XChaCha20Poly1305RandomNonceCipher::rekey(&mut self.recv_key)?;
                self.recv_rekey_counter = self.recv_rekey_counter.wrapping_add(1);
            }
            Ok(())
        }
    }

    /// Validates message timestamp and checks for replay attacks
    fn validate_message_timestamp(
        &mut self,
        packet_aad: &TransportPacketAad,
    ) -> Result<(), NoiseProtocolError> {
        let now = self.timeprovider.now();
        let packet_timestamp = packet_aad.timestamp;

        // Check message is not too old
        if packet_timestamp < now.saturating_sub(MAX_MESSAGE_AGE) {
            error!(
                "Message too old: timestamp={}, now={}, age={}",
                packet_timestamp,
                now,
                now.saturating_sub(packet_timestamp)
            );
            return Err(NoiseProtocolError::MessageTooOld {
                timestamp: packet_timestamp,
                now,
            });
        }

        // Check message is not from the future (with 1-min tolerance)
        if packet_timestamp > now + CLOCK_SKEW_TOLERANCE {
            error!(
                "Message from future: timestamp={}, now={}",
                packet_timestamp, now
            );
            return Err(NoiseProtocolError::MessageFromFuture {
                timestamp: packet_timestamp,
                now,
            });
        }

        Ok(())
    }

    /// Create a transport from persisted state
    pub(crate) fn restore_from_state(
        ciphersuite: Ciphersuite,
        send_key: SymmetricKey,
        recv_key: SymmetricKey,
        send_rekey_counter: u64,
        recv_rekey_counter: u64,
        last_rekeyed_time: u64,
        rekey_interval: u64,
    ) -> Self {
        Self {
            ciphersuite,
            send_key,
            send_rekey_counter,
            last_rekeyed_time,
            rekey_interval,
            recv_key,
            recv_rekey_counter,
            seen_nonces: BTreeMap::new(),
            timeprovider: Timeprovider::new(),
        }
    }

    /// Get send rekey counter for persistence
    pub fn send_rekey_counter(&self) -> u64 {
        self.send_rekey_counter
    }

    /// Get receive rekey counter for persistence
    pub fn recv_rekey_counter(&self) -> u64 {
        self.recv_rekey_counter
    }

    #[cfg(test)]
    pub(crate) fn set_last_rekeyed_time(&mut self, timestamp: u64) {
        self.last_rekeyed_time = timestamp;
    }

    /// Get last rekeyed timestamp for persistence
    pub fn last_rekeyed_time(&self) -> u64 {
        self.last_rekeyed_time
    }

    /// Get rekey interval for persistence
    pub fn rekey_interval(&self) -> u64 {
        self.rekey_interval
    }

    /// Get transport keys for persistence
    pub fn keys(&self) -> (SymmetricKey, SymmetricKey) {
        (self.send_key.clone(), self.recv_key.clone())
    }

    #[cfg(test)]
    pub(crate) fn set_send_rekey_counter(&mut self, counter: u64) {
        self.send_rekey_counter = counter;
    }

    #[cfg(test)]
    #[allow(unused)]
    pub(crate) fn set_recv_rekey_counter(&mut self, counter: u64) {
        self.recv_rekey_counter = counter;
    }

    #[cfg(test)]
    pub(crate) fn send_key(&self) -> SymmetricKey {
        self.send_key.clone()
    }

    #[cfg(test)]
    pub(crate) fn recv_key(&self) -> SymmetricKey {
        self.recv_key.clone()
    }
}

struct XChaCha20Poly1305Nonce([u8; 24]);

impl XChaCha20Poly1305Nonce {
    fn from_slice(slice: &[u8]) -> Self {
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(slice);
        XChaCha20Poly1305Nonce(nonce)
    }

    // A rekey needs a nonce with all bytes set to 0xFF
    fn rekey_max_value() -> Self {
        XChaCha20Poly1305Nonce([0xFF; 24])
    }

    fn generate() -> Self {
        let mut nonce = [0u8; 24];
        let mut rng = rand::thread_rng();
        rand::RngCore::fill_bytes(&mut rng, &mut nonce);
        XChaCha20Poly1305Nonce(nonce)
    }

    fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<&XChaCha20Poly1305Nonce> for XNonce {
    fn from(nonce: &XChaCha20Poly1305Nonce) -> Self {
        *XNonce::from_slice(&nonce.0)
    }
}

struct XChaCha20Poly1305RandomNonceCipher;

impl XChaCha20Poly1305RandomNonceCipher {
    fn rekey(key: &mut SymmetricKey) -> Result<SymmetricKey, NoiseProtocolError> {
        let nonce = XChaCha20Poly1305Nonce::rekey_max_value();
        let empty_key = [0u8; 32];
        let cipher = XChaCha20Poly1305::new(key.as_slice().into());
        let derived = cipher
            .encrypt(
                &(&nonce).into(),
                Payload {
                    msg: &empty_key,
                    aad: &[],
                },
            )
            .map_err(|_| NoiseProtocolError::RekeyFailed)?;
        let mut new_key = [0u8; 32];
        new_key.copy_from_slice(&derived[..32]);
        Ok(SymmetricKey::from_bytes(new_key))
    }

    fn encrypt(
        key: &SymmetricKey,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(XChaCha20Poly1305Nonce, Vec<u8>), NoiseProtocolError> {
        let nonce = XChaCha20Poly1305Nonce::generate();
        let cipher = XChaCha20Poly1305::new(&key.to_bytes().into());
        let ciphertext = cipher
            .encrypt(
                &(&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| NoiseProtocolError::TransportEncryptionFailed)?;

        Ok((nonce, ciphertext))
    }

    fn decrypt(
        key: &SymmetricKey,
        nonce: &XChaCha20Poly1305Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseProtocolError> {
        let cipher = XChaCha20Poly1305::new(&key.to_bytes().into());
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        let plaintext = cipher
            .decrypt(&(nonce).into(), payload)
            .map_err(|_| NoiseProtocolError::TransportDecryptionFailed)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use crate::symmetric_key::{SYMMETRIC_KEY_TEST_VECTOR_1, SYMMETRIC_KEY_TEST_VECTOR_2};
    const PLAINTEXT_TEST_VECTOR: &[u8] = b"Test message for multi-device transport";

    use super::*;

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
    fn test_encrypt_decrypt() {
        let (mut sender, mut receiver) = setup_sender_receiver();
        let packet = sender
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt");

        let decrypted = receiver.decrypt(&packet).expect("should decrypt");
        assert_eq!(PLAINTEXT_TEST_VECTOR, decrypted);
    }

    #[test]
    fn test_replay_detection() {
        let (mut sender, mut receiver) = setup_sender_receiver();
        let packet = sender
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt");

        let _ = receiver.decrypt(&packet).expect("should decrypt");
        let _ = receiver.decrypt(&packet).expect_err("should detect replay");
    }

    #[test]
    fn test_message_too_old() {
        let (mut sender, mut receiver) = setup_sender_receiver();

        // Set receiver time far in the future
        receiver.timeprovider.set_now(2000000000);
        let packet = sender
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt");

        // Since the packet timestamp is far in the past compared to the receiver, it should be rejected
        let _ = receiver
            .decrypt(&packet)
            .expect_err("should detect old message");
    }

    #[test]
    fn test_message_from_future() {
        let (mut sender, mut receiver) = setup_sender_receiver();

        // Set sender time far in the future
        sender.timeprovider.set_now(2000000000);
        let packet = sender
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt");

        // Since the packet timestamp is far in the future compared to the receiver, it should be rejected
        let _ = receiver
            .decrypt(&packet)
            .expect_err("should detect future message");
    }

    #[test]
    fn test_send_rekey() {
        let (mut sender, mut receiver) = setup_sender_receiver();

        // Encrypt message at time=0 (should use counter=1)
        sender.timeprovider.set_now(0);
        let packet1 = sender
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt");

        // Advance time by REKEY_INTERVAL to trigger rekey (counter should become 2)
        sender.timeprovider.set_now(REKEY_INTERVAL);
        let packet2 = sender
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt after rekey");

        // Receiver should decrypt both messages
        receiver
            .decrypt(&packet1)
            .expect("should decrypt first message");
        // Advance receiver time to match sender for second packet
        receiver.timeprovider.set_now(REKEY_INTERVAL);
        receiver
            .decrypt(&packet2)
            .expect("should decrypt second message");

        // Verify send_rekey_counter incremented from 1 to 2
        assert_eq!(sender.send_rekey_counter, 2);
    }

    #[test]
    fn test_receive_rekey_catchup() {
        let (mut sender, mut receiver) = setup_sender_receiver();

        // Advance time and encrypt to trigger rekeys
        receiver.timeprovider.set_now(REKEY_INTERVAL);
        receiver.encrypt(b"msg1").expect("should encrypt"); // Rekey to counter=1
        receiver.timeprovider.set_now(REKEY_INTERVAL * 2);
        receiver.encrypt(b"msg2").expect("should encrypt"); // Rekey to counter=2
        receiver.timeprovider.set_now(REKEY_INTERVAL * 3);
        let packet = receiver
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt"); // Rekey to counter=3

        // Sender's time should be close to receiver's to avoid "message from future" error
        sender.timeprovider.set_now(REKEY_INTERVAL * 3);

        // Sender should catch up from 0 to 3 and decrypt successfully
        let decrypted = sender
            .decrypt(&packet)
            .expect("should decrypt after catchup");
        assert_eq!(decrypted, PLAINTEXT_TEST_VECTOR);
    }

    #[test]
    fn test_desynchronization() {
        let (mut sender, mut receiver) = setup_sender_receiver();
        sender.set_send_rekey_counter(MAX_REKEY_GAP + 2);

        let packet = sender
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt");

        let result = receiver.decrypt(&packet);
        assert!(result.is_err());
        assert!(matches!(
            result.err(),
            Some(NoiseProtocolError::Desynchronized)
        ));
    }

    #[test]
    fn test_device_group_out_of_order_answers() {
        // If a the single-device makes two requests, and the device-group answers out of order, then this should still decrypt fine
        let (sender, receiver) = setup_sender_receiver();
        let mut single_device = sender;
        let mut device_group_device_1 = receiver.clone();
        let mut device_group_device_2 = receiver;

        // Single device makes two requests
        let packet1 = single_device
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt request1");
        let packet2 = single_device
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt request2");

        // Device group devices answer out of order
        let _ = device_group_device_2
            .decrypt(&packet2)
            .expect("should decrypt request2");
        let response2 = device_group_device_2
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt response2");
        let decrypted_response2 = single_device
            .decrypt(&response2)
            .expect("should decrypt response2");
        assert_eq!(decrypted_response2, PLAINTEXT_TEST_VECTOR);

        let _ = device_group_device_1
            .decrypt(&packet1)
            .expect("should decrypt request1");
        let response1 = device_group_device_1
            .encrypt(PLAINTEXT_TEST_VECTOR)
            .expect("should encrypt response1");
        let decrypted_response1 = single_device
            .decrypt(&response1)
            .expect("should decrypt response1");
        assert_eq!(decrypted_response1, PLAINTEXT_TEST_VECTOR);
    }
}
