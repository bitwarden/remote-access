//! Handshake implementation for multi-device Noise protocol
//!
//! Implements NNpsk2 pattern for both classical (Curve25519) and post-quantum (Kyber768) cipher suites.

use std::fmt::{Debug, Display};

use clatter::crypto::cipher::ChaChaPoly;
use clatter::crypto::dh::X25519;
use clatter::crypto::hash::Sha256;
use clatter::crypto::kem::rust_crypto_ml_kem::MlKem768;
use clatter::handshakepattern::{noise_nn_psk2, noise_pqnn_psk2};
use clatter::traits::Handshaker;
use clatter::{NqHandshake, PqHandshake};
use sha2::Digest;
use tracing::{debug, error, instrument};

use super::ciphersuite::Ciphersuite;
use super::packet::{HandshakePacket, MessageType};
use crate::MAX_NOISE_MESSAGE_SIZE;
use crate::MultiDeviceTransport;
use crate::error::NoiseProtocolError;
use crate::psk::Psk;
use crate::symmetric_key::SymmetricKey;

/// The handshake from the initiator side. The handshake consists of 2 messages:
/// 1. HandshakeInit (I → R)
/// 2. HandshakeResponse (R → I)
///
/// This must be driven by calling [`send_start`] and [`receive_finish`] in order.
pub struct InitiatorHandshake {
    ciphersuite: Ciphersuite,
    inner: HandshakeState,
    complete: bool,
}

impl InitiatorHandshake {
    /// Create a new initiator handshake without PSK authentication.
    ///
    /// This is equivalent to calling `with_psk(ciphersuite, Psk::null())`.
    /// For enhanced security with authentication, use `with_psk()` instead.
    ///
    /// IMPORTANT: This is using a null PSK, so the cosumer *MUST* verify the handshake fingerprint
    /// out-of-band to ensure authenticity of the peer, otherwise a MITM attack is possible.
    pub fn new() -> InitiatorHandshake {
        Self::with_psk(Psk::null())
    }

    /// Create a new initiator handshake with PSK authentication.
    ///
    /// The PSK must be shared with the responder through a secure out-of-band channel
    /// (e.g., QR code, NFC, secure messaging). Both parties must use the same PSK for
    /// the handshake to succeed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bw_noise_protocol::{InitiatorHandshake, Psk};
    ///
    /// let psk = Psk::generate();
    /// // Share psk out-of-band...
    ///
    /// let mut initiator = InitiatorHandshake::with_psk(psk);
    /// ```
    pub fn with_psk(psk: Psk) -> InitiatorHandshake {
        let ciphersuite = Ciphersuite::default();
        Self::with_psk_inner(ciphersuite, psk)
    }

    #[cfg(test)]
    pub fn with_psk_for_testing(ciphersuite: Ciphersuite, psk: Psk) -> InitiatorHandshake {
        Self::with_psk_inner(ciphersuite, psk)
    }

    fn with_psk_inner(ciphersuite: Ciphersuite, psk: Psk) -> InitiatorHandshake {
        let inner = new_handshake(ciphersuite, psk, true);
        InitiatorHandshake {
            ciphersuite,
            inner,
            complete: false,
        }
    }

    /// Create the first handshake message to send to the responder
    pub fn send_start(&mut self) -> Result<HandshakePacket, NoiseProtocolError> {
        write_message(
            &mut self.inner,
            &[],
            MessageType::HandshakeStart,
            self.ciphersuite,
        )
    }

    /// Process the responder's handshake message
    pub fn receive_finish(&mut self, packet: &HandshakePacket) -> Result<(), NoiseProtocolError> {
        if packet.message_type != MessageType::HandshakeFinish {
            error!("Invalid message type received: {:?}", packet.message_type);
            return Err(NoiseProtocolError::InvalidMessageType(
                packet.message_type as u8,
            ));
        }

        read_message(&mut self.inner, packet, self.ciphersuite)?;
        self.complete = true;
        Ok(())
    }

    pub fn finalize(
        self,
    ) -> Result<(MultiDeviceTransport, HandshakeFingerprint), NoiseProtocolError> {
        if !self.complete {
            error!("Attempted to finalize incomplete handshake");
            return Err(NoiseProtocolError::HandshakeNotComplete);
        }

        finalize(self.inner, true, self.ciphersuite)
    }

    pub fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }
}

/// The handshake from the responder side. The handshake consists of 2 messages:
/// 1. HandshakeInit (I → R)
/// 2. HandshakeResponse (R → I)
///
/// This must be driven by calling `receive_one` and `send_two` in order.
pub struct ResponderHandshake {
    ciphersuite: Ciphersuite,
    inner: HandshakeState,
    complete: bool,
}

impl ResponderHandshake {
    /// Create a new responder handshake without PSK authentication.
    ///
    /// This is equivalent to calling `with_psk(ciphersuite, Psk::null())`.
    /// For enhanced security with authentication, use `with_psk()` instead.
    ///
    /// IMPORTANT: This is using a null PSK, so the cosumer *MUST* verify the handshake fingerprint
    /// out-of-band to ensure authenticity of the peer, otherwise a MITM attack is possible.
    pub fn new() -> Self {
        Self::with_psk(Psk::null())
    }

    /// Create a new responder handshake with PSK authentication.
    ///
    /// The PSK must be shared with the initiator through a secure out-of-band channel
    /// (e.g., QR code, NFC, secure messaging). Both parties must use the same PSK for
    /// the handshake to succeed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bw_noise_protocol::{ResponderHandshake, Psk};
    ///
    /// // In a real scenario, receive psk from out-of-band channel
    /// // For this example, we'll generate one
    /// let psk = Psk::generate();
    ///
    /// let mut responder = ResponderHandshake::with_psk(psk);
    /// ```
    pub fn with_psk(psk: Psk) -> Self {
        let ciphersuite = Ciphersuite::default();
        Self::with_psk_inner(ciphersuite, psk)
    }

    #[cfg(test)]
    pub fn with_psk_for_testing(ciphersuite: Ciphersuite, psk: Psk) -> Self {
        Self::with_psk_inner(ciphersuite, psk)
    }

    fn with_psk_inner(ciphersuite: Ciphersuite, psk: Psk) -> Self {
        let inner = new_handshake(ciphersuite, psk, false);
        ResponderHandshake {
            ciphersuite,
            inner,
            complete: false,
        }
    }

    /// Process the initiator's handshake message
    pub fn receive_start(&mut self, packet: &HandshakePacket) -> Result<(), NoiseProtocolError> {
        if packet.message_type != MessageType::HandshakeStart {
            error!("Invalid message type received: {:?}", packet.message_type);
            return Err(NoiseProtocolError::InvalidMessageType(
                packet.message_type as u8,
            ));
        }

        read_message(&mut self.inner, packet, self.ciphersuite)
    }

    /// Create the responder's handshake message to send to the initiator
    pub fn send_finish(&mut self) -> Result<HandshakePacket, NoiseProtocolError> {
        let packet = write_message(
            &mut self.inner,
            &[],
            MessageType::HandshakeFinish,
            self.ciphersuite,
        )?;
        self.complete = true;
        Ok(packet)
    }

    pub fn finalize(
        self,
    ) -> Result<(MultiDeviceTransport, HandshakeFingerprint), NoiseProtocolError> {
        if !self.complete {
            error!("Attempted to finalize incomplete handshake");
            return Err(NoiseProtocolError::HandshakeNotComplete);
        }

        finalize(self.inner, false, self.ciphersuite)
    }
}

#[instrument(skip(psk))]
fn new_handshake(
    ciphersuite: Ciphersuite,
    psk: Psk,
    initiator: bool,
) -> HandshakeState {
    debug!("Creating handshake with PSK");

    match ciphersuite {
        Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035 => {
            let pattern = noise_nn_psk2();
            let mut handshake =
                NqHandshake::new(pattern, &[], initiator, None, None, None, None)
                    .expect("Handshake creation cannot fail");
            handshake.push_psk(psk.as_slice());
            HandshakeState::Classical(Box::new(handshake))
        }
        Ciphersuite::PQNNpsk2_Kyber768_XChaCha20Poly1305 => {
            let pattern = noise_pqnn_psk2();
            let mut handshake =
                PqHandshake::new(pattern, &[], initiator, None, None, None, None)
                    .expect("Handshake creation cannot fail");
            handshake.push_psk(psk.as_slice());
            HandshakeState::PostQuantum(Box::new(handshake))
        }
    }
}

/// Internal handshake state (type-erased to handle both classical and PQ)
enum HandshakeState {
    Classical(Box<NqHandshake<X25519, ChaChaPoly, Sha256>>),
    PostQuantum(Box<PqHandshake<MlKem768, MlKem768, ChaChaPoly, Sha256>>),
}

impl Debug for HandshakeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeState::Classical(_) => write!(f, "HandshakeState::Classical(...)"),
            HandshakeState::PostQuantum(_) => write!(f, "HandshakeState::PostQuantum(...)"),
        }
    }
}

/// Write the next handshake message
///
/// Returns the packet to send to the peer
#[instrument(skip(payload))]
fn write_message(
    mut inner: &mut HandshakeState,
    payload: &[u8],
    message_type: MessageType,
    ciphersuite: Ciphersuite,
) -> Result<HandshakePacket, NoiseProtocolError> {
    debug!("Writing handshake message");
    let mut buf = vec![0u8; MAX_NOISE_MESSAGE_SIZE];

    let len = match &mut inner {
        HandshakeState::Classical(hs) => hs.write_message(payload, &mut buf).map_err(|e| {
            println!("Error writing message: {e:?}");
            NoiseProtocolError::HandshakeWriteError
        })?,
        HandshakeState::PostQuantum(hs) => hs
            .write_message(payload, &mut buf)
            .map_err(|_| NoiseProtocolError::HandshakeWriteError)?,
    };
    buf.truncate(len);
    Ok(HandshakePacket::new(message_type, ciphersuite, buf))
}

/// Read a handshake message from the peer
///
/// Returns the payload contained in the message
#[instrument]
fn read_message(
    inner: &mut HandshakeState,
    packet: &HandshakePacket,
    ciphersuite: Ciphersuite,
) -> Result<(), NoiseProtocolError> {
    if packet.ciphersuite != ciphersuite {
        error!("Ciphersuite mismatch");
        return Err(NoiseProtocolError::CiphersuiteMismatch);
    }

    let mut buf = vec![0u8; MAX_NOISE_MESSAGE_SIZE];
    let len = match inner {
        HandshakeState::Classical(hs) => hs
            .read_message(&packet.payload, &mut buf)
            .map_err(|_| NoiseProtocolError::HandshakeReadError)?,
        HandshakeState::PostQuantum(hs) => hs
            .read_message(&packet.payload, &mut buf)
            .map_err(|_| NoiseProtocolError::HandshakeReadError)?,
    };
    buf.truncate(len);
    Ok(())
}

/// Finalize the handshake and extract raw keys for custom transport
///
/// The keys are extracted from clatter's TransportState
/// For initiator: send_key = initiator_to_responder, recv_key = responder_to_initiator
/// For responder: send_key = responder_to_initiator, recv_key = initiator_to_responder
#[instrument]
fn finalize(
    handshake: HandshakeState,
    initiator: bool,
    ciphersuite: Ciphersuite,
) -> Result<(MultiDeviceTransport, HandshakeFingerprint), NoiseProtocolError> {
    debug!("Finalizing handshake");

    // Extract keys from the transport state, since we implement our own transport state
    let (i2r_key, r2i_key) = match handshake {
        HandshakeState::Classical(hs) => {
            let transport = hs
                .finalize()
                .map_err(|_| NoiseProtocolError::HandshakeSplit)?;

            let cipher_states = transport.take();
            let (i2r_key, _i2r_nonce) = cipher_states.initiator_to_responder.take();
            let (r2i_key, _r2i_nonce) = cipher_states.responder_to_initiator.take();
            (i2r_key, r2i_key)
        }
        HandshakeState::PostQuantum(hs) => {
            let transport = hs
                .finalize()
                .map_err(|_| NoiseProtocolError::HandshakeSplit)?;

            let cipher_states = transport.take();
            let (i2r_key, _i2r_nonce) = cipher_states.initiator_to_responder.take();
            let (r2i_key, _r2i_nonce) = cipher_states.responder_to_initiator.take();

            (i2r_key, r2i_key)
        }
    };

    let i2r_key = SymmetricKey::from_bytes(*i2r_key);
    let r2i_key = SymmetricKey::from_bytes(*r2i_key);

    let fingerprint = HandshakeFingerprint::new(&r2i_key.to_bytes(), &i2r_key.to_bytes());
    debug!("Handshake fingerprint: {}", fingerprint.0);

    // Map keys based on role
    let (send_key, recv_key) = if initiator {
        (i2r_key, r2i_key)
    } else {
        (r2i_key, i2r_key)
    };

    debug!(
        "[Handshake] Keys extracted - {:?}, {:?}",
        send_key, recv_key
    );

    Ok((
        MultiDeviceTransport::new(ciphersuite, send_key, recv_key),
        fingerprint,
    ))
}

/// A low-entropy fingerprint of the Handshake. Since the fingerprint is only ever created after the handshake is complete,
/// it cannot be brute-forced by a MITM to be a certain value, since it depends on the derived keys.
#[derive(Clone, PartialEq, Debug)]
pub struct HandshakeFingerprint(String);

impl HandshakeFingerprint {
    fn new(r2i_key: &[u8], i2r_key: &[u8]) -> Self {
        // To derive the 6 digit hex fingerprint, we concatenate the keys, then hash them.
        // Then, the first 6 bytes are the PIN
        let mut combined = Vec::with_capacity(r2i_key.len() + i2r_key.len());
        combined.extend_from_slice(r2i_key);
        combined.extend_from_slice(i2r_key);
        let hash = sha2::Sha256::digest(&combined);
        let fingerprint = hex::encode(&hash[..3]);
        HandshakeFingerprint(fingerprint)
    }
}

impl Display for HandshakeFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_handshake_without_psk() {
        // Create initiator and responder with null PSK (unauthenticated mode)
        let mut initiator = InitiatorHandshake::new();
        let mut responder = ResponderHandshake::new();

        // Execute handshake
        let start_packet = initiator.send_start().expect("initiator should send start");
        responder
            .receive_start(&start_packet)
            .expect("responder should receive start");
        let finish_packet = responder
            .send_finish()
            .expect("responder should send finish");
        initiator
            .receive_finish(&finish_packet)
            .expect("initiator should receive finish");

        // Finalize and get transports
        let (mut initiator_transport, initiator_fingerprint) =
            initiator.finalize().expect("initiator should finalize");
        let (mut responder_transport, responder_fingerprint) =
            responder.finalize().expect("responder should finalize");

        // Fingerprints must be identical
        assert_eq!(initiator_fingerprint, responder_fingerprint);

        // Messages can be exchanged bidirectionally
        let message = b"Hello from initiator";
        let packet = initiator_transport
            .encrypt(message)
            .expect("initiator should encrypt");
        let decrypted = responder_transport
            .decrypt(&packet)
            .expect("responder should decrypt");
        assert_eq!(message.as_slice(), decrypted.as_slice());

        let response = b"Hello from responder";
        let packet = responder_transport
            .encrypt(response)
            .expect("responder should encrypt");
        let decrypted = initiator_transport
            .decrypt(&packet)
            .expect("initiator should decrypt");
        assert_eq!(response.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_basic_handshake_with_psk() {
        // Generate a shared PSK
        let psk = Psk::generate();

        // Create initiator and responder with shared PSK (authenticated mode)
        let mut initiator = InitiatorHandshake::with_psk(psk.clone());
        let mut responder = ResponderHandshake::with_psk(psk);

        // Execute handshake
        let start_packet = initiator.send_start().expect("initiator should send start");
        responder
            .receive_start(&start_packet)
            .expect("responder should receive start");
        let finish_packet = responder
            .send_finish()
            .expect("responder should send finish");
        initiator
            .receive_finish(&finish_packet)
            .expect("initiator should receive finish");

        // Finalize and get transports
        let (mut initiator_transport, initiator_fingerprint) =
            initiator.finalize().expect("initiator should finalize");
        let (mut responder_transport, responder_fingerprint) =
            responder.finalize().expect("responder should finalize");

        // Fingerprints are identical, but don't have to be verified due to using a PSK
        assert_eq!(initiator_fingerprint, responder_fingerprint);

        // Messages can be exchanged bidirectionally
        let message = b"Hello from initiator";
        let packet = initiator_transport
            .encrypt(message)
            .expect("initiator should encrypt");
        let decrypted = responder_transport
            .decrypt(&packet)
            .expect("responder should decrypt");
        assert_eq!(message.as_slice(), decrypted.as_slice());

        let response = b"Hello from responder";
        let packet = responder_transport
            .encrypt(response)
            .expect("responder should encrypt");
        let decrypted = initiator_transport
            .decrypt(&packet)
            .expect("initiator should decrypt");
        assert_eq!(response.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_basic_handshake_post_quantum() {
        let psk = Psk::generate();

        let mut initiator = InitiatorHandshake::with_psk_for_testing(
            Ciphersuite::PQNNpsk2_Kyber768_XChaCha20Poly1305,
            psk.clone(),
        );
        let mut responder = ResponderHandshake::with_psk_for_testing(
            Ciphersuite::PQNNpsk2_Kyber768_XChaCha20Poly1305,
            psk,
        );

        // Execute handshake
        let start_packet = initiator.send_start().expect("initiator should send start");
        responder
            .receive_start(&start_packet)
            .expect("responder should receive start");
        let finish_packet = responder
            .send_finish()
            .expect("responder should send finish");
        initiator
            .receive_finish(&finish_packet)
            .expect("initiator should receive finish");

        // Finalize and get transports
        let (mut initiator_transport, initiator_fingerprint) =
            initiator.finalize().expect("initiator should finalize");
        let (mut responder_transport, responder_fingerprint) =
            responder.finalize().expect("responder should finalize");

        // Fingerprints are identical, but don't have to be verified due to using a PSK
        assert_eq!(initiator_fingerprint, responder_fingerprint);

        // Messages can be exchanged bidirectionally
        let message = b"Hello from initiator";
        let packet = initiator_transport
            .encrypt(message)
            .expect("initiator should encrypt");
        let decrypted = responder_transport
            .decrypt(&packet)
            .expect("responder should decrypt");
        assert_eq!(message.as_slice(), decrypted.as_slice());

        let response = b"Hello from responder";
        let packet = responder_transport
            .encrypt(response)
            .expect("responder should encrypt");
        let decrypted = initiator_transport
            .decrypt(&packet)
            .expect("initiator should decrypt");
        assert_eq!(response.as_slice(), decrypted.as_slice());
    }
}
