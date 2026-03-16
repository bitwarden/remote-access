//! Noise Protocol Handshake with PSK Authentication Example
//!
//! Demonstrates how to use Pre-Shared Keys (PSKs) to add authentication to Noise handshakes.   
//! PSKs provide protection against man-in-the-middle attacks when both parties have exchanged
//! a secret key through a secure out-of-band channel. This means that the fingerprint verification
//! can be skipped.
//!
//! # Security Considerations
//! - PSK must be exchanged through a secure out-of-band channel
//!
//! This example shows:
//! - Generating a random PSK
//! - Creating handshakes with PSK
//! - Completing the handshake
//! - Exchanging encrypted messages

use ap_noise::{InitiatorHandshake, Psk, ResponderHandshake};

fn main() -> Result<(), ap_noise::NoiseProtocolError> {
    // Generate a PSK using a cryptographically secure RNG
    let psk = Psk::generate();

    // Simulate sharing the PSK out-of-band encoded as a string
    let psk_string = psk.to_hex();
    // (transmission)
    let psk_received = Psk::from_hex(&psk_string)?;

    let mut initiator = InitiatorHandshake::with_psk(psk);

    let mut responder = ResponderHandshake::with_psk(psk_received);

    // Handshake
    let msg1 = initiator.send_start()?;
    responder.receive_start(&msg1)?;
    let msg2 = responder.send_finish()?;
    initiator.receive_finish(&msg2)?;

    let (mut transport_initiator, _fingerprint_initiator) = initiator.finalize()?;
    let (mut transport_responder, _fingerprint_responder) = responder.finalize()?;

    // Exchange messages
    let plaintext_initiator = b"Hello from Initiator! This message is encrypted and authenticated.";
    let encrypted_msg = transport_initiator.encrypt(plaintext_initiator)?;
    let decrypted_msg = transport_responder.decrypt(&encrypted_msg)?;
    assert_eq!(decrypted_msg, plaintext_initiator);

    let plaintext_responder = b"Hello from Responder! PSK authentication successful.";
    let encrypted_msg2 = transport_responder.encrypt(plaintext_responder)?;
    let decrypted_msg2 = transport_initiator.decrypt(&encrypted_msg2)?;
    assert_eq!(decrypted_msg2, plaintext_responder);

    Ok(())
}
