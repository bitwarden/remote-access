//! Basic Noise Protocol Handshake Example
//!
//! Demonstrates the complete flow of a Noise NNpsk2 handshake using the classical
//! Curve25519-based cipher suite, followed by encrypted message exchange in transport mode.
//!
//! This example shows:
//! - Creating initiator and responder handshake states
//! - Exchanging handshake messages
//! - Finalizing the handshake
//! - Verifying fingerprint
//! - Exchanging encrypted messages in transport mode
//!
//! It is important that the fingerprint is verified to protect against MITM attacks.
//!
//! Note: Depending on whether the "experimental-post-quantum-crypto" feature is enabled,
//! this test will use either the classical or post-quantum cipher suite.

use bw_noise_protocol::{InitiatorHandshake, ResponderHandshake};

fn main() -> Result<(), bw_noise_protocol::NoiseProtocolError> {
    // Create initiator
    let mut initiator = InitiatorHandshake::new();

    // Create responder
    let mut responder = ResponderHandshake::new();

    // Run the handshake steps
    let msg1 = initiator.send_start()?;
    let _ = responder.receive_start(&msg1)?;
    let msg2 = responder.send_finish()?;
    let _ = initiator.receive_finish(&msg2)?;
    let (mut transport_initiator, fingerprint_initiator) = initiator.finalize()?;
    let (mut transport_responder, fingerprint_responder) = responder.finalize()?;

    // Verify that both parties derived the same fingerprint. Consumers should verify this to prevent MITM attacks.
    assert_eq!(fingerprint_initiator, fingerprint_responder);
    println!(
        "Handshake completed successfully. Fingerprint: {}",
        fingerprint_initiator
    );

    // Now both parties can exchange encrypted messages in transport mode
    let plaintext_initiator = b"Hello from Initiator!";
    let encrypted_msg = transport_initiator.encrypt(plaintext_initiator)?;
    let decrypted_msg = transport_responder.decrypt(&encrypted_msg)?;
    assert_eq!(decrypted_msg, plaintext_initiator);

    let plaintext_responder = b"Hello from Responder!";
    let encrypted_msg2 = transport_responder.encrypt(plaintext_responder)?;
    let decrypted_msg2 = transport_initiator.decrypt(&encrypted_msg2)?;
    assert_eq!(decrypted_msg2, plaintext_responder);

    println!("Exchanged transport messages successfully.");

    Ok(())
}
