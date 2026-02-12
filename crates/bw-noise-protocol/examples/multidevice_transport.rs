//! Multi-Device Transport with Persistent State Example
//!
//! Demonstrates how to use state persistence to enable multiple devices on one side
//! to share the same transport session.

//! Flow:
//! 1. Initial handshake between initiator and responder
//! 2. Responder saves transport state using save_state()
//! 3. Second responder device loads the same state using restore_state()
//! 4. Both responder devices independently decrypt initiator messages
//! 5. Both responder devices independently send messages to initiator
use bw_noise_protocol::{InitiatorHandshake, Psk, ResponderHandshake};

fn main() -> Result<(), bw_noise_protocol::NoiseProtocolError> {
    let psk = Psk::generate();

    let psk_string = psk.to_hex();
    let psk_received = Psk::from_hex(&psk_string)?;

    let mut initiator = InitiatorHandshake::with_psk(psk);

    let mut responder = ResponderHandshake::with_psk(psk_received);

    let msg1 = initiator.send_start()?;
    responder.receive_start(&msg1)?;
    let msg2 = responder.send_finish()?;
    initiator.receive_finish(&msg2)?;

    let (mut transport_initiator, _fingerprint_initiator) = initiator.finalize()?;
    let (mut transport_responder, _fingerprint_responder) = responder.finalize()?;

    let test_message = b"Initial test message";
    let encrypted_test = transport_initiator.encrypt(test_message)?;
    let decrypted_test = transport_responder.decrypt(&encrypted_test)?;
    assert_eq!(decrypted_test, test_message);

    let state_bytes = transport_responder.save_state()?;

    let mut transport_responder_device2 =
        bw_noise_protocol::MultiDeviceTransport::restore_state(&state_bytes)?;
    let mut transport_responder_device1 = transport_responder;

    let message_to_both = b"Hello from Initiator to both devices!";
    let encrypted_msg = transport_initiator.encrypt(message_to_both)?;

    // Both devices can decrypt
    let decrypted_device1 = transport_responder_device1.decrypt(&encrypted_msg)?;
    assert_eq!(decrypted_device1, message_to_both);

    let decrypted_device2 = transport_responder_device2.decrypt(&encrypted_msg)?;
    assert_eq!(decrypted_device2, message_to_both);

    // Device 1 sends message to initiator
    let device1_msg = b"Device 1 responding";
    let encrypted_from_device1 = transport_responder_device1.encrypt(device1_msg)?;
    let decrypted_at_initiator1 = transport_initiator.decrypt(&encrypted_from_device1)?;
    assert_eq!(decrypted_at_initiator1, device1_msg);

    // Device 2 sends different message to initiator
    let device2_msg = b"Device 2 also responding";
    let encrypted_from_device2 = transport_responder_device2.encrypt(device2_msg)?;
    let decrypted_at_initiator2 = transport_initiator.decrypt(&encrypted_from_device2)?;
    assert_eq!(decrypted_at_initiator2, device2_msg);

    Ok(())
}
