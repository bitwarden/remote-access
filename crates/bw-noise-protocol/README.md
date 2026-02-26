# bw-noise-protocol

A multi-device Noise Protocol implementation with forward secrecy, break-in recovery, and optional post-quantum resistance.

## Overview

This crate provides secure channel establishment and encrypted communication for the `bw_remote` project. It implements the Noise Protocol Framework's NNpsk2 pattern with enhancements for multi-device scenarios.

## Quick Start

### Basic Handshake

```rust
use bw_noise_protocol::{Ciphersuite, InitiatorHandshake, ResponderHandshake};

fn main() -> Result<(), bw_noise_protocol::NoiseProtocolError> {
    // Create initiator and responder
    let mut initiator = InitiatorHandshake::new();
    let mut responder = ResponderHandshake::new();

    // Perform handshake
    let msg1 = initiator.send_start()?;
    responder.receive_start(&msg1)?;
    let msg2 = responder.send_finish()?;
    initiator.receive_finish(&msg2)?;

    // Finalize handshake and get transport state
    let (mut transport_initiator, fingerprint_initiator) = initiator.finalize()?;
    let (mut transport_responder, fingerprint_responder) = responder.finalize()?;

    // ⚠️ Verify fingerprints match to prevent MITM attacks
    assert_eq!(fingerprint_initiator, fingerprint_responder);
    println!("Handshake complete. Fingerprint: {}", fingerprint_initiator);

    // Exchange encrypted messages
    let plaintext = b"Hello, secure world!";
    let encrypted = transport_initiator.encrypt(plaintext)?;
    let decrypted = transport_responder.decrypt(&encrypted)?;
    assert_eq!(decrypted, plaintext);

    Ok(())
}
```

### Post-Quantum Crypto

The `experimental-post-quantum-crypto` feature gates whether a post-quantum ciphersuite is used for the handshake.

## Protocol Overview

The protocol operates in three phases:

### 1. Handshake Phase

Establishes a secure channel using the NNpsk2 pattern:

- **Message 1 (Initiator → Responder)**: Ephemeral key exchange begins
- **Message 2 (Responder → Initiator)**: Completes key exchange, derives shared secrets

After handshake completion, both parties derive:

- Initiator-to-Responder key (`i2r_key`)
- Responder-to-Initiator key (`r2i_key`)
- Handshake fingerprint (SHA-256 hash of handshake transcript)

If a PSK is provided, then no fingerprint verification is required. If no PSK is provided, then the fingerprint must be verified out-of-band (by the user confirming it is the same).
The fingerprint is low-entropy, but this is secure since it is based on the result of the handshake.

### 2. Transport Phase

To not require synchronization of counters, XChaCha20-Poly1305 is used, which allows random nonce selection. To still get forward secrecy,
the chain counter is advanced by both sides, which tells noise how many times to rekey. Replay protection is is provided in the sense that
messages with a lower chain counter are rejected.

## State Persistence

Transport state can be serialized and restored for session resumption:

```rust,ignore
# use bw_noise_protocol::MultiDeviceTransport;
# fn example(transport: &mut MultiDeviceTransport) -> Result<(), Box<dyn std::error::Error>> {
// Save transport state
let state_bytes = transport.save_state()?;
// ... store state_bytes to file, database, etc. ...

// Later, restore transport state
let mut restored_transport = MultiDeviceTransport::restore_state(&state_bytes)?;

// Continue encrypted communication with same keys
let packet = restored_transport.encrypt(b"Resumed session")?;
# Ok(())
# }
```

### Security

**Protected Against:**

- Passive eavesdropping (encryption)
- Active MITM attacks (with fingerprint verification)
- Replay attacks (chain counter validation)
- Harvest-now decrypt later under a quantum-enabled attacker (with PQ ciphersuite)
