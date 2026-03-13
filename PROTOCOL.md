# Bitwarden Remote Access Protocol Specification [DRAFT]

**Version**: 0.1.0 (Draft)
**Status**: Draft

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Cryptographic Primitives](#3-cryptographic-primitives)
4. [Identity Model](#4-identity-model)
5. [Proxy Relay Protocol](#5-proxy-relay-protocol)
6. [Noise Handshake Protocol](#6-noise-handshake-protocol)
7. [Encrypted Transport Layer](#7-encrypted-transport-layer)
8. [Application Protocol](#8-application-protocol)
9. [Connection Modes](#9-connection-modes)
10. [Session Persistence & Resumption](#10-session-persistence--resumption)
11. [CLI Interface](#11-cli-interface)
12. [Data Models Reference](#12-data-models-reference)
13. [Error Codes](#13-error-codes)
14. [Security Properties](#14-security-properties)

---

## 1. Overview

The Bitwarden Remote Access Protocol enables secure peer-to-peer credential sharing between a **User Client** (trusted device holding credentials) and a **Remote Client** (untrusted device requesting credentials). Communication is relayed through a **Proxy Server** that operates with zero knowledge of message contents.

The protocol is layered:

```
┌─────────────────────────────────────────────┐
│  Application Layer (Credential Requests)    │  ProtocolMessage (JSON)
├─────────────────────────────────────────────┤
│  Noise Transport Layer (E2E Encryption)     │  XChaCha20-Poly1305
├─────────────────────────────────────────────┤
│  Noise Handshake Layer (Key Agreement)      │  NNpsk2 pattern
├─────────────────────────────────────────────┤
│  Proxy Relay Protocol (Routing)             │  JSON over WebSocket
├─────────────────────────────────────────────┤
│  WebSocket Transport                        │  Text frames
└─────────────────────────────────────────────┘
```

### Roles

| Role | Description |
|------|-------------|
| **User Client** | Trusted device (e.g., laptop with Bitwarden vault). Listens for incoming connections, approves requests, and serves credentials. |
| **Remote Client** | Untrusted device requesting credentials. Initiates connections and sends credential requests. |
| **Proxy Server** | WebSocket relay. Authenticates clients, facilitates peer discovery (rendezvous), and routes encrypted messages. Cannot decrypt payloads. |

---

## 2. Architecture

### Crate Hierarchy

```
bw-remote (CLI binary)
  ├── bw-rat-client (protocol client library)
  │     ├── bw-noise-protocol (Noise handshake + encrypted transport)
  │     │     └── bw-error / bw-error-macro (error infrastructure)
  │     ├── bw-proxy-client (WebSocket proxy client)
  │     │     └── bw-proxy-protocol (shared wire protocol types)
  │     └── bw-proxy-protocol
  └── bw-proxy-client

bw-proxy (WebSocket relay server binary)
  └── bw-proxy-protocol
```

### Dependency Stack

| Layer | Crate | Role |
|-------|-------|------|
| Wire types | [`bw-proxy-protocol`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol) | Shared message types, identity, auth |
| Proxy client | [`bw-proxy-client`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-client) | WebSocket connection to proxy |
| Noise protocol | [`bw-noise-protocol`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol) | Handshake, transport encryption, session persistence |
| Protocol client | [`bw-rat-client`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client) | [`RemoteClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/remote_client.rs#L34) / [`UserClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/user_client.rs#L164) state machines |
| CLI | [`bw-remote`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-remote) | TUI, non-interactive mode, storage |
| Server | [`bw-proxy`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy) | WebSocket relay server |

---

## 3. Cryptographic Primitives

### Cipher Suites

The protocol supports two cipher suites, identified by a 1-byte ID on the wire ([source](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/ciphersuite.rs#L14)):

```rust
#[repr(u8)]
pub enum Ciphersuite {
    /// Noise_NNpsk2_25519_XChaChaPoly_SHA256
    ClassicalNNpsk2_25519_XChaCha20Poly1035 = 0x01,
    /// pqNoise_NNpsk2_Kyber768_XChaChaPoly_SHA256
    PQNNpsk2_Kyber768_XChaCha20Poly1305 = 0x02,
}
```

| ID | Name | Key Exchange | Symmetric Cipher | Hash |
|----|------|-------------|-------------------|------|
| `0x01` | Classical | Curve25519 (DH) | XChaCha20-Poly1305 | SHA-256 |
| `0x02` | Post-Quantum | ML-KEM-768 (KEM) | XChaCha20-Poly1305 | SHA-256 |

- **Default**: `0x02` (post-quantum) when the `experimental-post-quantum-crypto` feature is enabled; `0x01` (classical) otherwise.
- The post-quantum cipher suite is **enabled by default** in the proxy server and proxy client crates.
- Cipher suite is negotiated during the Noise handshake; both peers must use the same suite.

### Signature Algorithms

Used for proxy authentication (identity proof-of-possession) ([source](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/auth.rs#L20)):

```rust
pub enum SignatureAlgorithm {
    Ed25519,
    #[cfg(feature = "experimental-post-quantum-crypto")]
    MlDsa65,
}
```

| Algorithm | Key Size | Signature Format | Feature Gate |
|-----------|----------|-----------------|--------------|
| Ed25519 (EdDSA) | 32-byte seed | COSE_Sign1 | Default |
| ML-DSA-65 (Dilithium) | 32-byte seed | COSE_Sign1 | `experimental-post-quantum-crypto` |

### Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| PSK length | 32 bytes | Pre-shared key size |
| Nonce length | 24 bytes | XChaCha20-Poly1305 nonce |
| Symmetric key length | 32 bytes | Transport encryption key |
| Identity fingerprint | 32 bytes | SHA-256 of public key |
| Handshake fingerprint | 3 bytes (6 hex chars) | SHA-256 of transport keys, truncated |
| Max Noise message | 65,535 bytes | Maximum single Noise message |
| Max message age | 86,400 seconds (24h) | Replay protection window |
| Clock skew tolerance | 60 seconds | Future-timestamp tolerance |
| Rekey interval | 86,400 seconds (24h) | Automatic transport rekey period |
| Max rekey gap | 1,024 | Maximum rekey counter drift |

### Secure Memory

All key material ([`Psk`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/psk.rs#L15), [`SymmetricKey`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/symmetric_key.rs#L10), [`IdentityKeyPair`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/auth.rs#L45) private keys) implements `ZeroizeOnDrop` for automatic secure cleanup when values go out of scope.

---

## 4. Identity Model

### [`IdentityKeyPair`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/auth.rs#L45)

A device's long-term cryptographic identity. Stored as a 32-byte seed from which the full keypair is derived.

```rust
pub enum IdentityKeyPair {
    Ed25519 {
        private_key_encoded: [u8; 32],
        private_key: SigningKey,
        public_key: VerifyingKey,
    },
    #[cfg(feature = "experimental-post-quantum-crypto")]
    MlDsa65 {
        private_key_encoded: [u8; 32],
        private_key: ml_dsa::SigningKey<MlDsa65>,
        public_key: ml_dsa::VerifyingKey<MlDsa65>,
    },
}
```

**Storage format**: COSE Key (CBOR-encoded), stored at `~/.bw-remote/{name}.key`

**Key methods**:
- `generate()` — Create new keypair using default algorithm
- `generate_with_algorithm(algorithm)` — Create with explicit algorithm choice
- `to_cose() -> Vec<u8>` — Serialize for storage
- `from_cose(bytes) -> IdentityKeyPair` — Deserialize from storage
- `identity() -> Identity` — Extract public identity (no private material)

### [`Identity`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/auth.rs#L270)

The public portion of an identity. Can be freely shared with peers and the proxy server.

```rust
pub struct Identity {
    cose_key_bytes: Vec<u8>,
}
```

**Format**: COSE Key (CBOR-encoded public key bytes)

**Key methods**:
- `fingerprint() -> IdentityFingerprint` — SHA-256 hash of public key bytes
- `algorithm() -> Option<SignatureAlgorithm>` — Detect algorithm from COSE key structure
- `public_key_bytes() -> Option<Vec<u8>>` — Extract raw public key bytes

### [`IdentityFingerprint`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/auth.rs#L416)

A 32-byte (256-bit) SHA-256 hash of the public key bytes. Used as the primary addressing mechanism for message routing.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityFingerprint(pub [u8; 32]);
```

```
IdentityFingerprint = SHA-256(public_key_bytes)
```

**Properties**:
- Deterministic: same public key always produces same fingerprint
- Used as HashMap key for connection lookups on the server
- Serialized as 64-character hex string in JSON
- Supports multiple simultaneous connections per fingerprint (multi-device)

---

## 5. Proxy Relay Protocol

The proxy protocol operates over WebSocket (text frames) with JSON-serialized messages. It has three phases: Authentication, Rendezvous, and Messaging.

### 5.1 Wire Messages

All messages share the [`Messages`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/messages.rs#L34) enum, serialized as JSON:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Messages {
    AuthChallenge(Challenge),                           // Server → Client
    AuthResponse(Identity, ChallengeResponse),          // Client → Server
    GetRendevouz,                                       // Client → Server
    RendevouzInfo(RendevouzCode),                       // Server → Client
    GetIdentity(RendevouzCode),                         // Client → Server
    IdentityInfo {                                      // Server → Client
        fingerprint: IdentityFingerprint,
        identity: Identity,
    },
    Send {                                              // Bidirectional
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<IdentityFingerprint>,
        destination: IdentityFingerprint,
        payload: Vec<u8>,
    },
}
```

### 5.2 Phase 1: Authentication

**Purpose**: Prove identity ownership and register the connection.

**Timeout**: 5 seconds from challenge to response.

```
Client                                          Server
  │                                               │
  │──────────── WebSocket Connect ───────────────>│
  │                                               │
  │<───────── AuthChallenge(nonce_32) ────────────│
  │                                               │
  │  Sign nonce with private key (COSE_Sign1)     │
  │                                               │
  │── AuthResponse(Identity, ChallengeResponse) ─>│
  │                                               │
  │                    Verify signature            │
  │                    Extract fingerprint          │
  │                    Register connection          │
  │              [Authenticated]                   │
```

**[`Challenge`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/auth.rs#L460)** — 32-byte cryptographically random nonce generated by server:

```rust
pub struct Challenge([u8; 32]);
```

**[`ChallengeResponse`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/auth.rs#L581)** — COSE_Sign1 signature structure:

```rust
pub struct ChallengeResponse {
    cose_sign1_bytes: Vec<u8>,
}
```

The COSE_Sign1 structure contains:
- Protected header: signature algorithm (EdDSA or ML-DSA-65)
- Payload: original 32-byte challenge
- Signature: algorithm-specific signature bytes

**Server behavior on success** (see [`handler.rs`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy/src/server/handler.rs)):
1. Decode the [`Identity`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/auth.rs#L270) to extract the public key
2. Verify the COSE_Sign1 signature over the challenge
3. Compute `IdentityFingerprint = SHA-256(public_key_bytes)`
4. Register an [`AuthenticatedConnection`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy/src/connection.rs#L18) keyed by fingerprint
5. Multiple connections per fingerprint are allowed (multi-device)

[`AuthenticatedConnection`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy/src/connection.rs#L18):

```rust
pub struct AuthenticatedConnection {
    pub conn_id: u64,
    pub fingerprint: IdentityFingerprint,
    pub identity: Identity,
    pub tx: mpsc::UnboundedSender<Message>,
    pub connected_at: SystemTime,
}
```

**Server behavior on failure**:
- Invalid signature format → drop connection
- Signature verification fails → drop connection
- Timeout (>5s) → drop connection

### 5.3 Phase 2: Rendezvous (Optional)

**Purpose**: Allow a Remote Client to discover a User Client's identity using a short-lived code exchanged out-of-band.

```
User Client              Server                  Remote Client
  │                        │                          │
  │── GetRendevouz ───────>│                          │
  │                        │                          │
  │<── RendevouzInfo ──────│                          │
  │    (code: "ABC-DEF")   │                          │
  │                        │                          │
  │  (User shares code     │                          │
  │   out-of-band)         │                          │
  │                        │                          │
  │                        │<── GetIdentity("ABC-DEF")│
  │                        │                          │
  │                        │── IdentityInfo ─────────>│
  │                        │   { fingerprint, identity }
  │                        │   (code consumed)        │
```

[**`RendevouzCode`**](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/rendevouz.rs#L20):

```rust
pub struct RendevouzCode {
    code: String,
}
```

- **Format**: 6 alphanumeric characters with hyphen separator (e.g., `"ABC-DEF"`)
- **Character set**: A-Z, 0-9 (36 possibilities per character)
- **Entropy**: 36^6 = ~2.1 billion combinations
- **TTL**: 5 minutes from generation
- **Usage**: Single-use (consumed on first lookup)

**Server-side state** ([`RendevouzEntry`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy/src/server/proxy_server.rs#L14)):

```rust
pub struct RendevouzEntry {
    pub fingerprint: IdentityFingerprint,
    pub created_at: SystemTime,
    pub used: bool,
}
```

**Server cleanup**: Background task runs every 60 seconds, removing expired entries.

**Error conditions** (no explicit error message sent — client receives no response):
- Code not found
- Code expired (>5 minutes)
- Code already used

### 5.4 Phase 3: Messaging

**Purpose**: Route encrypted payloads between authenticated clients.

```
Client A                    Server                  Client B
  │                           │                        │
  │── Send {                  │                        │
  │     source: None,         │                        │
  │     destination: B_FP,    │                        │
  │     payload: [bytes]      │                        │
  │   } ─────────────────────>│                        │
  │                           │                        │
  │                           │── Send {               │
  │                           │     source: A_FP,      │
  │                           │     destination: B_FP, │
  │                           │     payload: [bytes]   │
  │                           │   } ──────────────────>│
  │                           │   (broadcast to all    │
  │                           │    B connections)      │
```

**Send message fields**:
- `source: Option<IdentityFingerprint>` — **Optional on send** (always `None` from client). **Required on receive** (server fills from authenticated connection).
- `destination: IdentityFingerprint` — **Required**. Target client's fingerprint.
- `payload: Vec<u8>` — **Required**. Opaque byte payload (encrypted at higher layer).

**Server behavior** (see [`proxy_server.rs`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy/src/server/proxy_server.rs)):
1. Replace `source` with the sender's authenticated fingerprint (prevents spoofing)
2. Look up all connections matching `destination` fingerprint
3. Broadcast the message to all matching connections
4. If no matching connections: log warning, message is silently dropped

**Multi-device routing**: When multiple devices share the same identity (same fingerprint), all connected devices receive every message addressed to that fingerprint.

**Server state** ([`ServerState`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy/src/server/proxy_server.rs#L20)):

```rust
pub struct ServerState {
    pub connections: Arc<RwLock<HashMap<IdentityFingerprint, Vec<Arc<AuthenticatedConnection>>>>>,
    pub rendezvous_map: Arc<RwLock<HashMap<String, RendevouzEntry>>>,
}
```

### 5.5 Client-Side Incoming Messages

The proxy client library filters server messages into a typed [`IncomingMessage`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/incoming.rs#L5) enum:

```rust
pub enum IncomingMessage {
    RendevouzInfo(RendevouzCode),
    IdentityInfo {
        fingerprint: IdentityFingerprint,
        identity: Identity,
    },
    Send {
        source: IdentityFingerprint,
        destination: IdentityFingerprint,
        payload: Vec<u8>,
    },
}
```

`AuthChallenge`/`AuthResponse` are handled internally during connection setup and never exposed to the caller.

---

## 6. Noise Handshake Protocol

### 6.1 Pattern: NNpsk2

The protocol uses the Noise NNpsk2 handshake pattern, which provides:
- **No static keys** (NN): Neither party presents a long-term Noise key
- **Pre-shared key at position 2** (psk2): PSK mixed after the second message

This is a 2-message handshake:

```
Initiator (Remote)                         Responder (User)
      │                                         │
      │── HandshakeStart ──────────────────────>│
      │   (ephemeral public key)                │
      │                                         │
      │<── HandshakeFinish ─────────────────────│
      │   (ephemeral public key + PSK mix)      │
      │                                         │
      │  [Both derive transport keys]           │
      │  [Both compute fingerprint]             │
```

### 6.2 Handshake Packet Format

Handshake messages are serialized as CBOR ([source](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/packet.rs#L28)):

```rust
pub struct HandshakePacket {
    pub message_type: MessageType,
    pub ciphersuite: Ciphersuite,
    pub payload: Vec<u8>,
}
```

[`MessageType`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/packet.rs#L14) (1-byte discriminator):

```rust
#[repr(u8)]
pub enum MessageType {
    HandshakeStart = 0x01,   // Initiator → Responder
    HandshakeFinish = 0x02,  // Responder → Initiator
    Transport = 0x10,        // Bidirectional (post-handshake)
}
```

### 6.3 PSK Modes

[`Psk`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/psk.rs#L15):

```rust
pub const PSK_LENGTH: usize = 32;

#[derive(Clone, PartialEq, ZeroizeOnDrop)]
pub struct Psk([u8; PSK_LENGTH]);
```

| Mode | PSK Value | Trust Model |
|------|-----------|-------------|
| Null PSK | All zeros (32 bytes) | No pre-shared trust. Requires out-of-band fingerprint verification. Used in rendezvous mode. |
| Explicit PSK | Random 32 bytes | Pre-shared trust via PSK token. No fingerprint verification needed. Used in PSK mode. |

### 6.4 Handshake Fingerprint

After handshake completion, both sides derive a 6-character verification fingerprint ([source](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/handshake.rs#L385)):

```rust
pub struct HandshakeFingerprint(String);

impl HandshakeFingerprint {
    fn new(r2i_key: &[u8], i2r_key: &[u8]) -> Self {
        let mut combined = Vec::with_capacity(r2i_key.len() + i2r_key.len());
        combined.extend_from_slice(r2i_key);
        combined.extend_from_slice(i2r_key);
        let hash = sha2::Sha256::digest(&combined);
        let fingerprint = hex::encode(&hash[..3]);
        HandshakeFingerprint(fingerprint)
    }
}
```

```
fingerprint = hex(SHA-256(responder_to_initiator_key ‖ initiator_to_responder_key)[0..3])
```

- **Length**: 6 hex characters (3 bytes)
- **Purpose**: Out-of-band visual verification between peers
- **Required**: When using null PSK (rendezvous mode), User Client must verify
- **Optional**: Remote Client may optionally verify (configurable via `verify_fingerprint` flag)
- **Skipped**: When using explicit PSK (trust established via shared secret)

### 6.5 Initiator Flow ([`RemoteClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/remote_client.rs#L34))

[`InitiatorHandshake`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/handshake.rs#L30):

```rust
pub struct InitiatorHandshake {
    ciphersuite: Ciphersuite,
    inner: HandshakeState,
    complete: bool,
}
```

1. Create `InitiatorHandshake::new()` (null PSK) or `InitiatorHandshake::with_psk(psk)` (explicit PSK)
2. Call `send_start()` → produces [`HandshakePacket`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/packet.rs#L28) with `MessageType::HandshakeStart`
3. Send packet to responder via proxy `Send` message (base64-encoded in [`ProtocolMessage::HandshakeInit`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/types.rs#L145))
4. Receive responder's `HandshakePacket` with `MessageType::HandshakeFinish`
5. Call `receive_finish(packet)`
6. Call `finalize()` → returns `(MultiDeviceTransport, HandshakeFingerprint)`

### 6.6 Responder Flow ([`UserClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/user_client.rs#L164))

[`ResponderHandshake`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/handshake.rs#L134):

```rust
pub struct ResponderHandshake {
    ciphersuite: Ciphersuite,
    inner: HandshakeState,
    complete: bool,
}
```

1. Create `ResponderHandshake::new()` (null PSK) or `ResponderHandshake::with_psk(psk)` (explicit PSK)
2. Receive initiator's `HandshakePacket` with `MessageType::HandshakeStart`
3. Call `receive_start(packet)`
4. Call `send_finish()` → produces `HandshakePacket` with `MessageType::HandshakeFinish`
5. Send packet to initiator via proxy `Send` message (base64-encoded in [`ProtocolMessage::HandshakeResponse`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/types.rs#L145))
6. Call `finalize()` → returns `(MultiDeviceTransport, HandshakeFingerprint)`

---

## 7. Encrypted Transport Layer

### 7.1 Transport Packet Format

Post-handshake messages use CBOR-encoded transport packets ([source](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/packet.rs#L65)):

```rust
pub struct TransportPacket {
    pub nonce: Vec<u8>,      // 24-byte random nonce (XChaCha20-Poly1305)
    pub ciphertext: Vec<u8>, // AEAD ciphertext (plaintext + 16-byte auth tag)
    pub aad: Vec<u8>,        // CBOR-encoded TransportPacketAad
}

pub struct TransportPacketAad {
    pub timestamp: u64,          // Unix timestamp in seconds
    pub chain_counter: u64,      // Rekey chain counter
    pub ciphersuite: Ciphersuite,
}
```

### 7.2 [`MultiDeviceTransport`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/transport.rs#L46)

```rust
pub struct MultiDeviceTransport {
    ciphersuite: Ciphersuite,
    send_key: SymmetricKey,
    send_rekey_counter: u64,
    last_rekeyed_time: u64,
    rekey_interval: u64,
    recv_key: SymmetricKey,
    recv_rekey_counter: u64,
    seen_nonces: BTreeMap<Vec<u8>, u64>,
    timeprovider: Timeprovider,
}
```

[`SymmetricKey`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/symmetric_key.rs#L10):

```rust
pub const SYMMETRIC_KEY_LENGTH: usize = 32;

#[derive(Clone, PartialEq, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SymmetricKey([u8; SYMMETRIC_KEY_LENGTH]);
```

### 7.3 Encryption Process

1. Check if send-side rekey is needed (time-based, every 24 hours)
2. If rekey needed: derive new key via `encrypt(old_key, nonce=0xFF×24, plaintext=0x00×32)`, increment `send_rekey_counter`
3. Construct `TransportPacketAad { timestamp: now(), chain_counter: send_rekey_counter, ciphersuite }`
4. Generate random 24-byte nonce
5. AEAD encrypt: `XChaCha20-Poly1305(key=send_key, nonce=nonce, plaintext=message, aad=cbor(aad))`
6. Return `TransportPacket { nonce, ciphertext, aad: cbor(aad) }`

### 7.4 Decryption Process

1. Decode `TransportPacketAad` from `packet.aad`
2. Validate cipher suite matches local cipher suite
3. Validate timestamp: reject if `now - timestamp > 86400` (too old) or `timestamp - now > 60` (too far in future)
4. Check `packet.nonce` against seen nonces buffer; reject if duplicate (replay)
5. Record nonce in seen nonces buffer with current timestamp
6. Prune seen nonces older than 24 hours
7. Synchronize receive-side rekey counter with `aad.chain_counter` (catch up if behind, max gap: 1024)
8. AEAD decrypt: `XChaCha20-Poly1305(key=recv_key, nonce=packet.nonce, ciphertext=packet.ciphertext, aad=packet.aad)`
9. Return plaintext

### 7.5 Automatic Rekeying

**Send-side** (time-triggered):
- Every `rekey_interval` seconds (default: 86,400 = 24 hours)
- New key derived: `new_key = XChaCha20-Poly1305_Encrypt(old_key, nonce=0xFF×24, plaintext=0x00×32)`
- `send_rekey_counter` incremented

**Receive-side** (counter-synchronized):
- On each decryption, compare `aad.chain_counter` with `recv_rekey_counter`
- If `aad.chain_counter > recv_rekey_counter`: derive keys forward to catch up (max 1024 steps)
- If `aad.chain_counter < recv_rekey_counter`: attempt decryption with older derived keys
- Enables out-of-order message delivery across rekey boundaries

### 7.6 Replay Protection

- **Nonce tracking**: All received nonces stored in `BTreeMap<nonce, timestamp>`
- **Duplicate detection**: Reject any previously-seen nonce
- **Time window**: Messages older than 24 hours are rejected regardless of nonce
- **Clock skew**: Messages up to 60 seconds in the future are accepted
- **Nonce pruning**: Entries older than 24 hours are periodically removed
- **Persistence caveat**: Nonce buffer is NOT persisted across restarts. Safety is maintained by the 24-hour timestamp window — a restarted client cannot accept messages it already processed (assuming restart takes < 24h of the original message timestamp).

---

## 8. Application Protocol

### 8.1 Protocol Messages

Application-layer messages are serialized as JSON (serde-tagged), then encrypted via the transport layer, then base64-encoded, and finally sent as the `payload` of a proxy `Send` message.

[`ProtocolMessage`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/types.rs#L145):

```rust
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ProtocolMessage {
    #[serde(rename = "handshake-init")]
    HandshakeInit { data: String, ciphersuite: String },
    #[serde(rename = "handshake-response")]
    HandshakeResponse { data: String, ciphersuite: String },
    CredentialRequest { encrypted: String },
    CredentialResponse { encrypted: String },
}
```

| Message | Direction | Fields |
|---------|-----------|--------|
| `handshake-init` | Remote → User | `data`: base64-encoded `HandshakePacket` (required), `ciphersuite`: cipher suite name (required) |
| `handshake-response` | User → Remote | `data`: base64-encoded `HandshakePacket` (required), `ciphersuite`: cipher suite name (required) |
| `credential-request` | Remote → User | `encrypted`: base64-encoded `TransportPacket` containing encrypted `CredentialRequestPayload` (required) |
| `credential-response` | User → Remote | `encrypted`: base64-encoded `TransportPacket` containing encrypted `CredentialResponsePayload` (required) |

### 8.2 Credential Request

[`CredentialRequestPayload`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/types.rs#L160) (encrypted, JSON):

```rust
pub struct CredentialRequestPayload {
    #[serde(rename = "type")]
    pub request_type: String,      // e.g., "credential"
    pub domain: String,            // e.g., "example.com"
    pub timestamp: u64,            // milliseconds
    #[serde(rename = "requestId")]
    pub request_id: String,        // format: "req-{timestamp_millis}-{uuid_first_8_chars}"
}
```

### 8.3 Credential Response

[`CredentialResponsePayload`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/types.rs#L171) (encrypted, JSON):

```rust
pub struct CredentialResponsePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "requestId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}
```

[`CredentialData`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/types.rs#L124) (JSON):

```rust
pub struct CredentialData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}
```

### 8.4 Request-Response Flow

```
Remote Client                                    User Client
     │                                                │
     │  encrypt(CredentialRequestPayload)              │
     │  base64(TransportPacket)                        │
     │                                                │
     │── ProtocolMessage::CredentialRequest ──────────>│
     │   { encrypted: "base64..." }                   │
     │                                                │
     │                    decrypt + deserialize         │
     │                    emit CredentialRequest event  │
     │                    [User approves/denies]       │
     │                                                │
     │                    encrypt(CredentialResponsePayload)
     │                    base64(TransportPacket)      │
     │                                                │
     │<── ProtocolMessage::CredentialResponse ─────────│
     │   { encrypted: "base64..." }                   │
     │                                                │
     │  decrypt + deserialize                          │
     │  match request_id to pending request            │
     │  return CredentialData                          │
```

**Timeouts**:
- Credential request: 30 seconds (Remote Client waiting for response)
- Rendezvous resolution: 10 seconds
- Handshake response: 10 seconds
- Fingerprint verification: 60 seconds

---

## 9. Connection Modes

### 9.1 [`ConnectionMode`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/types.rs#L9)

```rust
pub enum ConnectionMode {
    New { rendezvous_code: String },
    NewPsk { psk: Psk, remote_fingerprint: IdentityFingerprint },
    Existing { remote_fingerprint: IdentityFingerprint },
}
```

### 9.2 Rendezvous Mode (`New`)

**Input**: 6-character rendezvous code (e.g., `"ABC-DEF"`)

**Flow**:
1. User Client requests rendezvous code from proxy (`GetRendevouz`)
2. User shares code out-of-band (voice, chat, etc.)
3. Remote Client sends code to proxy (`GetIdentity`)
4. Proxy returns User's `IdentityInfo` (fingerprint + public key)
5. Remote initiates Noise handshake with **null PSK**
6. User Client verifies handshake fingerprint (mandatory)
7. Remote Client optionally verifies fingerprint
8. Session cached for future use

### 9.3 PSK Mode (`NewPsk`)

**Input**: PSK token string — `"<64-hex-psk>_<64-hex-fingerprint>"` (129 characters)

**Token generation**:
1. User Client generates random 32-byte `Psk`
2. User Client constructs token: `"{psk.to_hex()}_{fingerprint.to_hex()}"`
3. Token shared out-of-band

**Flow**:
1. Remote Client parses token → extracts `Psk` (32 bytes) and `IdentityFingerprint` (32 bytes)
2. Remote initiates Noise handshake with **explicit PSK**
3. No fingerprint verification required (trust via PSK)
4. Session cached for future use

### 9.4 Cached Session Mode (`Existing`)

**Input**: Peer's `IdentityFingerprint` (from session cache)

**Flow**:
1. Remote Client looks up cached session by fingerprint
2. Loads persisted `MultiDeviceTransport` state (if available)
3. Resumes encrypted communication without re-handshake
4. Updates `last_connected_at` timestamp

### 9.5 Token Parsing

The CLI automatically detects token type by length:

| Token Length | Type | Parsing |
|-------------|------|---------|
| 7 characters | Rendezvous code | Used as-is (format: `ABC-DEF`) |
| 129 characters | PSK token | Split on `_`: first 64 hex chars → PSK, last 64 hex chars → fingerprint |

---

## 10. Session Persistence & Resumption

### 10.1 Storage Location

All persistent data is stored in `~/.bw-remote/`:

| File | Format | Content |
|------|--------|---------|
| `{name}.key` | COSE (CBOR binary) | Identity keypair (32-byte seed) |
| `session_cache_{name}.json` | JSON | Array of cached sessions |

Where `{name}` is the storage name (typically `"remote_client"` or `"user_client"`).

[`FileIdentityStorage`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-remote/src/storage/identity_storage.rs#L9):

```rust
pub struct FileIdentityStorage {
    keypair: IdentityKeyPair,
}
```

### 10.2 Session Cache Format

[`SessionRecord`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-remote/src/storage/session_storage.rs#L13):

```rust
struct SessionRecord {
    remote_fingerprint: IdentityFingerprint,
    cached_at: u64,
    last_connected_at: u64,
    #[serde(default)]
    transport_state: Option<Vec<u8>>,
    #[serde(default)]
    name: Option<String>,
}
```

[`FileSessionCache`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-remote/src/storage/session_storage.rs#L13):

```rust
pub struct FileSessionCache {
    cache_path: PathBuf,
    data: SessionCacheData,
}
```

Example JSON:

```json
{
  "sessions": [
    {
      "remote_fingerprint": [32-byte array as JSON array of integers],
      "cached_at": 1700000000,
      "last_connected_at": 1700000100,
      "transport_state": [CBOR bytes as JSON array of integers],
      "name": "Work Laptop"
    }
  ]
}
```

### 10.3 [`PersistentTransportState`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/persistence.rs#L23)

Serialized as CBOR bytes within the session cache:

```rust
pub struct PersistentTransportState {
    ciphersuite: Ciphersuite,
    send_key: SymmetricKey,
    recv_key: SymmetricKey,
    send_rekey_counter: u64,
    recv_rekey_counter: u64,
    last_rekeyed_time: u64,
    rekey_interval: u64,
}
```

**Not persisted** (reset on load):
- Seen nonces buffer (safe due to 24-hour timestamp window)
- Time provider (re-initialized from system clock)

### 10.4 [`SessionStore`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/traits.rs#L10) Trait

```rust
pub trait SessionStore: Send + Sync {
    fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool;
    fn cache_session(&mut self, fingerprint: IdentityFingerprint) -> Result<(), RemoteClientError>;
    fn remove_session(&mut self, fingerprint: &IdentityFingerprint) -> Result<(), RemoteClientError>;
    fn clear(&mut self) -> Result<(), RemoteClientError>;
    fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)>;
    fn set_session_name(&mut self, fingerprint: &IdentityFingerprint, name: String) -> Result<(), RemoteClientError>;
    fn update_last_connected(&mut self, fingerprint: &IdentityFingerprint) -> Result<(), RemoteClientError>;
    fn save_transport_state(&mut self, fingerprint: &IdentityFingerprint, transport_state: MultiDeviceTransport) -> Result<(), RemoteClientError>;
    fn load_transport_state(&self, fingerprint: &IdentityFingerprint) -> Result<Option<MultiDeviceTransport>, RemoteClientError>;
}
```

---

## 11. CLI Interface

### 11.1 Commands

```
bw-remote [OPTIONS] [COMMAND]

Commands:
  connect    Connect to a remote device (default)
  listen     Listen for incoming connections
  cache      Manage session cache

Global Options:
  --proxy-url <URL>       Proxy server URL [default: wss://rat1.lesspassword.dev]
  --verbose               Enable debug logging
```

### 11.2 Connect Command

See [`ConnectArgs`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-remote/src/command/connect.rs).

```
bw-remote connect [OPTIONS]

Options:
  --token <TOKEN>              Rendezvous code or PSK token (conflicts with --session)
  --session <FINGERPRINT>      Cached session fingerprint or unique prefix (conflicts with --token)
  --no-cache                   Disable session caching
  --verify-fingerprint         Require fingerprint verification
  --domain <DOMAIN>            Domain for single-shot non-interactive mode
  --output <FORMAT>            Output format: text or json [default: text]
```

### 11.3 Listen Command

See [`ListenArgs`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-remote/src/command/listen.rs).

```
bw-remote listen [OPTIONS]

Options:
  --psk                        Use PSK mode instead of rendezvous code
```

### 11.4 Cache Command

See [`CacheArgs`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-remote/src/command/cache.rs).

```
bw-remote cache <SUBCOMMAND>

Subcommands:
  clear [--scope sessions|all]    Clear cached sessions (or all data including keys)
  list                            List cached sessions

Options:
  --client-type <TYPE>            Filter by: remote, user
```

### 11.5 Single-Shot Non-Interactive Mode

Triggered when `--domain` is provided. No TUI is displayed.

**Session resolution priority**:
1. `--token` provided → parse as rendezvous code or PSK token
2. `--session` provided → look up cached session by fingerprint (supports unique prefix matching)
3. Exactly one cached session exists → auto-select
4. Multiple cached sessions → error (ambiguous, `--session` required)
5. No cached sessions → error (`--token` required)

**Output to stdout** (text format):
```
username: user@example.com
password: hunter2
totp: 123456
uri: https://example.com
notes: Some notes
```

**Output to stdout** (JSON format):
```json
{
  "success": true,
  "domain": "example.com",
  "credential": {
    "username": "user@example.com",
    "password": "hunter2",
    "totp": "123456",
    "uri": "https://example.com",
    "notes": "Some notes"
  }
}
```

**Error output** (JSON format):
```json
{
  "success": false,
  "error": {
    "message": "Connection timed out",
    "code": "connection_failed"
  }
}
```

**Exit codes** (see [`output.rs`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-remote/src/command/output.rs)):

| Code | Name | Description |
|------|------|-------------|
| 0 | `SUCCESS` | Credential retrieved successfully |
| 1 | `GENERAL_ERROR` | Unclassified error |
| 2 | `CONNECTION_FAILED` | WebSocket or proxy connection failure |
| 3 | `AUTH_HANDSHAKE_FAILED` | Authentication, handshake, or pairing failure |
| 4 | `CREDENTIAL_NOT_FOUND` | Credential request failed or denied |
| 5 | `FINGERPRINT_MISMATCH` | Fingerprint verification rejected |

---

## 12. Data Models Reference

### 12.1 Event Types

#### [`RemoteClientEvent`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/types.rs#L39)

Emitted by [`RemoteClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/remote_client.rs#L34):

```rust
pub enum RemoteClientEvent {
    Connecting { proxy_url: String },
    Connected { fingerprint: IdentityFingerprint },
    ReconnectingToSession { fingerprint: IdentityFingerprint },
    RendevouzResolving { code: String },
    RendevouzResolved { fingerprint: IdentityFingerprint },
    PskMode { fingerprint: IdentityFingerprint },
    HandshakeStart,
    HandshakeProgress { message: String },
    HandshakeComplete,
    HandshakeFingerprint { fingerprint: String },  // 6-char hex
    FingerprintVerified,
    FingerprintRejected { reason: String },
    Ready { can_request_credentials: bool },
    CredentialRequestSent { domain: String },
    CredentialReceived { domain: String, credential: CredentialData },
    Error { message: String, context: Option<String> },
    Disconnected { reason: Option<String> },
}
```

#### [`RemoteClientResponse`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/types.rs#L29)

Sent to [`RemoteClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/remote_client.rs#L34):

```rust
pub enum RemoteClientResponse {
    VerifyFingerprint { approved: bool },
}
```

#### [`UserClientEvent`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/user_client.rs#L29)

Emitted by [`UserClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/user_client.rs#L164):

```rust
pub enum UserClientEvent {
    Listening {},
    RendevouzCodeGenerated { code: String },
    PskTokenGenerated { token: String },        // format: "<psk_hex>_<fingerprint_hex>"
    HandshakeStart {},
    HandshakeProgress { message: String },
    HandshakeComplete {},
    HandshakeFingerprint { fingerprint: String }, // 6-char hex
    FingerprintVerified {},
    FingerprintRejected { reason: String },
    CredentialRequest { domain: String, request_id: String, session_id: String },
    CredentialApproved { domain: String },
    CredentialDenied { domain: String },
    SessionRefreshed { fingerprint: IdentityFingerprint },
    ClientDisconnected {},
    Error { message: String, context: Option<String> },
}
```

#### [`UserClientResponse`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/user_client.rs#L100)

Sent to [`UserClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/user_client.rs#L164):

```rust
pub enum UserClientResponse {
    VerifyFingerprint {
        approved: bool,
        name: Option<String>,
    },
    RespondCredential {
        request_id: String,
        session_id: String,
        approved: bool,
        credential: Option<CredentialData>,
    },
}
```

### 12.2 Client Structs

[`RemoteClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/remote_client.rs#L34):

```rust
pub struct RemoteClient {
    session_store: Box<dyn SessionStore>,
    proxy_client: Box<dyn ProxyClient>,
    incoming_rx: Option<mpsc::UnboundedReceiver<IncomingMessage>>,
    transport: Option<Arc<Mutex<MultiDeviceTransport>>>,
    remote_fingerprint: Option<IdentityFingerprint>,
    pending_requests: Arc<Mutex<HashMap<String, oneshot::Sender<Result<CredentialData, RemoteClientError>>>>>,
    event_tx: mpsc::Sender<RemoteClientEvent>,
    response_rx: Option<mpsc::Receiver<RemoteClientResponse>>,
}
```

[`UserClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/clients/user_client.rs#L164):

```rust
pub struct UserClient {
    identity_provider: Box<dyn IdentityProvider>,
    session_store: Box<dyn SessionStore>,
    proxy_client: Option<Box<dyn ProxyClient>>,
    transports: HashMap<IdentityFingerprint, MultiDeviceTransport>,
    rendezvous_code: Option<RendevouzCode>,
    psk: Option<Psk>,
    incoming_rx: Option<mpsc::UnboundedReceiver<IncomingMessage>>,
    pending_verification: Option<PendingHandshakeVerification>,
    pending_session_name: Option<String>,
}
```

### 12.3 Traits

#### [`IdentityProvider`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/traits.rs#L68)

```rust
pub trait IdentityProvider: Send + Sync {
    fn identity(&self) -> &IdentityKeyPair;
    fn fingerprint(&self) -> IdentityFingerprint {
        self.identity().identity().fingerprint()
    }
}
```

#### [`ProxyClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/proxy.rs#L15)

```rust
#[async_trait]
pub trait ProxyClient: Send + Sync {
    async fn connect(&mut self) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, RemoteClientError>;
    async fn request_rendezvous(&self) -> Result<(), RemoteClientError>;
    async fn request_identity(&self, code: RendevouzCode) -> Result<(), RemoteClientError>;
    async fn send_to(&self, fingerprint: IdentityFingerprint, data: Vec<u8>) -> Result<(), RemoteClientError>;
    async fn disconnect(&mut self) -> Result<(), RemoteClientError>;
}
```

### 12.4 Proxy Client

[`ProxyClientConfig`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-client/src/config.rs#L29):

```rust
pub struct ProxyClientConfig {
    pub proxy_url: String,
    pub identity_keypair: Option<IdentityKeyPair>,
}
```

[`ProxyProtocolClient`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-client/src/protocol_client.rs#L69):

```rust
pub struct ProxyProtocolClient {
    config: ProxyClientConfig,
    identity: Arc<IdentityKeyPair>,
    state: Arc<Mutex<ClientState>>,
    outgoing_tx: Option<mpsc::UnboundedSender<Message>>,
    read_task_handle: Option<JoinHandle<()>>,
    write_task_handle: Option<JoinHandle<()>>,
}
```

[`ProxyServer`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy/src/server/proxy_server.rs#L88):

```rust
pub struct ProxyServer {
    bind_addr: SocketAddr,
    state: Arc<ServerState>,
    conn_counter: AtomicU64,
}
```

---

## 13. Error Codes

### 13.1 [`NoiseProtocolError`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-noise-protocol/src/error.rs#L9)

```rust
pub enum NoiseProtocolError {
    HandshakeWriteError,
    HandshakeReadError,
    HandshakeSplit,
    HandshakeNotComplete,
    DecryptionFailed,
    UnsupportedCiphersuite(u8),
    InvalidMessageType(u8),
    CiphersuiteMismatch,
    CborEncodeFailed,
    CborDecodeFailed,
    Desynchronized,
    MessageTooOld { timestamp: u64, now: u64 },
    MessageFromFuture { timestamp: u64, now: u64 },
    ReplayDetected,
    RekeyFailed,
    TransportEncryptionFailed,
    TransportDecryptionFailed,
    InvalidPskLength,
    InvalidPskEncoding,
}
```

### 13.2 [`ProxyError`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-proxy-protocol/src/error.rs#L11)

```rust
pub enum ProxyError {
    WebSocket(String),
    AuthenticationFailed(String),
    DestinationNotFound(IdentityFingerprint),
    Serialization(serde_json::Error),
    ConnectionClosed,
    InvalidMessage(String),
    Io(std::io::Error),
    NotConnected,
    AlreadyConnected,
    AuthenticationTimeout,
    ChannelSendFailed,
}
```

### 13.3 [`RemoteClientError`](https://github.com/bitwarden/remote-access/tree/8624b1e83d057412546dedef63794ae5f1b6a4e1/crates/bw-rat-client/src/error.rs#L9)

```rust
pub enum RemoteClientError {
    ConnectionFailed(String),
    WebSocket(String),
    ProxyAuthFailed(String),
    InvalidPairingCode(String),
    NoiseProtocol(String),
    HandshakeFailed(String),
    Timeout(String),
    SecureChannelNotEstablished,
    NotInitialized,
    CredentialRequestFailed(String),
    Serialization(String),
    SessionCache(String),
    KeypairStorage(String),
    ChannelClosed,
    IdentityStorageFailed(String),
    RendevouzResolutionFailed(String),
    InvalidRendevouzCode(String),
    FingerprintRejected,
    InvalidState { expected: String, current: String },
    SessionNotFound,
}
```

---

## 14. Security Properties

### 14.1 Threat Model

| Property | Guarantee |
|----------|-----------|
| **Confidentiality** | End-to-end encryption (XChaCha20-Poly1305). Proxy cannot decrypt payloads. |
| **Integrity** | AEAD authentication on every transport message. Tampering detected. |
| **Authentication** | Proxy: challenge-response signature (COSE_Sign1). Peers: Noise handshake + fingerprint verification or PSK. |
| **Replay protection** | Nonce tracking + 24-hour timestamp window. |
| **Forward secrecy** | Ephemeral Noise keys. Compromise of long-term identity does not reveal past sessions. |
| **Post-compromise security** | Automatic rekey every 24 hours limits exposure window. |
| **Source authentication** | Proxy replaces `source` field with authenticated fingerprint — clients cannot spoof sender identity. |

### 14.2 What the Proxy Sees

| Visible | Not Visible |
|---------|-------------|
| Client identity fingerprints | Private keys |
| Connection timestamps | Credential data |
| Message source/destination | Plaintext payloads |
| Message sizes | Handshake key material |
| Rendezvous code ↔ fingerprint mapping | PSK values |

### 14.3 Trust Establishment

| Mode | Trust Anchor | Verification |
|------|-------------|--------------|
| Rendezvous | Out-of-band code exchange | Mandatory fingerprint verification (User side); optional (Remote side) |
| PSK | Out-of-band PSK token exchange | Implicit (shared secret proves identity) |
| Cached | Previous successful pairing | Transport state reuse (no re-verification) |

### 14.4 Serialization Format Summary

| Layer | Format | Wire Encoding |
|-------|--------|---------------|
| Proxy wire protocol | JSON | WebSocket text frames |
| Identity key storage | COSE Key (CBOR) | Binary file |
| Session cache | JSON | File |
| Auth signatures | COSE_Sign1 (CBOR) | Embedded in JSON |
| Handshake packets | CBOR | Base64 in JSON |
| Transport packets | CBOR | Base64 in JSON |
| Transport state (persisted) | CBOR | Byte array in JSON |

---

## Appendix A: Complete End-to-End Flow (Rendezvous Mode)

```
Remote Client              Proxy Server              User Client
     │                          │                          │
     │                          │<── WebSocket Connect ────│
     │                          │── AuthChallenge ────────>│
     │                          │<── AuthResponse ─────────│
     │                          │  [User authenticated]    │
     │                          │                          │
     │                          │<── GetRendevouz ─────────│
     │                          │── RendevouzInfo ────────>│
     │                          │   (code: "ABC-DEF")     │
     │                          │                          │
     │     (User shares code    │                          │
     │      out-of-band)        │                          │
     │                          │                          │
     │── WebSocket Connect ────>│                          │
     │<── AuthChallenge ────────│                          │
     │── AuthResponse ────────>│                          │
     │  [Remote authenticated]  │                          │
     │                          │                          │
     │── GetIdentity("ABC-DEF")>│                          │
     │<── IdentityInfo ─────────│                          │
     │   (User's fingerprint)   │  (code consumed)        │
     │                          │                          │
     │── Send(HandshakeInit) ──>│── Send(HandshakeInit) ──>│
     │                          │                          │
     │                          │<── Send(HandshakeResp) ──│
     │<── Send(HandshakeResp) ──│                          │
     │                          │                          │
     │  [Both derive transport  │  [Both derive transport  │
     │   keys + fingerprint]    │   keys + fingerprint]    │
     │                          │                          │
     │  Display fingerprint     │  Display fingerprint     │
     │  (e.g., "A1B2C3")       │  (e.g., "A1B2C3")       │
     │                          │  [User verifies match]   │
     │                          │                          │
     │── Send(CredReq) ───────>│── Send(CredReq) ────────>│
     │  (encrypted domain)      │                          │
     │                          │  [User approves]         │
     │                          │                          │
     │                          │<── Send(CredResp) ───────│
     │<── Send(CredResp) ───────│                          │
     │  (encrypted credential)  │                          │
     │                          │                          │
     │  [Session cached]        │  [Session cached]        │
```

## Appendix B: Complete End-to-End Flow (PSK Mode)

```
Remote Client              Proxy Server              User Client
     │                          │                          │
     │                          │  [User authenticated]    │
     │                          │                          │
     │                          │  Psk::generate()         │
     │                          │  token = "{psk}_{fp}"    │
     │                          │                          │
     │  [User shares 129-char   │                          │
     │   token out-of-band]     │                          │
     │                          │                          │
     │  [Remote authenticated]  │                          │
     │                          │                          │
     │  Parse token:            │                          │
     │  psk = first 64 hex      │                          │
     │  fp = last 64 hex        │                          │
     │                          │                          │
     │── Send(HandshakeInit) ──>│── Send(HandshakeInit) ──>│
     │  (with PSK)              │                          │
     │                          │<── Send(HandshakeResp) ──│
     │<── Send(HandshakeResp) ──│  (with PSK)             │
     │                          │                          │
     │  [Transport established  │  [Transport established  │
     │   No fingerprint check]  │   No fingerprint check]  │
     │                          │                          │
     │── Send(CredReq) ───────>│── Send(CredReq) ────────>│
     │<── Send(CredResp) ───────│<── Send(CredResp) ───────│
```
