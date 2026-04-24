# Agent Access Protocol v0

Covers the noise, wire and proxy protocol. Does not include client or CLI architecture.
We've intentionally included some implementation details for the sake of pragamatism.

Status: draft.

Authors:
* Anders Åberg, Bitwarden <aaberg@bitwarden.com>
* Bernd Schoolmann, Bitwarden

Contributors:
* Ludovic Widmer, Dashlane

## Bird's-eye View

### Problem

Any remote system (e.g. an AI agent or headless script) needs to fetch
a specific credential from any password manager running on a user's
device, without letting any intermediary read the credential and
without requiring the two systems to be on the same network or a
proprietary integration.

### Shape of the solution

The two peers establish an end-to-end **Noise NNpsk2** session directly
between themselves; all credential traffic is encrypted and
authenticated inside that session. Because the peers are usually on
different networks, the session is tunneled over a public **proxy**
that relays opaque payloads over WebSocket. The proxy authenticates
each connection by a long-lived signing identity so it can route by
address, but it cannot decrypt, forge, or modify payloads.

```
    UserClient                                        RemoteClient
(holds credentials)                               (needs credentials)
         │                                                │
         │               Noise NNpsk2 (E2E)               │
         │ ◄══════════════════════════════════════════════►│
         │               XChaCha20-Poly1305               │
         │                                                │
         │ Send(dst, payload)         Send(dst, payload)  │
         ▼                                                ▼
    ┌────────────────────────────────────────────────────────┐
    │                         Proxy                          │
    │   Authenticates identities, routes by fingerprint,     │
    │   sees only opaque ciphertext.                         │
    └────────────────────────────────────────────────────────┘
                      WebSocket (JSON frames)
```

### Lifecycle

1. **Connect & authenticate** (each side, independently). Client opens a
   WebSocket to the proxy. The proxy issues a random challenge; the
   client signs it with its identity key (Ed25519 or ML-DSA-65). The
   proxy indexes the connection by `fingerprint = SHA256(pubkey)`.
2. **Pair** (first time only). The two peers need to learn each other's
   fingerprint. Either:
   - **Rendezvous**: UserClient asks the proxy for a short human code
     (`ABC-DEF-GHI`, 5 min TTL). RemoteClient exchanges the code for the
     UserClient's identity. No shared secret - peers will verify a
     6-hex handshake fingerprint out-of-band during pairing.
   - **PSK token**: UserClient exports a 129-char token containing a
     32-byte PSK and its fingerprint. RemoteClient uses both. The PSK
     authenticates the Noise handshake; no handshake fingerprint
     verification needed.
3. **Handshake.** RemoteClient initiates a two-message Noise NNpsk2
   handshake (`HandshakeStart` → `HandshakeFinish`) carried inside
   proxy `Send` frames. Both sides derive symmetric transport keys.
4. **Use.** Peers exchange arbitrary E2E-encrypted application messages.
   In v0 these are credential request / response pairs. Transport uses
   random 24-byte nonces with a timestamp-based replay window and
   automatic 24-hour rekeying. State can be persisted for resumption
   without a new handshake.

> **Editor note: Upcoming MITM hardening for rendezvous.** Before pairing, the
> responder commits to its handshake key and publishes the commitment
> alongside the rendezvous code. Flow:
>
> 1. Responder → Commitment → Initiator (out-of-band, with the code).
>    The responder cannot change its handshake key after this point.
> 2. Initiator → `HandshakeStart` (with pubkey) → Responder.
> 3. Responder → `HandshakeFinish` (with pubkey) → Initiator. The
>    initiator verifies the enclosed key matches the commitment.
>
> A proxy cannot swap the responder's key mid-flight because it cannot
> produce a matching commitment, closing the fingerprint-grinding gap.

### Proxy model

> **Editor note.** This is not a proper threat model; we anticipate
> iteration on the proxy. The lists below are a high-level view of the
> current design.

*The proxy can:*

- Observe which fingerprints are connected, and who talks to whom.
- Observe message sizes and timing. (**Editor note:** v0 has no payload
  padding - add padding so the proxy can't infer credential sizes.)
- Drop, delay, reorder, or re-send any message it relays. Re-sends are
  rejected by the Noise transport replay buffer, but the proxy can
  still emit them.
- Deny service at will.

*The proxy cannot:*

- Read or modify E2E payloads (Noise AEAD over XChaCha20-Poly1305).
- Produce ciphertext that decrypts under another peer's session keys.
  It may set `source` to any fingerprint on the wire, but the receiver
  will only accept payloads that authenticate under the transport keys
  established during the Noise handshake with that peer.
- Recover past session keys. Noise NNpsk2 derives keys from ephemeral
  DH/KEM material that is discarded after the handshake, and the rekey
  chain is one-way.

*Caveat: rendezvous MITM.* In rendezvous (null-PSK) mode, the proxy
supplies the peer's `Identity` in response to `GetIdentity(code)`, and
a malicious proxy can substitute its own identity to mount a MITM.
This is detected only if both peers verify the 6-hex
`HandshakeFingerprint` out-of-band (see §4.3). With 24 bits of entropy
the fingerprint is brute-forceable by a determined proxy; PSK mode
closes this gap, and the commitment scheme above is a proposed fix for
rendezvous mode.

## Outline

1. **Overview**: peers, layers, where the trust boundary sits.
2. **Identities**: `IdentityKeyPair`, `Identity`, `IdentityFingerprint`.
3. **Proxy layer**: WebSocket transport, JSON framing, three phases.
   1. Authentication: challenge / COSE_Sign1 response.
   2. Pairing: rendezvous codes and PSK tokens.
   3. Message routing: `Send` with proxy-asserted source.
4. **End-to-end layer (`ap-noise`)**: runs inside relayed payloads.
   1. Ciphersuites (classical / post-quantum).
   2. Handshake: NNpsk2 (null-PSK or real-PSK).
   3. `HandshakeFingerprint` for out-of-band MITM check.
   4. Transport: XChaCha20-Poly1305 with random nonces and AAD.
   5. Replay protection and timestamp window.
   6. Time-based rekey chain.
   7. Session persistence.
5. **Application messages**: `ProtocolMessage` carried inside Noise.
   1. `CredentialRequest` payload.
   2. `CredentialResponse` payload.
   3. Request/response lifecycle.
   4. Open items for v1.
6. **Constants & wire formats**: one consolidated reference table.

---

## 1. Overview

Two peers - a **UserClient** (holds credentials) and a **RemoteClient**
(requests credentials, runs on a remote device) - exchange encrypted
payloads through a WebSocket **proxy**. The proxy authenticates each
connection by identity but never sees plaintext. The proxy is not trusted
for confidentiality or integrity of payloads; peers rely on Noise NNpsk2
for E2E security.

The Noise-level terms **initiator** and **responder** are used only in §4
and refer to handshake roles: RemoteClient initiates, UserClient responds.
They have no meaning outside the handshake.

Two independent cryptographic layers:

| Layer | Purpose | Key material | Crate |
|-------|---------|--------------|-------|
| Proxy | Identify + route connections | `IdentityKeyPair` (Ed25519 or ML-DSA-65) | `ap-proxy-protocol` |
| E2E (Noise) | Encrypt peer traffic | Ephemeral DH/KEM + optional PSK | `ap-noise` |

## 2. Identities

- `IdentityKeyPair`: signature key pair. Default Ed25519; with feature
  `experimental-post-quantum-crypto`, ML-DSA-65. Stored as a COSE key
  (RFC 9052). 32-byte seed; keys derived from seed.
- `Identity`: COSE-encoded public key only. Freely shareable.
- `IdentityFingerprint`: `SHA256(public_key_bytes)` → 32 bytes, hex-encoded
  as 64 chars. Used as the proxy addressing key and for display.
- No rotation protocol in v0; the key pair is the long-term identity of a
  client and survives reconnection and session resumption.

## 3. Proxy Layer

**Transport.** WebSocket (`ws://` or `wss://`). All protocol frames are WebSocket **text** frames
containing a JSON-serialized `Messages` enum (tagged by variant name).
Binary/ping/pong frames are accepted as liveness but carry no protocol
semantics.

**Idle timeout.** Server closes the connection after
`CLIENT_INACTIVITY_TIMEOUT = 120 s` without receiving any WS frame.

**Messages enum** (JSON, externally tagged):

```
AuthChallenge(Challenge)                                 // S → C
AuthResponse(Identity, ChallengeResponse)                // C → S

GetRendezvous                                            // C → S, UserClient
RendezvousInfo(RendezvousCode)                           // S → C, UserClient

GetIdentity(RendezvousCode)                              // C → S, RemoteClient
IdentityInfo { fingerprint, identity }                   // S → C, RemoteClient

Send { source?, destination, payload }                   // C ⇄ S
```

### 3.1 Authentication

1. Upon WS accept, server sends `AuthChallenge(nonce)` where `nonce` is
   32 random bytes.
2. Client MUST respond within 5 s with
   `AuthResponse(identity, ChallengeResponse)`.
3. `ChallengeResponse` is a `COSE_Sign1` with:
   - `protected.alg` ∈ { `EdDSA`, `ML_DSA_65` }
   - `payload` = the 32-byte challenge verbatim
   - `signature` = raw signature bytes (Ed25519: 64 B; ML-DSA-65: 3309 B)
4. Server verifies:
   - `protected.alg` matches `identity.alg`,
   - `payload == challenge`,
   - signature verifies against `identity`.
5. On success, server records the connection under
   `fingerprint = SHA256(identity.public_key_bytes)`. A single fingerprint
   MAY have multiple simultaneous connections (multi-device).

Failure modes (server closes the connection): timeout, wrong message
type, algorithm mismatch, verification failure.

### 3.2 Pairing (peer discovery)

Two mutually exclusive paths to obtain the peer's fingerprint:

**Rendezvous** (no pre-shared secret):

1. Responder → `GetRendezvous`.
2. Server generates `RendezvousCode` = `[A-Z0-9]{3}-[A-Z0-9]{3}-[A-Z0-9]{3}`
   (9 chars, 36⁹ ≈ 1.0 × 10¹⁴), binds it to the responder's fingerprint
   with `created_at`, sends `RendezvousInfo(code)`.
3. Code is delivered to the initiator out-of-band (human-readable).
4. Initiator → `GetIdentity(code)`. Server looks up the code; if present,
   not expired (> 300 s), and not previously used, marks it used and
   replies with `IdentityInfo { fingerprint, identity }`. Subsequent
   lookups fail; a background sweep runs every 60 s to purge expired
   entries.

Because rendezvous transmits no shared secret, the resulting Noise
session MUST be MITM-verified via `HandshakeFingerprint` (§4.3).

**PSK token** (pre-shared): the responder exports
`PskToken = hex(psk) || "_" || hex(fingerprint)` (64 + 1 + 64 = 129
chars). The initiator parses it and skips `GetIdentity`. The PSK
authenticates the Noise handshake; no out-of-band verification required.

### 3.3 Message routing

Clients address peers by `IdentityFingerprint`.

- Client → Server: `Send { destination, payload }`. Any `source` field
  from the client is ignored.
- Server → recipients: `Send { source, destination, payload }` where
  `source` is the *authenticated* sender fingerprint (server-asserted).
- If `destination` has multiple connections, the message is delivered to
  **all** of them (fan-out). If none are connected, the message is
  silently dropped with a log warning (**Editor note:** We'd like to adress this to be more resilient).
- The server performs no inspection, no ordering guarantees beyond
  per-connection FIFO, and no retry.

`payload` is an opaque `bytes`; in this protocol it always carries a
JSON-serialized `ProtocolMessage` (§5).

## 4. End-to-End Layer (`ap-noise`)

Noise messages and transport packets are serialized as **CBOR**, then
embedded in the Send `payload`. (The `ProtocolMessage` wrapper puts
handshake/transport bytes into a JSON field as base64 - see §5.)

> **Editor note.** We should consider using CBOR over JSON for the
> ProtocolMessage.

### 4.1 Ciphersuites

| ID (u8) | Name | DH / KEM | AEAD | Hash |
|---------|------|----------|------|------|
| `0x01` | `ClassicalNNpsk2_25519_XChaCha20Poly1305` | Curve25519 (X25519) | XChaCha20-Poly1305 | SHA-256 |
| `0x02` | `PQNNpsk2_Kyber768_XChaCha20Poly1305` | ML-KEM-768 | XChaCha20-Poly1305 | SHA-256 |

Default is classical; with `experimental-post-quantum-crypto` the default
is PQ.

> **Editor note: why XChaCha20-Poly1305 in the transport, and not in the handshake (yet).**
> Standard Noise drives its AEAD with a 64-bit counter nonce owned by
> the encryptor, which is safe only when a single party holds the send
> key. In this protocol a UserClient identity may be live on multiple
> devices simultaneously, all encrypting under the same session key; a
> shared counter would require cross-device coordination on every send,
> and uncoordinated counters cause nonce reuse, which under
> ChaCha20-Poly1305 is catastrophic (it leaks plaintext XORs and the
> Poly1305 one-time key, enabling forgery).
>
> A 64-bit *random* nonce is not a fix: the birthday bound caps safe
> usage at ~2¹⁶ messages per key (NIST SP 800-38D threshold,
> p_collision ≤ 2⁻³²). XChaCha20-Poly1305's 192-bit nonce pushes the
> same bound past 2⁸⁰ messages, so independent devices can sample
> nonces with a CSPRNG and never coordinate. Cost: 24 B of nonce on
> every transport packet, plus the `seen_nonces` replay set (§4.5).
>
> The **handshake** retains standard ChaChaPoly with 64-bit counter
> nonces. It has a single encryptor per direction and two messages
> total, so the multi-device collision problem does not apply. Our
> Noise library (`clatter`) also does not expose XChaCha primitives,
> so unifying would require forking it for no security benefit. While
> the asymmetry is intentional; we'd prefer consistency and may
> revisit if upstream support lands.

### 4.2 Handshake (NNpsk2)

Two messages, initiator → responder → initiator:

```
MessageType::HandshakeStart   = 0x01     // I → R
MessageType::HandshakeFinish  = 0x02     // R → I
```

Both sides agree on a `Psk` (32 bytes). If no real PSK is available
(rendezvous mode), both sides MUST use `Psk::null()` (all-zero). A
mismatched PSK causes `HandshakeReadError` on the receiver.

`HandshakePacket` (CBOR):

```
HandshakePacket {
  message_type:  u8,     // 0x01 | 0x02
  ciphersuite:   u8,     // 0x01 | 0x02
  payload:       bytes,  // raw Noise bytes (≤ 65 535)
}
```

On finalize, the split yields two 32-byte keys: `i2r_key` and `r2i_key`.
The initiator sets `send = i2r_key, recv = r2i_key`; the responder the
opposite. The handshake state's nonce counters are discarded; the
transport uses random nonces.

> **Editor note: why clatter.** We picked
> [clatter](https://docs.rs/clatter) over the more common
> [snow](https://docs.rs/snow) for two reasons:
>
> 1. **Post-quantum support.** clatter implements the
>    `noise_pqnn_psk2` pattern with `PqHandshake<MlKem768, …>`, giving
>    us ML-KEM-768 NNpsk2 natively. snow has no post-quantum KEM
>    support.
> 2. **Access to the split keys.** clatter's `finalize()` returns a
>    `TransportState` whose per-direction `CipherStates` expose the raw
>    32-byte keys via `.take()` (see `handshake.rs::finalize`). That's
>    what lets us drive our own XChaCha20-Poly1305 transport (§4.1)
>    and serialize sessions for resumption (§4.7), instead of being
>    locked to clatter's internal transport state.

### 4.3 HandshakeFingerprint

```
HandshakeFingerprint = hex(SHA256(r2i_key || i2r_key)[0..3])   // 6 hex
```

Computed identically on both sides, derived from post-handshake keys so
a MITM cannot force it. In **rendezvous** (null-PSK) mode, both parties
MUST display this 6-char value and confirm equality out-of-band before
exchanging credentials. In PSK mode, verification is unnecessary because
the handshake would fail on mismatch.

> **Editor note.** Please see caveat about commitment scheme
> improvement to rendezvous flows.

### 4.4 Transport

`TransportPacket` (CBOR):

```
TransportPacket {
  nonce:      bytes[24],   // random XChaCha20 nonce
  ciphertext: bytes,       // XChaCha20-Poly1305(key, nonce, plaintext, aad)
  aad:        bytes,       // CBOR-encoded TransportPacketAad
}

TransportPacketAad {
  timestamp:     u64,   // seconds since Unix epoch
  chain_counter: u64,   // sender's rekey counter at encrypt time, starts at 1
  ciphersuite:   u8,
}
```

Encryption:

1. If `now - last_rekeyed_time ≥ REKEY_INTERVAL`, advance the send chain
   (see §4.6) until caught up.
2. Build AAD with `now`, current `send_rekey_counter`, ciphersuite.
3. Generate a fresh 24-byte random nonce.
4. `XChaCha20-Poly1305::encrypt(send_key, nonce, plaintext, aad_bytes)`.

Decryption, in order:

1. Parse AAD; reject if `ciphersuite` mismatches the transport's.
2. Timestamp window: reject if
   `timestamp < now - MAX_MESSAGE_AGE` (too old) or
   `timestamp > now + CLOCK_SKEW_TOLERANCE` (too new).
3. Replay check: reject if `nonce ∈ seen_nonces`; otherwise insert with
   `timestamp`. Prune entries older than `MAX_MESSAGE_AGE` before check.
4. Receive rekey catch-up (§4.6).
5. `XChaCha20-Poly1305::decrypt(recv_key, nonce, ct, aad_bytes)`.

### 4.5 Replay protection

- Nonces are not counters; uniqueness relies on the random 192-bit nonce
  and explicit de-duplication against `seen_nonces` for the duration of
  the timestamp window.
- `seen_nonces` is in-memory only; resets on process restart. The
  timestamp window (MAX_MESSAGE_AGE) bounds the acceptance interval such
  that lost replay state is recovered within `MAX_MESSAGE_AGE`.

> **Editor note: persisting replay state.** We should consider
> persisting `seen_nonces`, or consider persisting a "high-water-mark"
> timestamp with the last-seen message, and let clients reject messages
> older than it.

### 4.6 Rekey chain

Both sides maintain independent send/recv keys and rekey counters,
starting at `1`. The rekey function:

```
rekey(k) = XChaCha20-Poly1305::encrypt(k, 0xFF*24, 0*32, aad=[])[0..32]
```

This is deterministic given a key. Each rekey is one-way.

- **Send side**: every `REKEY_INTERVAL` (24 h), `send_key ← rekey(send_key)`
  and `send_rekey_counter += 1`. Advances multiple steps if the sender
  was idle longer than one interval.
- **Receive side**: on decrypt, inspect `packet.chain_counter = c`:
  - `c < recv_rekey_counter`: `Desynchronized` (old key no longer
    derivable; session unrecoverable, must re-handshake).
  - `c > recv_rekey_counter + MAX_REKEY_GAP`: `Desynchronized`.
  - Otherwise: advance `recv_key` until `recv_rekey_counter == c - 1`,
    then decrypt with either `recv_key` (if `c == recv_rekey_counter`)
    or one further rekey (if `c == recv_rekey_counter + 1`). This allows
    out-of-order delivery across the transition boundary without
    dropping either side.

### 4.7 Session persistence

A session can be suspended/resumed without re-handshaking.
`PersistentTransportState` is CBOR-encoded:

```
PersistentTransportState {
  ciphersuite:        u8,
  send_key:           bytes[32],
  recv_key:           bytes[32],
  send_rekey_counter: u64,
  recv_rekey_counter: u64,
  last_rekeyed_time:  u64,
  rekey_interval:     u64,
}
```

`seen_nonces` is **not** persisted; after restore, the
timestamp window (`MAX_MESSAGE_AGE`) provides replay protection during
the replay-state warm-up.

## 5. Application Messages

Carried inside `Send.payload` as JSON-serialized `ProtocolMessage`,
internally tagged via `type`:

```
{"type":"handshake-init",     "data":"<b64(HandshakePacket)>", "ciphersuite":"<name>", "psk_id":"<16-hex>"?}
{"type":"handshake-response", "data":"<b64(HandshakePacket)>", "ciphersuite":"<name>"}
{"type":"credential-request", "encrypted":"<b64(TransportPacket)>"}
{"type":"credential-response","encrypted":"<b64(TransportPacket)>"}
```

- `data` and `encrypted` are base64 of the CBOR bytes.
- `psk_id = hex(SHA256(psk)[0..8])` (16 hex chars). Absent/null in
  rendezvous mode. Responder uses it to match an inbound handshake to a
  pending PSK pairing.

### 5.1 CredentialRequest

Plaintext inside a `credential-request` is a JSON document:

```jsonc
{
  "type":      "credential-request",   // fixed discriminator
  "query":     { "domain": "example.com" } | { "id": "..." } | { "search": "..." },
  "timestamp": 1729600000,              // u64, seconds since Unix epoch
  "requestId": "9f7c8e2b-4a1d-..."      // opaque string, caller-generated; see §5.1
}
```

- **`query`**: exactly one variant (externally tagged by camelCase key):
  - `domain`: URL or host; semantically "find a credential whose URI
    matches this domain". The responder is expected to normalize (scheme
    stripping, suffix match, eTLD+1 collapse, etc.) per vendor policy.
  - `id`: a vault-item identifier that the caller already knows
    (typically returned from a previous search). Resolution is
    responder-defined.
  - `search`: free-text search over item names, usernames, URIs, etc.
    Semantics are responder-defined; may return the first match or an
    ambiguity error.
- **`timestamp`**: caller's wall-clock at send time. The responder MAY
  reject stale requests but is not required to; the transport already
  enforces `MAX_MESSAGE_AGE`.
- **`requestId`**: opaque string, echoed verbatim in the response.
  Lets the caller correlate responses with outstanding requests; the
  transport is bidirectional with no request/response ordering
  guarantee, so the caller cannot rely on arrival order. Uniqueness
  across outstanding requests is a caller concern; the responder does
  not track it.

### 5.2 CredentialResponse

```jsonc
{
  "credential": {
    "credentialId": "b1f2-...",         // optional; vendor vault item ID
    "domain":       "example.com",      // optional, exists because uri may contain information.
    "uri":          "https://example.com/login",  // optional
    "username":     "alice@example.com",          // optional
    "password":     "hunter2",                    // optional; treated as secret
    "totp":         "123456",                     // optional; current OTP value OR an otpauth:// URI (vendor choice)
    "notes":        "..."                         // optional
  },
  "error":     null,                    // absent on success
  "requestId": "9f7c8e2b-4a1d-..."      // echoed from the request
}
```

- Exactly one of `credential` or `error` is present.
- On failure, `credential` is absent and `error` carries a
  human-readable string.

  > **Editor note: structured errors.** Error classes are not yet
  > enumerated. We should replace the free-form string with a
  > discriminated enum (`not-found`, `ambiguous`, `user-rejected`,
  > `locked`, `forbidden`, `internal`, ...).
- All fields in `credential` are optional; a responder MAY return a
  subset (e.g. username-only for a partial match, or TOTP-only for a
  second-factor-only item). Callers MUST tolerate any subset.

### 5.3 Request/response lifecycle

1. RemoteClient encrypts a `CredentialRequestPayload` with the session
   transport and sends it as a `credential-request`.
2. UserClient decrypts, surfaces the request to the user (or to a
   policy engine etc), awaits an approve/deny decision,
   resolves the vault lookup, and returns either a `credential` or an
   `error` with the same `requestId`.
3. No implicit retry. If the caller times out, it MAY issue a new
   request with a new `requestId`; the previous one is abandoned.
4. No streaming. One request → at most one response. Multiple
   credentials are obtained via multiple requests.

### 5.4 Open items

A non-exhaustive list of open items.

- **Asserted identities**. Current scheme is anonymouse. We'd like to
  add optional but strong attestation to identities, e.g. certificates.
- **Credential writes / updates.** A future version
  may add `credential-create`, `credential-update`.
- **Capability negotiation.** No way today for a caller to discover
  what query types or fields a responder supports.
- **Structured errors.** Replace `error: string` with a tagged enum.
- **Context metadata.** The responder may want the request to carry a
  purpose string ("agent X accessing site Y for user task Z") to
  display in the approval UI.
- **Proxy Buffering.** The proxy requires clients to be online. We
  could relax that
- **Mandated re-handshakes**. We currently do not do automatic
  self-healing. We could consider a SHOULD based on time/count.


## 6. Constants & Wire Formats

> **Editor note.** I don't think we'll keep this in it's current
> format, but good for refencing.

| Name | Value | Layer |
|------|-------|-------|
| `CHALLENGE_SIZE` | 32 B | Proxy |
| `AUTH_TIMEOUT` | 5 s | Proxy |
| `CLIENT_INACTIVITY_TIMEOUT` | 120 s | Proxy |
| Rendezvous code | `[A-Z0-9]{3}-…-…` (9 chars) | Proxy |
| Rendezvous TTL | 300 s, single-use | Proxy |
| Rendezvous sweep | every 60 s | Proxy |
| `PSK_LENGTH` | 32 B | Noise |
| `PskId` | `hex(SHA256(psk)[0..8])` (16 chars) | Noise |
| `HandshakeFingerprint` | 6 hex chars | Noise |
| `IdentityFingerprint` | 32 B (64 hex) | Proxy/Noise |
| `MAX_NOISE_MESSAGE_SIZE` | 65 535 B | Noise |
| `MAX_MESSAGE_AGE` | 86 400 s (24 h) | Transport |
| `CLOCK_SKEW_TOLERANCE` | 60 s | Transport |
| `REKEY_INTERVAL` | 86 400 s (24 h) | Transport |
| `MAX_REKEY_GAP` | 1 024 | Transport |
| Transport nonce | 24 B random | Transport |

| Encoding | Where |
|----------|-------|
| JSON (WebSocket text) | Proxy `Messages`, `ProtocolMessage` |
| CBOR | COSE keys, `COSE_Sign1`, `HandshakePacket`, `TransportPacket`, `TransportPacketAad`, `PersistentTransportState` |
| Base64 | `ProtocolMessage.data` and `.encrypted` fields |
| Hex | Fingerprints, PSKs, PSK tokens, PSK IDs |
