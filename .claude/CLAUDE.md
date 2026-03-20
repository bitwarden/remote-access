# Agent Access SDK - Claude Code Configuration

Rust workspace implementing secure peer-to-peer credential sharing over a WebSocket proxy with end-to-end encryption via the Noise Protocol (NNpsk2 pattern). The proxy server is zero-knowledge and cannot decrypt traffic.

## Overview

### What This Project Does
- Enables secure, encrypted credential retrieval between a trusted device (UserClient) and an untrusted device (RemoteClient) through a zero-knowledge WebSocket relay proxy
- Ships two binaries: `aac` (CLI for credential operations) and `ap-proxy` (WebSocket relay server)
- Consumed as a library (`ap-client`) by integrators building custom credential-sharing workflows

### Key Concepts
- **Zero-knowledge proxy** — the relay server authenticates clients by identity fingerprint but never sees plaintext credentials
- **Noise NNpsk2** — a Noise Protocol pattern providing encryption with optional pre-shared key authentication; the "NN" means neither side presents a static key during the handshake, and "psk2" injects a PSK after the second message
- **IdentityFingerprint** — SHA256 hash of a client's public key (32 bytes / 64 hex chars), used as a stable addressing identifier in the proxy
- **HandshakeFingerprint** — 6-character hex string derived from transport keys (`SHA256(r2i_key || i2r_key)[0..3]`), used for out-of-band MITM verification
- **Rendezvous code** — 9-character alphanumeric code (format `ABC-DEF-GHI`, 36^9 entropy) with 5-minute TTL for initial pairing
- **PSK token** — `<64-hex-psk>_<64-hex-fingerprint>` (129 chars) for pre-authenticated pairing without rendezvous
- **PskId** — `SHA256(psk)[0..8]` as hex (16 chars), a non-secret identifier for PSK lookup
- **Session resumption** — cached `PersistentTransportState` (CBOR) allows reconnection without re-handshaking; transport auto-rekeys every 24 hours
- **Event-response model** — clients communicate via `tokio::sync::mpsc` channels; clients emit notifications (fire-and-forget) and requests (requiring a `oneshot` reply)

---

## Architecture & Patterns

### System Architecture

```
    Remote Device                          User Device
   (untrusted)                            (trusted)
        |                                      |
   RemoteClient                          UserClient
        |                                      |
   +----------+                         +----------+
   | ap-noise |  Noise NNpsk2 E2E       | ap-noise |
   |(handshake|<----------------------->|(handshake |
   |+transport|  XChaCha20-Poly1305     |+transport)|
   +----+-----+                         +-----+----+
        |                                      |
   ap-proxy-client                      ap-proxy-client
        |         WebSocket (JSON)             |
        +--------------+  +--------------------+
                       v  v
                +--------------+
                |   ap-proxy   |  Zero-knowledge relay
                |  (WebSocket  |  Auth + Rendezvous +
                |   server)    |  Message routing
                +--------------+
```

### Code Organization

```
crates/
├── ap-cli/                  # CLI binary ("aac")
│   └── src/
│       ├── main.rs
│       ├── command/         # connect, listen, connections, run
│       │   ├── mod.rs       # Cli struct, Commands enum, dispatch
│       │   ├── connect.rs   # Remote-client connect flow
│       │   ├── listen.rs    # User-client listen flow
│       │   ├── connections.rs # list/clear cached sessions
│       │   ├── run.rs       # Fetch credential -> exec command
│       │   ├── output.rs    # OutputFormat (text/json)
│       │   ├── tui.rs       # Interactive ratatui TUI
│       │   ├── tui_tracing.rs
│       │   └── util.rs
│       ├── providers/
│       │   └── bitwarden.rs # bw CLI credential lookup
│       └── storage/
│           ├── session_storage.rs  # File-backed SessionStore
│           └── identity_storage.rs # File-backed IdentityProvider
├── ap-client/               # High-level client library
│   └── src/
│       ├── lib.rs
│       ├── clients/
│       │   ├── remote_client.rs  # RemoteClient + notifications/requests
│       │   └── user_client.rs    # UserClient + notifications/requests
│       ├── traits.rs        # SessionStore, IdentityProvider, AuditLog
│       ├── proxy.rs         # ProxyClient trait
│       ├── types.rs         # CredentialData, ConnectionMode, PskToken, etc.
│       ├── memory_session_store.rs
│       ├── error.rs         # ClientError
│       └── compat.rs
├── ap-noise/                # Noise Protocol + transport encryption
│   └── src/
│       ├── lib.rs
│       ├── handshake.rs     # InitiatorHandshake, ResponderHandshake
│       ├── transport.rs     # MultiDeviceTransport (encrypt/decrypt)
│       ├── ciphersuite.rs   # Classical vs PQ ciphersuite selection
│       ├── persistence.rs   # PersistentTransportState
│       ├── packet.rs        # HandshakePacket, TransportPacket
│       ├── psk.rs           # Psk, PskId generation
│       ├── symmetric_key.rs # SymmetricKey (ZeroizeOnDrop)
│       └── error.rs         # NoiseProtocolError
├── ap-proxy/                # WebSocket proxy server binary + library
│   └── src/
│       ├── main.rs
│       ├── lib.rs
│       ├── server/
│       │   ├── proxy_server.rs  # ProxyServer::run()
│       │   ├── handler.rs       # Per-connection auth + message routing
│       │   └── mod.rs
│       └── connection.rs
├── ap-proxy-client/         # WebSocket client for proxy protocol
│   └── src/
│       ├── lib.rs
│       ├── protocol_client.rs  # ProxyProtocolClient (WebSocket impl)
│       └── config.rs           # IncomingMessage enum
├── ap-proxy-protocol/       # Shared wire protocol types
│   └── src/
│       ├── lib.rs
│       ├── messages.rs      # Messages enum (AuthChallenge, Send, etc.)
│       ├── auth.rs          # IdentityKeyPair, Identity, Challenge, etc.
│       ├── rendezvous.rs    # RendezvousCode
│       └── error.rs         # ProxyError
├── ap-error/                # FlatError trait
│   └── src/
│       ├── lib.rs
│       └── flat_error.rs
└── ap-error-macro/          # #[ap_error(flat)] proc macro
    └── src/
        └── lib.rs

examples/
├── remote-client/           # Minimal RemoteClient example
├── user-client/             # Minimal UserClient example
├── rustapp/                 # Rust app example
├── python-pyo3/             # Python bindings (excluded from workspace)
├── shell/                   # Shell script examples (get-credential.sh, psql-connect.sh)
└── skills/                  # Agent integration skill definition
```

### Crate Dependency Hierarchy

```
ap-cli (binary: aac)
  └── ap-client (protocol client library)
        ├── ap-noise (Noise handshake + encrypted transport)
        │     └── ap-error / ap-error-macro (error infrastructure)
        ├── ap-proxy-client (WebSocket client)
        │     └── ap-proxy-protocol (wire protocol types)
        └── ap-proxy-protocol
```

- **ap-noise** — Noise NNpsk2 handshake, `MultiDeviceTransport` for encrypted messaging, XChaCha20-Poly1305 transport encryption, session state persistence for resumption.
- **ap-proxy** — WebSocket proxy server (`ap-proxy` binary). Three-phase protocol: authentication, rendezvous, messaging. Default listen address: `ws://localhost:8080`.
- **ap-proxy-client** — `ProxyProtocolClient` WebSocket client library for connecting to the proxy.
- **ap-proxy-protocol** — Shared wire protocol types (`Messages`, `Challenge`, `Identity`, `RendezvousCode`, etc.).
- **ap-client** — `RemoteClient` (untrusted device requesting credentials) and `UserClient` (trusted device serving credentials). Uses trait abstractions (`SessionStore`, `IdentityProvider`, `ProxyClient`) and async event/response channels.
- **ap-cli** (`aac` binary) — CLI driver with interactive TUI (ratatui + crossterm) and non-interactive single-shot mode. Subcommands: `connect`, `listen`, `connections` (with `clear`/`list`), `run`. Integrates with `bw` CLI for credential lookup via `bw get item`.
- **ap-error / ap-error-macro** — Error handling utilities ported from Bitwarden's `sdk-internal`. Provides the `FlatError` trait and `#[ap_error(flat)]` proc macro.

### Key Principles
1. **Zero-knowledge relay** — the proxy authenticates identities but never sees plaintext; all credential data is encrypted end-to-end via Noise
2. **Trait-based abstractions** — `SessionStore`, `IdentityProvider`, `ProxyClient`, and `AuditLog` decouple protocol logic from storage, transport, and auditing implementations
3. **Event-response channels** — clients emit `Notification` events (fire-and-forget via `mpsc`) and `Request` events (requiring a `oneshot::Sender` reply), keeping the protocol loop decoupled from UI/business logic

### Core Patterns

#### Trait Abstraction Pattern

**Purpose**: Decouple protocol logic from storage, identity, and transport implementations so consumers can plug in their own backends.

**Key traits** (`crates/ap-client/src/traits.rs` and `crates/ap-client/src/proxy.rs`):

```rust
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<SessionInfo>;
    async fn save(&mut self, session: SessionInfo) -> Result<(), ClientError>;
    async fn update(&mut self, update: SessionUpdate) -> Result<(), ClientError>;
    async fn list(&self) -> Vec<SessionInfo>;
}

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    async fn identity(&self) -> IdentityKeyPair;
    async fn fingerprint(&self) -> IdentityFingerprint { /* default impl */ }
}

#[async_trait]
pub trait ProxyClient: Send + Sync {
    async fn connect(&mut self, identity: IdentityKeyPair)
        -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ClientError>;
    async fn request_rendezvous(&self) -> Result<(), ClientError>;
    async fn request_identity(&self, code: RendezvousCode) -> Result<(), ClientError>;
    async fn send_to(&self, fingerprint: IdentityFingerprint, data: Vec<u8>)
        -> Result<(), ClientError>;
    async fn disconnect(&mut self) -> Result<(), ClientError>;
}

#[async_trait]
pub trait AuditLog: Send + Sync {
    async fn write(&self, event: AuditEvent<'_>);
}
```

**Built-in implementations**: `MemorySessionStore`, `MemoryIdentityProvider`, `NoOpAuditLog` (all in `ap-client`); `ProxyProtocolClient` (in `ap-proxy-client`).

#### Event-Response Channel Pattern

**Purpose**: Keep the protocol event loop decoupled from UI and business logic by communicating through typed channels.

**Structure** (from `RemoteClient::connect()` and `UserClient::connect()`):

```rust
pub struct UserClientHandle {
    pub client: UserClient,                                     // Control handle
    pub notifications: mpsc::Receiver<UserClientNotification>,  // Fire-and-forget events
    pub requests: mpsc::Receiver<UserClientRequest>,            // Events needing reply
}

// Request with reply channel:
pub enum UserClientRequest {
    CredentialRequest {
        query: CredentialQuery,
        identity: IdentityFingerprint,
        reply: oneshot::Sender<CredentialRequestReply>,  // Caller MUST reply
    },
    VerifyFingerprint {
        fingerprint: String,
        identity: IdentityFingerprint,
        reply: oneshot::Sender<FingerprintVerificationReply>,
    },
}
```

**Usage**: The caller spawns a task to drain `notifications` and `requests`, replying via the `oneshot::Sender` on each request.

#### Three-Phase Proxy Protocol

1. **Authentication**: Server sends `AuthChallenge` (32-byte nonce) -> client replies with `AuthResponse` (COSE_Sign1 signature + COSE public key identity) -> server verifies and registers connection by `IdentityFingerprint`. 5-second timeout.
2. **Rendezvous** (optional, new connections only): Client sends `GetRendezvous` -> server generates 9-char code (5-minute TTL, single-use) -> discovering client sends `GetIdentity(code)` -> server returns target's `IdentityInfo`.
3. **Messaging**: `Send { source, destination, payload }` — server replaces source with authenticated fingerprint, delivers to all connections matching destination fingerprint (supports multiple concurrent connections per identity).

Noise handshake and encrypted credential payloads are layered on top as `ProtocolMessage` variants sent through the messaging phase.

---

## Development Guide

### Build & Run

```bash
cargo build                        # Build all crates (debug)
cargo build --release              # Build all crates (release)
cargo run --bin aac                # Run the CLI application
cargo run --bin ap-proxy           # Run the WebSocket proxy server
```

### Adding a New Client Trait Implementation

The most common development task is implementing a new `SessionStore`, `IdentityProvider`, or `ProxyClient` for a new platform or backend.

**1. Implement the trait** (e.g., `my_session_store.rs`)
```rust
use async_trait::async_trait;
use ap_client::{SessionStore, SessionInfo, SessionUpdate, ClientError, IdentityFingerprint};

pub struct MySessionStore { /* ... */ }

#[async_trait]
impl SessionStore for MySessionStore {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<SessionInfo> { todo!() }
    async fn save(&mut self, session: SessionInfo) -> Result<(), ClientError> { todo!() }
    async fn update(&mut self, update: SessionUpdate) -> Result<(), ClientError> { todo!() }
    async fn list(&self) -> Vec<SessionInfo> { todo!() }
}
```

**2. Wire it into a client**
```rust
let handle = RemoteClient::connect(
    Box::new(my_identity_provider),
    Box::new(my_session_store),
    Box::new(ProxyProtocolClient::new(proxy_url)),
).await?;
```

**3. Write tests** — see the mock proxy pattern in `crates/ap-client/tests/pairing.rs`

### Adding a New CLI Subcommand

**1. Create the command file** (`crates/ap-cli/src/command/mycommand.rs`)
```rust
use clap::Args;
use color_eyre::eyre::Result;

#[derive(Args)]
pub struct MyCommandArgs {
    /// Description of the argument
    #[arg(long)]
    pub my_arg: String,
}

impl MyCommandArgs {
    pub async fn run(self) -> Result<()> {
        // Implementation
        Ok(())
    }
}
```

**2. Register in `mod.rs`** (`crates/ap-cli/src/command/mod.rs`)
```rust
mod mycommand;
pub use mycommand::MyCommandArgs;

#[derive(Subcommand)]
pub enum Commands {
    // ... existing commands ...
    /// My new command description
    MyCommand(MyCommandArgs),
}
```

**3. Add dispatch** in `process_command()`
```rust
Some(Commands::MyCommand(args)) => args.run().await,
```

### Common Patterns

#### Error Handling

Library crates use `thiserror`; the CLI binary uses `color-eyre`:

```rust
// In library code (ap-client, ap-noise, etc.)
#[ap_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum MyError {
    #[error("Something went wrong: {0}")]
    SomethingFailed(String),
}

// In CLI code (ap-cli)
use color_eyre::eyre::{Result, bail};
pub async fn run(self) -> Result<()> {
    bail!("Not implemented");
}
```

Error conversion between layers uses manual `From` impls that flatten to string messages:
```rust
impl From<NoiseProtocolError> for ClientError {
    fn from(err: NoiseProtocolError) -> Self {
        ClientError::NoiseProtocol(err.to_string())
    }
}
```

#### Connection Modes

```rust
pub enum ConnectionMode {
    New { rendezvous_code: String },           // Rendezvous pairing
    NewPsk { psk: Psk, remote_fingerprint: IdentityFingerprint },  // PSK pairing
    Existing { remote_fingerprint: IdentityFingerprint },          // Cached session
}
```

### Demo Flow

1. Start proxy: `cargo run --bin ap-proxy`
2. Start user-client: `cargo run --bin aac -- listen`
3. Copy the pairing token (9-char code, e.g. `ABC-DEF-GHI`) from step 2, connect: `cargo run --bin aac -- connect --token <CODE>`
4. Type domains on the connect side to request credentials; approve on the listen side

Use `--psk` on the listen side for PSK mode instead of rendezvous pairing tokens.

### Single-Shot Non-Interactive Mode

For agent/LLM integration: `aac connect --domain example.com [--output json|text]`

- No TUI — status to stderr, credential output to stdout
- If exactly one cached session exists, it is used automatically (no `--token` or `--session` needed)
- With multiple cached sessions, `--session` is required to disambiguate
- `--token` starts a new handshake (rendezvous or PSK) regardless of cache
- No fingerprint verification (headless)
- Output formats: `text` (key-value lines) or `json` (`{"success": true, "credential": {...}}`)
- Exit codes: 0=success, 1=general error, 2=connection failed, 3=auth/handshake failed, 4=credential not found, 5=fingerprint mismatch

---

## Data Models

### Core Types

```rust
// Credential payload (crates/ap-client/src/types.rs)
#[derive(Clone, Serialize, Deserialize)]
pub struct CredentialData {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
    pub credential_id: Option<String>,
    pub domain: Option<String>,
}

// Credential lookup query
pub enum CredentialQuery {
    Domain(String),
    Id(String),
    Search(String),
}

// Session state cached for reconnection (crates/ap-client/src/traits.rs)
pub struct SessionInfo {
    pub fingerprint: IdentityFingerprint,
    pub name: Option<String>,
    pub cached_at: u64,
    pub last_connected_at: u64,
    pub transport_state: Option<MultiDeviceTransport>,
}
```

### Wire Protocol Messages

```rust
// Proxy protocol (crates/ap-proxy-protocol/src/messages.rs)
pub enum Messages {
    AuthChallenge(Challenge),
    AuthResponse(Identity, ChallengeResponse),
    GetRendezvous,
    RendezvousInfo(RendezvousCode),
    GetIdentity(RendezvousCode),
    IdentityInfo { fingerprint: IdentityFingerprint, identity: Identity },
    Send { source: Option<IdentityFingerprint>, destination: IdentityFingerprint, payload: Vec<u8> },
}

// Noise-layer protocol (crates/ap-client/src/types.rs)
enum ProtocolMessage {
    HandshakeInit { data: String, ciphersuite: String, psk_id: Option<PskId> },
    HandshakeResponse { data: String, ciphersuite: String },
    CredentialRequest { encrypted: String },
    CredentialResponse { encrypted: String },
}
```

### Serialization Formats

| Layer | Format |
|-------|--------|
| Proxy wire protocol | JSON (WebSocket text frames) |
| Identity key files (`~/.access-protocol/*.key`) | CBOR via COSE |
| Session cache (`~/.access-protocol/session_cache_*.json`) | JSON |
| Transport state (inside session cache) | CBOR byte array |
| Handshake/encrypted payloads over wire | Base64-encoded binary inside JSON |
| Auth challenge signatures | COSE_Sign1 (CBOR) |

### Session Persistence

Storage directory: `~/.access-protocol/`
- Identity keypairs: `{name}.key` — CBOR-encoded COSE key (32-byte seed, keypair rederived on load)
- Session cache: `session_cache_{name}.json` — array of sessions keyed by `IdentityFingerprint`, with optional `PersistentTransportState` (CBOR) for session resumption without re-handshake
- Transport auto-rekeys every 24 hours; replay nonces are not persisted (reset on load, 24h max message age)

---

## Security & Configuration

### Security Rules

**MANDATORY — These rules have no exceptions:**

1. **No `.unwrap()` anywhere** — clippy lint `unwrap_used = "deny"` is workspace-wide. Use `.expect("reason")` or propagate errors with `?`.
2. **Zeroize all key material** — `SymmetricKey` and `Psk` derive `ZeroizeOnDrop`. Any new type holding secret bytes must do the same.
3. **Never log key material** — `SymmetricKey::Debug` outputs a 4-byte SHA256 preview, not the actual key. Follow this pattern for any new secret types.
4. **Random nonces only** — transport uses random 24-byte nonces (not counters) via `XChaCha20Poly1305` to support multi-device without coordination. Never introduce counter-based nonces.
5. **Identity keys are never transmitted in plaintext** — keys are wrapped in COSE structures; only public keys leave the device (via `Identity`).

### Cryptographic Functions

| Component | Algorithm | Purpose | Location |
|-----------|-----------|---------|----------|
| `InitiatorHandshake` / `ResponderHandshake` | Noise NNpsk2 (Curve25519 or ML-KEM-768) | Key agreement | `ap-noise/src/handshake.rs` |
| `MultiDeviceTransport` | XChaCha20-Poly1305 (random nonce) | Transport encryption | `ap-noise/src/transport.rs` |
| `IdentityKeyPair` | Ed25519 or ML-DSA-65 | Identity signing | `ap-proxy-protocol/src/auth.rs` |
| `Challenge::sign()` | COSE_Sign1 | Proxy authentication | `ap-proxy-protocol/src/auth.rs` |
| `HandshakeFingerprint` | SHA256 (first 3 bytes) | MITM verification | `ap-noise/src/handshake.rs` |
| `IdentityFingerprint` | SHA256 (full 32 bytes) | Client addressing | `ap-proxy-protocol/src/auth.rs` |
| `Psk::id()` | SHA256 (first 8 bytes) | Non-secret PSK lookup | `ap-noise/src/psk.rs` |

### Transport Security Constants

```rust
const REKEY_INTERVAL: u64 = 86400;        // 24 hours — automatic re-key interval
const MAX_REKEY_GAP: u64 = 1024;          // Max chain counter gap before Desynchronized error
const MAX_MESSAGE_AGE: u64 = 86400;       // 1 day — reject older messages
const CLOCK_SKEW_TOLERANCE: u64 = 60;     // 1 minute — future message tolerance
const CLIENT_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(120); // Proxy disconnects idle clients
```

### Environment Configuration

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `BIND_ADDR` | No | Proxy server bind address | `127.0.0.1:8080` |
| `RUST_LOG` | No | Tracing log filter | Proxy: `INFO`, CLI: `WARN` |
| `LLM` | No | Disables color output (set by agents) | unset |
| `NO_COLOR` | No | Disables color output (standard) | unset |
| `GIT_HASH` | No | Injected by CI for version string | unset |

### Feature Flags

- `experimental-post-quantum-crypto` — Enables ML-KEM-768 key exchange and ML-DSA-65 signatures. **On by default** in `ap-proxy` and `ap-proxy-client`; off by default in `ap-noise`. When enabled, `IdentityKeyPair::generate()` uses ML-DSA-65 instead of Ed25519, and the default ciphersuite becomes `PQNNpsk2_Kyber768_XChaCha20Poly1305`.
- `native-websocket` — Enables tokio-tungstenite WebSocket transport in `ap-proxy-client`. **On by default**. Disable for WASM targets.

### Authentication & Authorization

- **Proxy authentication**: challenge-response using COSE_Sign1 signatures over a 32-byte random nonce. The server verifies the signature and registers the connection by `IdentityFingerprint`.
- **Peer authentication (PSK mode)**: both sides prove knowledge of a pre-shared key during the Noise handshake. No additional verification needed.
- **Peer authentication (Rendezvous mode)**: no pre-shared secret; users must verify the 6-character `HandshakeFingerprint` out-of-band to prevent MITM.
- **No stored credentials on disk without encryption** — identity keypairs are COSE-encoded but not encrypted at rest (relies on filesystem permissions).

---

## Testing

### Test Structure

```
crates/ap-client/tests/
├── pairing.rs             # Mock-proxy integration tests (PSK, rendezvous, reconnect, backpressure)
└── websocket_proxy.rs     # Real-proxy E2E tests (credential exchange, multi-device, persistence)

crates/ap-proxy/tests/
└── client_integration.rs  # Proxy protocol tests (auth, messaging, broadcast, cleanup)

# Unit tests are embedded in source files via #[cfg(test)] modules throughout all crates
```

### Running Tests

```bash
cargo test                         # Run all tests
cargo test -p ap-proxy             # Run proxy tests only
cargo test -p ap-client            # Run client tests only
cargo test --test pairing          # Run a specific integration test
cargo test --test client_integration
```

### Writing Tests

**Mock Proxy Pattern** (for unit/integration tests without a real server):

```rust
// Create paired mock proxies that relay messages to each other
let (user_proxy, remote_proxy) = create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

let UserClientHandle { client, notifications, requests } = UserClient::connect(
    Box::new(MemoryIdentityProvider::new()),
    Box::new(MemorySessionStore::new()),
    Box::new(user_proxy),
    None,
).await?;
```

See `crates/ap-client/tests/pairing.rs` for the full `MockProxyClient` and `create_mock_proxy_pair()` implementations.

**Real Proxy E2E Pattern** (for full-stack tests):

```rust
// Start an ephemeral proxy on a random port
async fn start_test_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
    let addr = listener.local_addr().expect("should get addr");
    let server = ProxyServer::new(addr);
    tokio::spawn(async move { server.run_with_listener(listener).await.ok() });
    addr
}
```

See `crates/ap-client/tests/websocket_proxy.rs` for full examples.

**Key testing conventions:**
- Always wrap async operations in `tokio::time::timeout()` to prevent hanging tests
- Use `tokio::time::pause()` with `#[tokio::test(flavor = "current_thread")]` for deterministic backoff/timing tests
- Use `.expect("reason")` instead of `.unwrap()` (clippy enforced)
- Use `MemorySessionStore` and `MemoryIdentityProvider` for test isolation

### Test Environment

- **Dev dependencies**: `ap-proxy` (for `ProxyServer` in E2E tests), `tokio` with `rt-multi-thread`, `macros`, `time`, `test-util`
- **No external services required** — all tests are self-contained
- **No test fixtures on disk** — credentials and sessions are created in-memory per test

---

## Code Style & Standards

### Formatting
- **Tool**: `cargo fmt` (rustfmt)
- **Edition**: 2024, minimum Rust version 1.85, toolchain channel 1.93
- **Line width**: 120 columns (from `.editorconfig`)
- **Indentation**: 4 spaces

### Naming Conventions
- `snake_case` for: variables, functions, modules, file names
- `PascalCase` for: types, traits, enum variants
- `SCREAMING_SNAKE_CASE` for: constants
- Binary names: `aac` (CLI), `ap-proxy` (server)
- Crate names: `ap-` prefix for all workspace crates

### Rust Conventions
- **Write idiomatic Rust**: prefer iterators over manual loops, use pattern matching, leverage the type system, embrace ownership/borrowing, and follow standard Rust API guidelines
- Async runtime: Tokio (multi-threaded)
- Error handling: `thiserror` for library errors, `color-eyre` in the CLI binary
- All crypto memory uses `zeroize` for secure cleanup
- Release profile: LTO enabled, `opt-level = "z"` (size-optimized), single codegen unit

### Clippy Lints
```toml
[workspace.lints.clippy]
unwrap_used = "deny"       # Use .expect("reason") or ? operator
string_slice = "warn"      # Avoid unsafe string indexing
```

### Pre-commit Hooks

Husky + lint-staged runs automatically on `git commit`:
1. `cargo fmt --all -- --check` — formatting
2. `cargo clippy --workspace -- -D warnings` — linting (warnings are errors)

### Before Committing

Always run these checks before committing:

```bash
cargo fmt --all -- --check         # Verify formatting
cargo clippy --workspace           # Lint check
cargo build --workspace            # Verify it compiles
cargo test --workspace             # Run all tests
```

---

## Anti-Patterns

### DO

- Use `thiserror` for library error types with `#[ap_error(flat)]` for the `FlatError` trait
- Derive `ZeroizeOnDrop` on any type holding secret key material
- Use `Box<dyn Trait>` for client constructor parameters to keep APIs flexible
- Use `oneshot::Sender` for request-reply patterns between protocol loop and caller
- Wrap async test operations in `tokio::time::timeout()` to prevent hangs
- Use `MemorySessionStore` / `MemoryIdentityProvider` in tests and examples
- Use `.expect("descriptive reason")` when failure is a bug

### DON'T

- Use `.unwrap()` — denied by clippy workspace-wide
- Log or `Debug`-print raw key material — use hashed previews
- Use counter-based nonces — random nonces are required for multi-device
- Encrypt at rest without the user opting in — identity keys rely on filesystem permissions
- Introduce `unsafe` code — not used anywhere in the project
- Skip the `#[ap_error(flat)]` attribute on new error enums — needed for structured error reporting
- Use `std::sync::Mutex` in async code — use `tokio::sync::Mutex` instead

---

## Deployment

### Building

```bash
cargo build --release              # Size-optimized (LTO, opt-level "z", single codegen unit)
```

### Release Targets

CI builds for 4 platforms via GitHub Actions (`release.yml`):
- Linux x86_64 (Ubuntu 24.04)
- macOS aarch64 (macOS 15)
- macOS x86_64 (macOS 15)
- Windows x86_64

### Versioning

Workspace version managed in root `Cargo.toml`: currently **0.7.0**.

### Publishing

Crates are published to crates.io in dependency order via CI (`release.yml`, triggered by `v*` tags):
1. `ap-error-macro` -> 2. `ap-error` -> 3. `ap-noise` -> 4. `ap-proxy-protocol` -> 5. `ap-proxy-client` -> 6. `ap-proxy` -> 7. `ap-client` -> 8. `ap-cli`

---

## Troubleshooting

### Common Issues

#### Pre-commit hook fails on format check

**Problem**: `cargo fmt --all -- --check` reports formatting errors.

**Solution**: Run `cargo fmt --all` to auto-fix, then re-commit.

#### ML-DSA-65 key pair causes stack overflow

**Problem**: Post-quantum keys are ~108KB and can overflow the stack.

**Solution**: ML-DSA keys are already `Box`ed in `IdentityKeyPair::MlDsa65`. If adding new PQ types, always box large key structures.

#### Tests hang indefinitely

**Problem**: Async test blocks forever waiting for a channel message.

**Solution**: Always wrap async operations in `tokio::time::timeout()`. Check that all `oneshot::Sender` reply channels are being responded to.

#### Session resumption fails after transport rekey

**Problem**: `Desynchronized` error when reconnecting with cached session.

**Solution**: Rekey gap exceeded `MAX_REKEY_GAP` (1024). This happens when one side has rekeyed many more times than the other (e.g., long offline period). Clear the session cache and re-pair.

### Debug Tips

- Set `RUST_LOG=debug` (or `--verbose` on the CLI) to see Noise handshake steps and proxy protocol messages
- `RUST_LOG=ap_noise=trace` for transport-level encrypt/decrypt traces
- The proxy logs authenticated identity fingerprints at INFO level — use this to verify connections
- Use `aac connections list` to inspect cached sessions and their transport state

---

## References

### Official Documentation
- [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- [NNpsk2 Pattern](https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental)
- [COSE (RFC 9052)](https://www.rfc-editor.org/rfc/rfc9052.html)

### Internal Documentation
- [CONTRIBUTING.md](../CONTRIBUTING.md) — contribution guidelines
- [SECURITY.md](../SECURITY.md) — security policy and vulnerability reporting
- [examples/skills/agent-access/SKILL.md](../examples/skills/agent-access/SKILL.md) — agent integration skill definition

### Key Dependencies
- [snow](https://docs.rs/snow) — Noise Protocol implementation (classical)
- [clatter](https://docs.rs/clatter) — Noise Protocol with post-quantum KEM support
- [chacha20poly1305](https://docs.rs/chacha20poly1305) — AEAD cipher
- [ed25519-dalek](https://docs.rs/ed25519-dalek) — Ed25519 signatures
- [coset](https://docs.rs/coset) — COSE encoding/decoding
- [ratatui](https://docs.rs/ratatui) — Terminal UI framework
