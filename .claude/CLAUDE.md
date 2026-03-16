# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Agent Access SDK — a Rust workspace implementing secure peer-to-peer credential sharing over a WebSocket proxy with end-to-end encryption via the Noise Protocol (NNpsk2 pattern). The proxy server is zero-knowledge and cannot decrypt traffic.

## Build & Run Commands

```bash
cargo build                        # Build all crates (debug)
cargo build --release              # Build all crates (release)
cargo run --bin aac                # Run the CLI application
cargo run --bin ap-proxy           # Run the WebSocket proxy server
```

## Testing

```bash
cargo test                         # Run all tests
cargo test -p ap-proxy             # Run proxy tests only
cargo test -p ap-client            # Run client tests only
cargo test --test <test_name>      # Run a specific integration test
```

Integration tests are in `crates/ap-proxy/tests/` and `crates/ap-client/tests/`.

## Linting & Formatting

```bash
cargo clippy --workspace           # Lint all crates
cargo fmt --all                    # Format all crates
cargo fmt --all -- --check         # Check formatting without modifying
```

**Clippy rules**: `unwrap_used = "deny"` (use `expect()` or proper error handling), `string_slice = "warn"`.

Pre-commit hook runs `npx lint-staged` via Husky.

## Environment Variables

- `BIND_ADDR` — Proxy server bind address (default: `127.0.0.1:8080`)
- `RUST_LOG` — Tracing log filter. Proxy defaults to INFO; CLI defaults to WARN (`--verbose` upgrades to DEBUG)

## Feature Flags

- `experimental-post-quantum-crypto` — Enables ML-KEM-768 key exchange and ML-DSA-65 signatures. **On by default** in `ap-proxy`; off by default in `ap-noise`. When enabled, `IdentityKeyPair::generate()` uses ML-DSA-65 instead of Ed25519.

## Workspace Crate Architecture

```
ap-cli (CLI binary)
  └── ap-client (protocol client library)
        ├── ap-noise (Noise handshake + encrypted transport)
        │     └── ap-error / ap-error-macro (error infrastructure)
        └── ap-proxy (WebSocket proxy server + client library)
```

- **ap-noise** — Noise NNpsk2 handshake, `MultiDeviceTransport` for encrypted messaging, XChaCha20-Poly1305 transport encryption, session state persistence for resumption.
- **ap-proxy** — WebSocket proxy server (`ap-proxy` binary) and `ProxyProtocolClient` library. Three-phase protocol: authentication, rendezvous, messaging. Default listen address: `ws://localhost:8080`.
- **ap-client** — `RemoteClient` (untrusted device requesting credentials) and `UserClient` (trusted device serving credentials). Uses trait abstractions (`SessionStore`, `IdentityProvider`, `ProxyClient`) and async event/response channels.
- **ap-cli** (`aac` binary) — CLI driver with interactive TUI (ratatui + crossterm) and non-interactive single-shot mode. Subcommands: `connect`, `listen`, `cache` (with `clear`/`list`), `list-devices`, `clear-keypairs`. Integrates with `bw` CLI for credential lookup via `bw get item`.
- **ap-error / ap-error-macro** — Error handling utilities ported from Bitwarden's `sdk-internal`.

## Key Design Patterns

- **Trait-based abstractions**: `SessionStore`, `IdentityProvider`, `ProxyClient` decouple protocol logic from storage/transport implementations
- **Event-response model**: Clients communicate via `tokio::sync::mpsc` channels — clients emit events, callers send responses
- **Connection modes**: `ConnectionMode::New` (rendezvous pairing token), `ConnectionMode::NewPsk`, `ConnectionMode::Existing` (cached session)
- **Fingerprint verification**: 6-character hex handshake fingerprints (SHA256 of transport keys, first 3 bytes) for out-of-band verification between peers

## Three-Phase Proxy Protocol

1. **Authentication**: Server sends `AuthChallenge` (32-byte nonce) → client replies with `AuthResponse` (COSE_Sign1 signature + COSE public key identity) → server verifies and registers connection by `IdentityFingerprint`. 5-second timeout.
2. **Rendezvous** (optional, new connections only): Client sends `GetRendevouz` → server generates 9-char code (5-minute TTL, single-use) → discovering client sends `GetIdentity(code)` → server returns target's `IdentityInfo`.
3. **Messaging**: `Send { source, destination, payload }` — server replaces source with authenticated fingerprint, delivers to all connections matching destination fingerprint (supports multiple concurrent connections per identity).

Noise handshake and encrypted credential payloads are layered on top as `ProtocolMessage` variants sent through the messaging phase.

## Serialization Formats

| Layer | Format |
|-------|--------|
| Proxy wire protocol | JSON (WebSocket text frames) |
| Identity key files (`~/.access-protocol/*.key`) | CBOR via COSE |
| Session cache (`~/.access-protocol/session_cache_*.json`) | JSON |
| Transport state (inside session cache) | CBOR byte array |
| Handshake/encrypted payloads over wire | Base64-encoded binary inside JSON |
| Auth challenge signatures | COSE_Sign1 (CBOR) |

## Single-Shot Non-Interactive Mode

For agent/LLM integration: `aac connect --domain example.com [--output json|text]`

- No TUI — status to stderr, credential output to stdout
- If exactly one cached session exists, it is used automatically (no `--token` or `--session` needed)
- With multiple cached sessions, `--session` is required to disambiguate
- `--token` starts a new handshake (rendezvous or PSK) regardless of cache
- No fingerprint verification (headless)
- PSK token format: `<64-hex-psk>_<64-hex-fingerprint>` (129 chars)
- Output formats: `text` (key-value lines) or `json` (`{"success": true, "credential": {...}}`)
- Exit codes: 0=success, 1=general error, 2=connection failed, 3=auth/handshake failed, 4=credential not found, 5=fingerprint mismatch

## Session Persistence

Storage directory: `~/.access-protocol/`
- Identity keypairs: `{name}.key` — CBOR-encoded COSE key (32-byte seed, keypair rederived on load)
- Session cache: `session_cache_{name}.json` — array of sessions keyed by `IdentityFingerprint`, with optional `PersistentTransportState` (CBOR) for session resumption without re-handshake
- Transport auto-rekeys every 24 hours; replay nonces are not persisted (reset on load, 24h max message age)

## Before Committing

Always run these checks before committing:

```bash
cargo fmt --all -- --check         # Verify formatting
cargo clippy --workspace           # Lint check
cargo build --workspace            # Verify it compiles
cargo test --workspace             # Run all tests
```

## Rust Conventions

- **Write idiomatic Rust**: prefer iterators over manual loops, use pattern matching, leverage the type system, embrace ownership/borrowing, and follow standard Rust API guidelines
- Edition 2024, minimum Rust version 1.85, toolchain channel 1.93
- Async runtime: Tokio (multi-threaded)
- Error handling: `thiserror` for library errors, `color-eyre` in the CLI binary
- All crypto memory uses `zeroize` for secure cleanup
- Release profile: LTO enabled, `opt-level = "z"` (size-optimized), single codegen unit

## Demo Flow

1. Start proxy: `cargo run --bin ap-proxy`
2. Start user-client: `cargo run --bin aac -- listen`
3. Copy the pairing token (9-char code, e.g. `ABC-DEF-GHI`) from step 2, connect: `cargo run --bin aac -- connect --token <CODE>`
4. Type domains on the connect side to request credentials; approve on the listen side

Use `--psk` on the listen side for PSK mode instead of rendezvous pairing tokens.
