# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bitwarden Remote Access SDK — a Rust workspace implementing secure peer-to-peer credential sharing over WebSocket relay with end-to-end encryption via the Noise Protocol (NNpsk2 pattern). The proxy server is zero-knowledge and cannot decrypt traffic.

## Build & Run Commands

```bash
cargo build                        # Build all crates (debug)
cargo build --release              # Build all crates (release)
cargo run --bin bw-remote          # Run the CLI application
cargo run --bin bw-proxy           # Run the WebSocket proxy server
```

## Testing

```bash
cargo test                         # Run all tests
cargo test -p bw-proxy             # Run proxy tests only
cargo test -p bw-rat-client        # Run client tests only
cargo test --test <test_name>      # Run a specific integration test
```

Integration tests are in `crates/bw-proxy/tests/` and `crates/bw-rat-client/tests/`.

## Linting & Formatting

```bash
cargo clippy --workspace           # Lint all crates
cargo fmt --all                    # Format all crates
cargo fmt --all -- --check         # Check formatting without modifying
```

**Clippy rules**: `unwrap_used = "deny"` (use `expect()` or proper error handling), `string_slice = "warn"`.

## Workspace Crate Architecture

```
bw-remote (CLI binary)
  └── bw-rat-client (protocol client library)
        ├── bw-noise-protocol (Noise handshake + encrypted transport)
        │     └── bw-error / bw-error-macro (error infrastructure)
        └── bw-proxy (WebSocket relay server + client library)
```

- **bw-noise-protocol** — Noise NNpsk2 handshake, `MultiDeviceTransport` for encrypted messaging, XChaCha20-Poly1305 transport encryption, session state persistence for resumption. Optional post-quantum support via `experimental-post-quantum-crypto` feature flag.
- **bw-proxy** — WebSocket relay server (`bw-proxy` binary) and `ProxyProtocolClient` library. Three-phase protocol: authentication (MlDsa65 signatures), rendezvous (temporary peer discovery codes), messaging. Default listen address: `ws://localhost:8080`.
- **bw-rat-client** — `RemoteClient` (untrusted device requesting credentials) and `UserClient` (trusted device serving credentials). Uses trait abstractions (`SessionStore`, `IdentityProvider`, `ProxyClient`) and async event/response channels.
- **bw-remote** — CLI driver with subcommands: `connect` (remote client mode), `listen` (user client mode), `clear-cache`, `list-cache`, `list-devices`, `clear-keypairs`. Integrates with `bw` CLI for credential lookup via `bw get item`.
- **bw-error / bw-error-macro** — Error handling utilities ported from Bitwarden's `sdk-internal`.

## Key Design Patterns

- **Trait-based abstractions**: `SessionStore`, `IdentityProvider`, `ProxyClient` decouple protocol logic from storage/transport implementations
- **Event-response model**: Clients communicate via `tokio::sync::mpsc` channels — clients emit events, callers send responses
- **Connection modes**: `ConnectionMode::New` (rendezvous code), `ConnectionMode::NewPsk`, `ConnectionMode::Existing` (cached session)
- **Fingerprint verification**: 6-character handshake fingerprints for out-of-band verification between peers

## Before Committing

Always run these checks before committing:

```bash
cargo fmt --all -- --check         # Verify formatting
cargo clippy --workspace           # Lint check
cargo build --workspace            # Verify it compiles
cargo test --workspace             # Run all tests
```

## Rust Conventions

- Edition 2024, minimum Rust version 1.85, toolchain channel 1.93
- Async runtime: Tokio (multi-threaded)
- Error handling: `thiserror` for library errors, `color-eyre` in the CLI binary
- All crypto memory uses `zeroize` for secure cleanup
