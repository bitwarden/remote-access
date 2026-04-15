# ap-uniffi

UniFFI bindings for the Access Protocol client library. Generates native bindings for Python, Swift, and Kotlin from the Rust `ap-client` crate.

## Exported types

| Type | Role |
|------|------|
| `RemoteClient` | Untrusted device requesting credentials |
| `UserClient` | Trusted device serving credentials |
| `ClientError` | Categorized error enum (6 variants) |

Consumers implement callback interfaces for storage and credential handling:

- **`IdentityStorage`** — persist identity keypair bytes
- **`ConnectionStorage`** — persist cached connection state
- **`CredentialProvider`** — handle incoming credential requests (`UserClient` only)
- **`FingerprintVerifier`** — verify handshake fingerprints on rendezvous pairing (`UserClient` only)
- **`EventHandler`** — receive protocol lifecycle events

## Building

```bash
# Build the cdylib
cargo build -p ap-uniffi

# Generate bindings
cargo run --bin uniffi-bindgen generate \
    --library target/debug/libap_uniffi.dylib \
    --language python --out-dir examples/python-uniffi/

cargo run --bin uniffi-bindgen generate \
    --library target/debug/libap_uniffi.dylib \
    --language swift --out-dir examples/swift-uniffi/Sources/ApUniffi/
```

## Examples

- [`examples/python-uniffi/`](../../examples/python-uniffi/) — Python async example
- [`examples/swift-uniffi/`](../../examples/swift-uniffi/) — Swift example with SPM
