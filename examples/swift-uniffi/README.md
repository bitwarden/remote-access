# Swift UniFFI Example

Swift example using UniFFI-generated bindings for the Agent Access SDK.

## Prerequisites

- Rust toolchain
- Swift 5.9+ (Xcode 15+ or swift.org toolchain)

## Setup

### 1. Build the native library

```bash
cargo build -p ap-uniffi
```

### 2. Generate Swift bindings

```bash
cargo run --bin uniffi-bindgen generate --library target/debug/libap_uniffi.dylib --language swift --out-dir examples/swift-uniffi/generated/
```

### 3. Copy generated files into the package

```bash
cp examples/swift-uniffi/generated/ap_uniffi.swift examples/swift-uniffi/Sources/ApUniffi/
cp examples/swift-uniffi/generated/ap_uniffiFFI.h examples/swift-uniffi/Sources/CApUniffi/include/
```

### 4. Build and run

```bash
cd examples/swift-uniffi
DYLD_LIBRARY_PATH=../../target/debug swift run ApUniffiExample --token <PSK_TOKEN_OR_RENDEZVOUS_CODE> --domain example.com
```

## Usage

Start a proxy and a listener first (see the main project README), then:

```bash
# With PSK token
DYLD_LIBRARY_PATH=../../target/debug swift run ApUniffiExample --token <64hex_psk>_<64hex_fingerprint> --domain github.com

# With rendezvous code
DYLD_LIBRARY_PATH=../../target/debug swift run ApUniffiExample --token ABC-DEF-GHI --domain example.com

# Custom proxy
DYLD_LIBRARY_PATH=../../target/debug swift run ApUniffiExample --proxy wss://your-proxy.example.com --token <TOKEN> --domain example.com
```

## Storage

This example uses in-memory storage (`Storage.swift`) — identity and connections are ephemeral. Real applications should implement `IdentityStorage` and `ConnectionStorage` with persistent backends (Keychain, Core Data, file, etc.).

## Files

| File | Description |
|------|-------------|
| `Sources/ApUniffiExample/main.swift` | CLI connect + request credential |
| `Sources/ApUniffiExample/Storage.swift` | In-memory storage implementations |
| `Sources/ApUniffi/ap_uniffi.swift` | _(generated)_ Swift bindings — regenerate, don't edit |
| `Sources/CApUniffi/include/ap_uniffiFFI.h` | _(generated)_ C FFI header — regenerate, don't edit |
| `Package.swift` | Swift Package Manager configuration |
