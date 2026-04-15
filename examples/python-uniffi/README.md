# UniFFI Python Bindings Example

Python example using the UniFFI-generated bindings for the Bitwarden Remote Access SDK.

## Setup

### 1. Build the native library

```bash
cargo build -p ap-uniffi
```

### 2. Generate Python bindings

```bash
cargo run --bin uniffi-bindgen generate --library target/debug/libap_uniffi.dylib --language python --out-dir examples/python-uniffi/
```

This produces `ap_uniffi.py` in this directory.

### 3. Symlink the native library

The generated module loads the `.dylib`/`.so` from the same directory:

```bash
# macOS
ln -sf ../../target/debug/libap_uniffi.dylib examples/python-uniffi/

# Linux
ln -sf ../../target/debug/libap_uniffi.so examples/python-uniffi/
```

## Usage

Start a proxy and a listener first (see the main project README), then:

```bash
# Connect with a PSK token
python3 connect_request.py --token <PSK_TOKEN> --domain github.com

# Connect with a rendezvous code
python3 connect_request.py --token ABC-DEF-GHI --domain example.com

# Custom proxy
python3 connect_request.py --proxy wss://your-proxy.example.com --token <PSK_TOKEN> --domain example.com
```

### Token formats

| Format | Example | Mode |
|--------|---------|------|
| Rendezvous code | `ABC-DEF-GHI` | Discovers peer via proxy |
| PSK token | `<64hex>_<64hex>` | Pre-shared key (no rendezvous) |

### Storage

These examples use in-memory storage (`storage.py`) — identity and connections are ephemeral. Real applications should implement `IdentityStorage` and `ConnectionStorage` with persistent backends (file, keychain, database).

## Generating bindings for other languages

The same native library supports Kotlin, Swift, and Ruby:

```bash
# Kotlin
cargo run --bin uniffi-bindgen generate --library target/debug/libap_uniffi.dylib --language kotlin --out-dir bindings/kotlin/

# Swift
cargo run --bin uniffi-bindgen generate --library target/debug/libap_uniffi.dylib --language swift --out-dir bindings/swift/

# Ruby
cargo run --bin uniffi-bindgen generate --library target/debug/libap_uniffi.dylib --language ruby --out-dir bindings/ruby/
```

## Files

| File | Description |
|------|-------------|
| `connect_request.py` | Connect + request credential example |
| `storage.py` | In-memory storage implementations (shared by examples) |
| `ap_uniffi.py` | _(generated)_ Python bindings — do not edit |
| `libap_uniffi.dylib` | _(symlink)_ Native library — do not commit |
