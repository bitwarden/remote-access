# UniFFI Python Bindings Example

Python example using the UniFFI-generated bindings for the Bitwarden Remote Access SDK.

## Setup

### 1. Build the native library

```bash
cargo build -p bw-remote-uniffi
```

### 2. Generate Python bindings

```bash
cargo run --bin uniffi-bindgen generate \
  --library target/debug/libbw_remote_uniffi.dylib \
  --language python --out-dir examples/uniffi/
```

This produces `bw_remote_uniffi.py` in this directory.

### 3. Symlink the native library

The generated module loads the `.dylib`/`.so` from the same directory:

```bash
# macOS
ln -sf ../../target/debug/libbw_remote_uniffi.dylib examples/uniffi/

# Linux
ln -sf ../../target/debug/libbw_remote_uniffi.so examples/uniffi/
```

## Usage

Start a proxy and a listener first (see the main project README), then:

```bash
# Connect with a PSK token
python3 test.py --token <PSK_TOKEN> --domain github.com

# Reuse a cached session
python3 test.py --domain github.com

# Full options
python3 connect_request.py \
  --proxy wss://your-proxy.example.com \
  --token <PSK_TOKEN> \
  --domain example.com \
  --identity my-keypair-name
```

### Token formats

| Format | Example | Mode |
|--------|---------|------|
| Rendezvous code | `ABC-DEF-GHI` | Discovers peer via proxy |
| PSK token | `<64hex>_<64hex>` | Pre-shared key (no rendezvous) |
| _(omitted)_ | | Uses cached session |

### Identity keypair

The `--identity` flag controls which keypair file is used at `~/.bw-remote/<name>.key`. Each identity name gets its own keypair and session cache. Default: `uniffi-remote`.

## Generating bindings for other languages

The same native library supports Kotlin, Swift, and Ruby:

```bash
# Kotlin
cargo run --bin uniffi-bindgen generate \
  --library target/debug/libbw_remote_uniffi.dylib \
  --language kotlin --out-dir bindings/kotlin/

# Swift
cargo run --bin uniffi-bindgen generate \
  --library target/debug/libbw_remote_uniffi.dylib \
  --language swift --out-dir bindings/swift/

# Ruby
cargo run --bin uniffi-bindgen generate \
  --library target/debug/libbw_remote_uniffi.dylib \
  --language ruby --out-dir bindings/ruby/
```

## Files

| File | Description |
|------|-------------|
| `test.py` | Quick test script with CLI args |
| `connect_request.py` | Full example with all connection modes |
| `bw_remote_uniffi.py` | _(generated)_ Python bindings — do not edit |
| `libbw_remote_uniffi.dylib` | _(symlink)_ Native library — do not commit |
