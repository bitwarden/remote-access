# Bitwarden Remote Access

Remote Access allows users to access credentials from their password manager on remote systems, without exposing their entire vault.
It creates an end-to-end encrypted tunnel between the remote system and the password manager.

Remote Access is an open protocol, CLI tool, and Rust SDK that you can use to implement it directly into agents or custom software. While we at Bitwarden have built it, it's open for any password manager to leverage to further support agentic or automation use cases without exposing your entire vault.

## Installation

### macOS (Apple Silicon)

```shell
curl -L https://github.com/bitwarden/remote-access/releases/latest/download/bw-remote-aarch64-apple-darwin.tar.gz | tar xz
sudo mv bw-remote /usr/local/bin/
```

### macOS (Intel)

```shell
curl -L https://github.com/bitwarden/remote-access/releases/latest/download/bw-remote-x86_64-apple-darwin.tar.gz | tar xz
sudo mv bw-remote /usr/local/bin/
```

### Linux (x86_64)

```shell
curl -L https://github.com/bitwarden/remote-access/releases/latest/download/bw-remote-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv bw-remote /usr/local/bin/
```

### Windows (x86_64)

Download [bw-remote-x86_64-pc-windows-msvc.zip](https://github.com/bitwarden/remote-access/releases/latest/download/bw-remote-x86_64-pc-windows-msvc.zip) from the [latest release](https://github.com/bitwarden/remote-access/releases/latest) and extract it to a directory on your PATH.

## Examples

* OpenClaw skill
* Automated script requesting an API-token.
* Github Action

## Getting started (cli, bitwarden)

Once you've installed the CLI tool, it can connect to your Bitwarden vault using the Bitwarden CLI.

```shell
bw-remote listen
```

The interactive CLI will create a pairing code that you can use to establish a connection on the remote side.

**Setting up the remote side**

You can run the remote side interactively (most useful for testing/demonstration) or in "one-shot" mode for single credential requests.

```shell
# interactive mode
bw-remote connect
```

```shell
# one time pairing
bw-remote connect --token <rendevouz-code> --output json

# one shot mode
bw-remote connect --session <sessionId> --domain example.com --output json
bw-remote connect --session <sessionId> --domain github.com --output json

```

## Contributing

This repo contains multiple building blocks that power Remote Access.

It contains:

* An end-to-end encrypted tunnel, using Noise
* A Rust SDK for establishing a tunnel, sending requests, and responding to them
* A CLI tool for requesting / releasing credentials
* A proxy server for demo/development purposes


## Crate Structure

* `bw-error` - Error handling utilities for bw_remote. Re-exports the `bw_error` proc macro and provides the `FlatError` trait.
* `bw-error-macro` - Proc macro for generating error types with `FlatError` trait implementation. Simplified version of `bitwarden-error-macro` that only supports the `flat` error type for CLI use.
* `bw-noise-protocol` - Multi-device Noise-based Protocol implementation using the NNpsk2 pattern for secure channel establishment with PSK-based authentication. 
* `bw-proxy` - Zero-knowledge WebSocket proxy server enabling secure rendezvous between remote and user clients. Runs as a standalone binary with environment-based configuration.
* `bw-rat-client` - Remote and user client implementations for connecting through the proxy using the Noise Protocol.
* `bw-remote` - CLI interface for connecting to a user-client through a proxy to request credentials over a secure Noise Protocol channel. Manages session caching and device keypair storage.

## Building

Run `cargo build` in this directory. This is a standalone workspace and has no dependencies on any other Bitwarden components. Requires Rust 1.85+.

## Running

### Proxy Server

Run the `bw-proxy` binary to start the WebSocket proxy server:

```
cargo run -p bw-proxy
```

The proxy binds to `127.0.0.1:8080` by default. Set the `BIND_ADDR` environment variable to override.

### CLI

Run `aac` to use the demo CLI. This top-level driver command lets you explore the functionality of the SDK:

```
Connect to a user-client through a proxy to request credentials over a secure channel

Usage: aac [OPTIONS] [COMMAND]

Commands:
  cache    Manage the session cache
  connect  Connect to proxy and request credentials (default)
  listen   Listen for remote client connections (user-client mode)
  help         Print this message or the help of the given subcommand(s)

Options:
      --proxy-url <PROXY_URL>  Proxy server URL [default: ws://localhost:8080]
      --token <TOKEN>          Token (rendezvous code or PSK token)
      --session <SESSION>      Session fingerprint to reconnect to (hex string)
      --no-cache               Disable session caching
      --debug-log              Enable debug logging for the multi-device Noise protocol
  -h, --help                   Print help
  -V, --version                Print version
```

### Demo Flow

1. Start the proxy server with `cargo run -p bw-proxy`
2. Start the user-client side with `cargo run --bin aac -- listen`
3. Enter the outputted PSK from step 2 into the `--pair-code` argument of `aac connect` and type a client ID
4. Now `aac`, taking the role of the remote client, will let you type in domains to request credentials for, and you will approve them on the `listen` side from step 2
5. Observe that the credential was sent to the remote side
