# How to Contribute

Our [Contributing Guidelines](https://contributing.bitwarden.com/contributing/) are located in our [Contributing Documentation](https://contributing.bitwarden.com/). The documentation also includes recommended tooling, code style tips, and lots of other great information to get you started.

## Overview

This repo contains multiple building blocks that power Remote Access.

It contains:

* An end-to-end encrypted tunnel, using Noise
* A Rust SDK for establishing a tunnel, sending requests, and responding to them
* A CLI tool for requesting / releasing credentials
* A proxy server for demo/development purposes

## Crate Structure

* `ap-error` - Error handling utilities for access-protocol. Re-exports the `ap_error` proc macro and provides the `FlatError` trait.
* `ap-error-macro` - Proc macro for generating error types with `FlatError` trait implementation. Simplified version of `bitwarden-error-macro` that only supports the `flat` error type for CLI use.
* `ap-noise` - Multi-device Noise-based Protocol implementation using the NNpsk2 pattern for secure channel establishment with PSK-based authentication.
* `ap-proxy` - Zero-knowledge WebSocket proxy server enabling secure rendezvous between remote and user clients. Runs as a standalone binary with environment-based configuration.
* `ap-client` - Remote and user client implementations for connecting through the proxy using the Noise Protocol.
* `ap-cli` - CLI interface for connecting to a user-client through a proxy to request credentials over a secure Noise Protocol channel. Manages session caching and device keypair storage.

## Building

Run `cargo build` in this directory. This is a standalone workspace and has no dependencies on any other Bitwarden components. Requires Rust 1.85+.

## Running

### Proxy Server

Run the `ap-proxy` binary to start the WebSocket proxy server:

```shell
cargo run -p ap-proxy
```

The proxy binds to `127.0.0.1:8080` by default. Set the `BIND_ADDR` environment variable to override.

### CLI

Run `aac` to use the demo CLI. This top-level driver command lets you explore the functionality of the SDK:

```shell
Retrieve credentials from your password manager over a secure channel

Usage: aac [OPTIONS] [COMMAND]

Commands:
  connect      Connect to proxy and request credentials
  listen       Listen for remote client connections (user-client mode)
  connections  Manage connections
  help         Print this message or the help of the given subcommand(s)

Options:
      --proxy-url <PROXY_URL>  Proxy server URL [default: wss://rat1.lesspassword.dev]
      --token <TOKEN>          Token (rendezvous code or PSK token)
      --session <SESSION>      Session fingerprint to reconnect to (hex string)
      --no-cache               Disable session caching
      --debug-log              Enable debug logging for the multi-device Noise protocol
  -h, --help                   Print help
  -V, --version                Print version
```

### Demo Flow

1. Start the proxy server with `cargo run -p ap-proxy`
2. Start the user-client side with `cargo run --bin aac -- listen`
3. Enter the pairing token from step 2 into the `--token` argument of `aac connect`
4. Now `aac`, taking the role of the remote client, will let you type in domains to request credentials for, and you will approve them on the `listen` side from step 2
5. Observe that the credential was sent to the remote side
