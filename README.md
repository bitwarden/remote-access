# Bitwarden Remote Access

Remote Access allows users to access credentials from their password manager on remote systems, without exposing their entire vault.
It creates an e2e connected tunnel between the remote and the password manager.

Remote Access is both an open protocol, CLI tool, and a Rust SDK that you can use to implement it directly into agents or custom software. While we at Bitwarden has built it, it's open for any Password Manager to leverage to further support Agentic or automation use cases without exposting your entire vault.
 
Download the binary for your system from the latest release:

* Linux
* Mac (Silicon)
* Windows

## Examples

* OpenClaw skill
* Automated script requesting an API-token.
* Github Action

## Getting started (cli, bitwarden)

Once you've installed the CLI tool, it can connect to your bitwarden vault using the bitwarden cli.

```shell
bw-remote listen
```

The interactive CLI will create a pairing code that you can use to establish a connection on the remote side

**Setting up the remote side**

You can run the remote side interactively (most useful for testing/demonstration) or to "one-shot" credential requests

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

This repo contains multiple building blocks that powers Remote Access.

It contains:

* A e2e tunnel, using Noise
* A Rust SDK for establishing a tunnel, sending requests, and responding to them
* A CLI tool for request / releasing credentials
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

Run `bw-remote` to use the demo CLI. This top-level driver command lets you explore the functionality of the SDK:

```
Connect to a user-client through a proxy to request credentials over a secure channel

Usage: bw-remote [OPTIONS] [COMMAND]

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
2. Start the user-client side with `cargo run -p bw-remote -- listen`
3. Enter the outputted PSK from step 2 into the `--pair-code` argument of `bw-remote connect` and type a client ID
4. Now `bw-remote`, taking the role of the remote client, will let you type in domains to request credentials for, and you will approve them on the `listen` side from step 2
5. Observe that the credential was sent to the remote side
