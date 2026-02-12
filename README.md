# Bitwarden Remote SDK

## Crate Structure
* `bw-error`, `bw-error-macro` - simplified ports of error functionality from `sdk-internal`
* `bw-noise` - implementation of the NOISE handshake via `snow` plus associated types
* `bw-noise-client` - implements the remote client side protocol logic
* `bw-remote` - CLI driver to use all of these and demonstrate integration for both sides of the protocol, also manages session caching for the same

## Building
Run `cargo build` in this directory, `bw_remote`. This is a standalone effort and has no dependencies on any other Bitwarden components.

## Running

### Overview
Run `target/[config]bw-remote` to run the demo CLI. This top-level driver command lets you explore the functionality of the SDK:

```
$ target/debug/bw-remote --help
Connect to a user-client through a proxy to request credentials over a secure channel

Usage: bw-remote [OPTIONS] [COMMAND]

Commands:
  clear-cache     Clear all cached sessions
  list-cache      List cached sessions
  list-devices    List stored device keypairs
  clear-keypairs  Clear all device keypairs
  connect         Connect to proxy and request credentials (default)
  listen          Listen for remote client connections (user-client mode)
  help            Print this message or the help of the given subcommand(s)

Options:
      --proxy-url <PROXY_URL>  Proxy server URL [default: ws://localhost:8080]
      --pair-code <PAIR_CODE>  Pairing code (format: password:metadata)
      --client-id <CLIENT_ID>  Client ID for this device
      --no-cache               Disable session caching
  -h, --help                   Print help
  -V, --version                Print version
```

### Demo flow
1. Ensure that the websocket proxy server is running (`npm run proxy` in `skunkworks/noise`)
2. Ensure that you have unlocked your demo vault using the `bw` CLI and set the session key environment variable
3. Start the user-client side with `bw-remote listen`
4. Enter the outputted PSK from step 2 into the `--pair-code` argument of `bw-remote connect` and type a client ID
5. Now `bw-remote`, taking the role of the remote client, will let you type in domains to request credentials for, and you will approve them on the `listen` side from Step 2
6. Observe that the credential was sent to the remote side
