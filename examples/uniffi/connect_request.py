#!/usr/bin/env python3
"""Example: connect to a listening peer and request a credential using UniFFI bindings.

Usage:
    # With rendezvous code:
    python connect_request.py --token ABC-DEF-GHI --domain example.com

    # With PSK token:
    python connect_request.py --token <64hex_psk>_<64hex_fingerprint> --domain example.com

    # With cached session:
    python connect_request.py --session <fingerprint_hex> --domain example.com

Setup:
    # Build the cdylib
    cargo build -p bw-remote-uniffi

    # Generate Python bindings into this directory
    cargo run --bin uniffi-bindgen generate \
        --library target/debug/libbw_remote_uniffi.dylib \
        --language python --out-dir examples/uniffi/

    # Then run this script from the repo root
    python examples/uniffi/connect_request.py --token ABC-DEF-GHI --domain example.com
"""

import argparse
import sys

from bw_remote_uniffi import (
    RemoteAccessClient,
    list_connections,
    looks_like_psk_token,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Request a credential via Agent Access (UniFFI bindings)"
    )
    parser.add_argument("--proxy", default="ws://localhost:8080", help="Proxy server URL")
    parser.add_argument("--token", help="Rendezvous code or PSK token")
    parser.add_argument("--session", help="Cached session fingerprint (hex)")
    parser.add_argument("--domain", required=True, help="Domain to request credentials for")
    parser.add_argument("--identity", default="uniffi-remote", help="Identity name")
    args = parser.parse_args()

    try:
        client = RemoteAccessClient(
            proxy_url=args.proxy,
            identity_name=args.identity,
            event_handler=None,
        )

        # Step 1: Connect to the proxy
        client.connect()

        # Step 2: Establish a secure channel (consumer decides which mode)
        if args.token:
            if looks_like_psk_token(args.token):
                client.pair_with_psk(args.token)
            else:
                fp = client.pair_with_handshake(args.token)
                print(f"Handshake fingerprint: {fp}", file=sys.stderr)
        elif args.session:
            client.load_existing_connection(args.session)
        else:
            # Auto-select if exactly one cached session exists
            connections = list_connections(args.identity)
            if len(connections) == 1:
                client.load_existing_connection(connections[0].fingerprint)
            elif len(connections) == 0:
                print("No cached sessions. Provide --token to start a new connection.", file=sys.stderr)
                return 1
            else:
                print(f"Multiple cached sessions ({len(connections)}). Use --session to specify one:", file=sys.stderr)
                for c in connections:
                    name = c.name or "unnamed"
                    print(f"  {c.fingerprint[:16]}... ({name})", file=sys.stderr)
                return 1

        # Step 3: Request credential
        cred = client.request_credential(args.domain)
        client.close()

        if cred.username:
            print(f"Username: {cred.username}")
        if cred.password:
            print(f"Password: {cred.password}")
        if cred.totp:
            print(f"TOTP: {cred.totp}")
        if cred.uri:
            print(f"URI: {cred.uri}")
        if cred.notes:
            print(f"Notes: {cred.notes}")

        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
