#!/usr/bin/env python3
"""Example: connect to a listening peer and request a credential using UniFFI bindings.

Usage:
    # With rendezvous code:
    python connect_request.py --token ABC-DEF-GHI --domain example.com

    # With PSK token:
    python connect_request.py --token <64hex_psk>_<64hex_fingerprint> --domain example.com

Setup:
    # Build the cdylib
    cargo build -p ap-uniffi

    # Generate Python bindings into this directory
    cargo run --bin uniffi-bindgen generate \
        --library target/debug/libap_uniffi.dylib \
        --language python --out-dir examples/python-uniffi/

    # Then run this script from the repo root
    python examples/python-uniffi/connect_request.py --token ABC-DEF-GHI --domain example.com
"""

import argparse
import asyncio
import sys

from ap_uniffi import (
    RemoteAccessClient,
    looks_like_psk_token,
)
from storage import MemoryConnectionStorage, MemoryIdentityStorage


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Request a credential via Agent Access (UniFFI bindings)"
    )
    parser.add_argument("--proxy", default="wss://ap.lesspassword.dev", help="Proxy server URL")
    parser.add_argument("--token", required=True, help="Rendezvous code or PSK token")
    parser.add_argument("--domain", required=True, help="Domain to request credentials for")
    args = parser.parse_args()

    try:
        client = RemoteAccessClient(
            proxy_url=args.proxy,
            identity_storage=MemoryIdentityStorage(),
            connection_storage=MemoryConnectionStorage(),
            event_handler=None,
        )

        await client.connect()

        if looks_like_psk_token(args.token):
            await client.pair_with_psk(args.token)
        else:
            fp = await client.pair_with_handshake(args.token)
            print(f"Handshake fingerprint: {fp}", file=sys.stderr)

        cred = await client.request_credential(args.domain)
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
    sys.exit(asyncio.run(main()))
