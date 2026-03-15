#!/usr/bin/env python3
"""Example: connect to a listening peer and request a credential using UniFFI bindings.

Usage:
    # With rendezvous code:
    python connect_request.py --token ABC-DEF-GHI --domain example.com

    # With PSK token:
    python connect_request.py --token <64hex_psk>_<64hex_fingerprint> --domain example.com

    # With cached session (auto-select if only one):
    python connect_request.py --domain example.com

    # With specific cached session:
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

from bw_remote_uniffi import RemoteAccessClient, connect_and_request


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Request a credential via Bitwarden Remote Access (UniFFI bindings)"
    )
    parser.add_argument("--proxy", default="ws://localhost:8080", help="Proxy server URL")
    parser.add_argument("--token", help="Rendezvous code or PSK token")
    parser.add_argument("--session", help="Cached session fingerprint (hex)")
    parser.add_argument("--domain", required=True, help="Domain to request credentials for")
    parser.add_argument("--identity", default="uniffi-remote", help="Identity name")
    parser.add_argument(
        "--one-shot",
        action="store_true",
        help="Use the connect_and_request convenience function",
    )
    args = parser.parse_args()

    try:
        if args.one_shot:
            cred = connect_and_request(
                domain=args.domain,
                token=args.token,
                session=args.session,
                proxy_url=args.proxy,
                identity_name=args.identity,
            )
        else:
            client = RemoteAccessClient(
                proxy_url=args.proxy,
                identity_name=args.identity,
            )

            fingerprint = client.connect(token=args.token, session=args.session)
            if fingerprint:
                print(f"Handshake fingerprint: {fingerprint}", file=sys.stderr)

            print(f"Ready: {client.is_ready()}", file=sys.stderr)

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
