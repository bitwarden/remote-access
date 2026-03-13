#!/usr/bin/env python3
"""Example: connect to a listening peer and request a credential.

Usage:
    # With rendezvous code:
    python connect_request.py --token ABC-DEF-GHI --domain example.com

    # With PSK token:
    python connect_request.py --token <64hex_psk>_<64hex_fingerprint> --domain example.com

    # With cached session (auto-select if only one):
    python connect_request.py --domain example.com

    # With specific cached session:
    python connect_request.py --session <fingerprint_hex> --domain example.com
"""

import argparse
import sys

from bw_remote_rs import RemoteClient


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Request a credential via Bitwarden Remote Access (Rust backend)"
    )
    parser.add_argument("--proxy", default="ws://localhost:8080", help="Proxy server URL")
    parser.add_argument("--token", help="Rendezvous code or PSK token")
    parser.add_argument("--session", help="Cached session fingerprint (hex)")
    parser.add_argument("--domain", required=True, help="Domain to request credentials for")
    parser.add_argument("--identity", default="python-remote", help="Identity name")
    args = parser.parse_args()

    client = RemoteClient(proxy_url=args.proxy, identity_name=args.identity)

    try:
        fingerprint = client.connect(token=args.token, session=args.session)
        if fingerprint:
            print(f"Handshake fingerprint: {fingerprint}", file=sys.stderr)

        cred = client.request_credential(args.domain)

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
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
