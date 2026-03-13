#!/usr/bin/env python3
"""Example: connect to a listening peer and request a credential.

Usage:
    # With rendezvous code:
    python examples/connect_request.py --token ABC-DEF-GHI --domain example.com

    # With PSK token:
    python examples/connect_request.py --token <64hex_psk>_<64hex_fingerprint> --domain example.com

    # With cached session (auto-select if only one):
    python examples/connect_request.py --domain example.com

    # With specific cached session:
    python examples/connect_request.py --session <fingerprint_hex> --domain example.com
"""

import argparse
import asyncio
import logging
import sys

from bw_remote import RemoteClient


async def main() -> int:
    parser = argparse.ArgumentParser(description="Request a credential via Bitwarden Remote Access")
    parser.add_argument("--proxy", default="ws://localhost:8080", help="Proxy server URL")
    parser.add_argument("--token", help="Rendezvous code or PSK token")
    parser.add_argument("--session", help="Cached session fingerprint (hex)")
    parser.add_argument("--domain", required=True, help="Domain to request credentials for")
    parser.add_argument("--identity", default="python-remote", help="Identity name")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    client = RemoteClient(proxy_url=args.proxy, identity_name=args.identity)

    try:
        fingerprint = await client.connect(token=args.token, session=args.session)
        if fingerprint:
            print(f"Handshake fingerprint: {fingerprint}", file=sys.stderr)

        cred = await client.request_credential(args.domain)

        # Output credential to stdout
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
        await client.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
