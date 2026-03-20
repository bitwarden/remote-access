#!/usr/bin/env python3
"""Pair with a listening peer and cache the session.

Clears any existing cached session first — only one session is kept at a time.

Usage:
    # With rendezvous code:
    python3 pair.py --token ABC-DEF-GHI

    # With PSK token:
    python3 pair.py --token <64hex_psk>_<64hex_fingerprint>
"""

import argparse
import sys

from bw_remote_rs import RemoteClient


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pair with a remote peer via Bitwarden Remote Access (Rust backend)"
    )
    parser.add_argument("--proxy", default="wss://ap.lesspassword.dev", help="Proxy server URL")
    parser.add_argument("--token", required=True, help="Rendezvous code or PSK token")
    parser.add_argument(
        "--identity", default="python-remote",
        help="Identity keypair name — stored at ~/.bw-remote/<name>.key",
    )
    args = parser.parse_args()

    client = RemoteClient(proxy_url=args.proxy, identity_name=args.identity)

    try:
        # Clear any existing session so we only keep one
        client.clear_sessions()

        fingerprint = client.connect(token=args.token)
        if fingerprint:
            print(f"Handshake fingerprint: {fingerprint}", file=sys.stderr)

        print("Paired successfully.", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
