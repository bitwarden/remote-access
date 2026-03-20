#!/usr/bin/env python3
"""Request a credential using the cached session.

Requires a prior pairing via pair.py.

Usage:
    python3 get.py --domain example.com
"""

import argparse
import sys

from bw_remote_rs import RemoteClient


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Request a credential via Bitwarden Remote Access (Rust backend)"
    )
    parser.add_argument("--proxy", default="wss://ap.lesspassword.dev", help="Proxy server URL")
    parser.add_argument("--domain", required=True, help="Domain to request credentials for")
    parser.add_argument(
        "--identity", default="python-remote",
        help="Identity keypair name — stored at ~/.bw-remote/<name>.key",
    )
    args = parser.parse_args()

    client = RemoteClient(proxy_url=args.proxy, identity_name=args.identity)

    try:
        # Connect using the single cached session
        client.connect()

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
