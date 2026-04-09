#!/usr/bin/env python3
"""Interactive test script for UniFFI Python bindings.

Usage:
    python test.py --token <PSK_TOKEN> --domain github.com
    python test.py --domain github.com              # uses cached session
"""

import argparse
import sys
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))

from bw_remote_uniffi import (
    RemoteAccessClient,
    RemoteAccessError,
    list_connections,
    looks_like_psk_token,
)

PROXY = "wss://ap.lesspassword.dev"
IDENTITY = "test-python-uniffi"


def main():
    parser = argparse.ArgumentParser(description="Test UniFFI Python bindings")
    parser.add_argument("--token", help="PSK token or rendezvous code")
    parser.add_argument("--session", help="Cached session fingerprint (hex)")
    parser.add_argument("--domain", default="github.com", help="Domain to request")
    parser.add_argument("--proxy", default=PROXY, help="Proxy URL")
    parser.add_argument(
        "--identity", default=IDENTITY,
        help="Identity keypair name — stored at ~/.bw-remote/<name>.key",
    )
    args = parser.parse_args()

    client = RemoteAccessClient(args.proxy, args.identity, event_handler=None)
    try:
        client.connect()

        if args.token:
            if looks_like_psk_token(args.token):
                client.pair_with_psk(args.token)
                print("Paired with PSK")
            else:
                fp = client.pair_with_handshake(args.token)
                print(f"Paired with rendezvous (fingerprint={fp})")
        elif args.session:
            client.load_existing_connection(args.session)
            print("Loaded cached connection")
        else:
            connections = list_connections(args.identity)
            if len(connections) == 1:
                client.load_existing_connection(connections[0].fingerprint)
                print(f"Auto-selected cached session: {connections[0].fingerprint[:16]}...")
            else:
                print(f"No token and {len(connections)} cached sessions — provide --token or --session")
                return 1

        print(f"Requesting '{args.domain}' — approve on listener...")
        cred = client.request_credential(args.domain)

        print(f"\n  Username: {cred.username}")
        print(f"  Password: {cred.password}")
        print(f"  TOTP:     {cred.totp}")
        print(f"  URI:      {cred.uri}")
        print(f"  Notes:    {cred.notes}")
    except (
        RemoteAccessError.ConnectionFailed,
        RemoteAccessError.HandshakeFailed,
        RemoteAccessError.CredentialRequestFailed,
        RemoteAccessError.SessionError,
        RemoteAccessError.InvalidArgument,
        RemoteAccessError.Timeout,
    ) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
