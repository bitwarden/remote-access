#!/usr/bin/env python3
"""Interactive test script for UniFFI Python bindings.

Usage:
    python test.py --token <PSK_TOKEN> --domain github.com
    python test.py --domain github.com              # uses cached session
"""

import argparse
import sys
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))

from bw_remote_uniffi import RemoteAccessClient, RemoteAccessError

PROXY = "wss://rat1.lesspassword.dev"
IDENTITY = "test-python-uniffi"


def main():
    parser = argparse.ArgumentParser(description="Test UniFFI Python bindings")
    parser.add_argument("--token", help="PSK token or rendezvous code")
    parser.add_argument("--domain", default="github.com", help="Domain to request")
    parser.add_argument("--proxy", default=PROXY, help="Proxy URL")
    parser.add_argument(
        "--identity", default=IDENTITY,
        help="Identity keypair name — stored at ~/.bw-remote/<name>.key",
    )
    args = parser.parse_args()

    client = RemoteAccessClient(args.proxy, args.identity)
    try:
        fp = client.connect(token=args.token, session=None)
        print(f"Connected (fingerprint={fp}, ready={client.is_ready()})")

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
