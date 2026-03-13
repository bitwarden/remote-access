"""Protocol message types sent inside proxy Send payloads.

Reference: crates/bw-rat-client/src/types.rs

These are JSON messages exchanged over the encrypted Noise channel.
The outer proxy protocol wraps them as raw bytes in Send.payload.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass, field


@dataclass
class CredentialData:
    """Credential data returned from a request."""

    username: str | None = None
    password: str | None = None
    totp: str | None = None
    uri: str | None = None
    notes: str | None = None


def make_handshake_init(data_b64: str, ciphersuite: str) -> str:
    """Create a handshake-init ProtocolMessage JSON string."""
    return json.dumps({
        "type": "handshake-init",
        "data": data_b64,
        "ciphersuite": ciphersuite,
    })


def make_credential_request(encrypted_b64: str) -> str:
    """Create a credential-request ProtocolMessage JSON string."""
    return json.dumps({
        "type": "credential-request",
        "encrypted": encrypted_b64,
    })


def make_credential_request_payload(domain: str) -> tuple[str, str]:
    """Create a credential request payload (to be encrypted).

    Returns (json_str, request_id).
    """
    request_id = f"req-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
    payload = {
        "type": "credential_request",
        "domain": domain,
        "timestamp": int(time.time() * 1000),
        "requestId": request_id,
    }
    return json.dumps(payload), request_id


def parse_protocol_message(data: str) -> dict:
    """Parse a ProtocolMessage JSON string."""
    return json.loads(data)


def parse_credential_response_payload(data: bytes) -> tuple[CredentialData | None, str | None, str | None]:
    """Parse a decrypted credential response payload.

    Returns (credential, error, request_id).
    """
    obj = json.loads(data)
    cred = None
    if "credential" in obj and obj["credential"] is not None:
        c = obj["credential"]
        cred = CredentialData(
            username=c.get("username"),
            password=c.get("password"),
            totp=c.get("totp"),
            uri=c.get("uri"),
            notes=c.get("notes"),
        )
    return cred, obj.get("error"), obj.get("requestId")
