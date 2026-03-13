"""Bitwarden Remote Access Python SDK — RemoteClient (connect side)."""

from .errors import (
    AuthenticationError,
    CredentialRequestError,
    HandshakeError,
    RemoteAccessError,
    SessionNotFoundError,
    TransportError,
)
from .identity import Identity, IdentityKeyPair
from .psk import Psk
from .remote_client import RemoteClient
from .transport import MultiDeviceTransport

__all__ = [
    "RemoteAccessError",
    "AuthenticationError",
    "HandshakeError",
    "TransportError",
    "SessionNotFoundError",
    "CredentialRequestError",
    "Identity",
    "IdentityKeyPair",
    "Psk",
    "RemoteClient",
    "MultiDeviceTransport",
]
