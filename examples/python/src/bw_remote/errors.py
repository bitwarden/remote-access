"""Exception hierarchy for the Bitwarden Remote Access SDK."""


class RemoteAccessError(Exception):
    """Base exception for all remote access errors."""


class AuthenticationError(RemoteAccessError):
    """Raised when proxy authentication fails."""


class HandshakeError(RemoteAccessError):
    """Raised when the Noise protocol handshake fails."""


class TransportError(RemoteAccessError):
    """Raised when transport encryption/decryption fails."""


class SessionNotFoundError(RemoteAccessError):
    """Raised when a cached session is not found."""


class CredentialRequestError(RemoteAccessError):
    """Raised when a credential request fails."""
