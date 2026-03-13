"""Pre-Shared Key (PSK) type for Noise protocol authentication.

Reference: crates/bw-noise-protocol/src/psk.rs
"""

from __future__ import annotations

import os

PSK_LENGTH = 32


class Psk:
    """A 32-byte pre-shared key for Noise NNpsk2 authentication."""

    __slots__ = ("_bytes",)

    def __init__(self, data: bytes) -> None:
        if len(data) != PSK_LENGTH:
            raise ValueError(f"PSK must be exactly {PSK_LENGTH} bytes, got {len(data)}")
        self._bytes = bytes(data)

    @classmethod
    def generate(cls) -> Psk:
        return cls(os.urandom(PSK_LENGTH))

    @classmethod
    def null(cls) -> Psk:
        return cls(b"\x00" * PSK_LENGTH)

    @classmethod
    def from_hex(cls, hex_str: str) -> Psk:
        data = bytes.fromhex(hex_str)
        return cls(data)

    def to_hex(self) -> str:
        return self._bytes.hex()

    def to_bytes(self) -> bytes:
        return self._bytes

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Psk):
            return self._bytes == other._bytes
        return NotImplemented

    def __repr__(self) -> str:
        import hashlib

        h = hashlib.sha256(self._bytes).hexdigest()[:8]
        return f"Psk({h}...)"
