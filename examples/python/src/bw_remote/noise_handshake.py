"""NNpsk2 initiator handshake via dissononce.

Reference: crates/bw-noise-protocol/src/handshake.rs

Uses Noise_NNpsk2_25519_ChaChaPoly_SHA256 pattern.
The handshake uses ChaChaPoly (not XChaCha20Poly1305) — the transport layer
switches to XChaCha20Poly1305 with random nonces after the handshake completes.

dissononce implements the base ChaChaPoly cipher for the handshake, and we use
PyNaCl (libsodium) for the XChaCha20Poly1305 transport afterwards.
"""

from __future__ import annotations

import hashlib

from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.sha256 import SHA256Hash
from dissononce.processing.handshakepatterns.interactive.NN import NNHandshakePattern
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.modifiers.psk import PSKPatternModifier

from .errors import HandshakeError
from .packet import (
    CLASSICAL_CIPHERSUITE_STR,
    CiphersuiteId,
    HandshakePacket,
    MessageType,
)
from .psk import Psk


class InitiatorHandshake:
    """NNpsk2 initiator handshake (message 1: I→R, message 2: R→I)."""

    def __init__(self, psk: Psk | None = None) -> None:
        self._psk = psk or Psk.null()
        self._ciphersuite = CiphersuiteId.CLASSICAL

        # Build NNpsk2 pattern: NN with PSK at position 2
        pattern = PSKPatternModifier(2).modify(NNHandshakePattern())

        self._hs = HandshakeState(
            X25519DH(),
            ChaChaPolyCipher(),
            SHA256Hash(),
        )
        self._hs.initialize(
            handshake_pattern=pattern,
            initiator=True,
            prologue=b"",
            psks=[self._psk.to_bytes()],
        )
        self._complete = False
        self._i2r_key: bytes | None = None
        self._r2i_key: bytes | None = None

    def send_start(self) -> HandshakePacket:
        """Create HandshakeStart message (message 1)."""
        buffer = bytearray()
        self._hs.write_message(b"", buffer)
        return HandshakePacket(
            message_type=MessageType.HANDSHAKE_START,
            ciphersuite=self._ciphersuite,
            payload=bytes(buffer),
        )

    def receive_finish(self, packet: HandshakePacket) -> None:
        """Process HandshakeFinish message (message 2)."""
        if packet.message_type != MessageType.HANDSHAKE_FINISH:
            raise HandshakeError(
                f"Expected HandshakeFinish, got {packet.message_type!r}"
            )
        if packet.ciphersuite != self._ciphersuite:
            raise HandshakeError("Ciphersuite mismatch")

        payload_buffer = bytearray()
        cipherstates = self._hs.read_message(bytes(packet.payload), payload_buffer)

        if cipherstates is None:
            raise HandshakeError("Handshake not complete after message 2")

        i2r_cs, r2i_cs = cipherstates
        self._i2r_key = bytes(i2r_cs._key)  # noqa: SLF001
        self._r2i_key = bytes(r2i_cs._key)  # noqa: SLF001
        self._complete = True

    def finalize(self) -> tuple[bytes, bytes, str]:
        """Finalize handshake, returning (send_key, recv_key, fingerprint).

        For the initiator:
          send_key = i2r_key
          recv_key = r2i_key
          fingerprint = hex(SHA256(r2i_key || i2r_key)[:3])
        """
        if not self._complete or self._i2r_key is None or self._r2i_key is None:
            raise HandshakeError("Handshake not complete")

        send_key = self._i2r_key
        recv_key = self._r2i_key

        # Fingerprint: SHA256(r2i || i2r), first 3 bytes hex-encoded → 6 chars
        combined = recv_key + send_key
        h = hashlib.sha256(combined).digest()
        fingerprint = h[:3].hex()

        return send_key, recv_key, fingerprint

    @property
    def ciphersuite_str(self) -> str:
        return CLASSICAL_CIPHERSUITE_STR
