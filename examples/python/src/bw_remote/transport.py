"""XChaCha20-Poly1305 multi-device transport encryption.

Reference: crates/bw-noise-protocol/src/transport.rs

Uses random 24-byte nonces with timestamp-based replay protection.
"""

from __future__ import annotations

import os
import time

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

from .errors import TransportError
from .packet import CiphersuiteId, TransportPacket, TransportPacketAad

MAX_MESSAGE_AGE = 86400  # 1 day
CLOCK_SKEW_TOLERANCE = 60  # 1 minute
MAX_REKEY_GAP = 1024
REKEY_INTERVAL = 86400  # 1 day
NONCE_SIZE = 24
KEY_SIZE = 32


def _rekey(key: bytes) -> bytes:
    """Derive a new key: encrypt 32 zero bytes with nonce=0xFF*24, take first 32 bytes."""
    nonce = b"\xff" * NONCE_SIZE
    plaintext = b"\x00" * KEY_SIZE
    derived = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, b"", nonce, key)
    return derived[:KEY_SIZE]


class MultiDeviceTransport:
    """Transport state for encrypted messaging with random nonces."""

    def __init__(
        self,
        ciphersuite: CiphersuiteId,
        send_key: bytes,
        recv_key: bytes,
        send_rekey_counter: int = 1,
        recv_rekey_counter: int = 1,
        last_rekeyed_time: int | None = None,
        rekey_interval: int = REKEY_INTERVAL,
    ) -> None:
        self.ciphersuite = ciphersuite
        self._send_key = send_key
        self._recv_key = recv_key
        self.send_rekey_counter = send_rekey_counter
        self.recv_rekey_counter = recv_rekey_counter
        self.last_rekeyed_time = last_rekeyed_time or int(time.time())
        self.rekey_interval = rekey_interval
        self._seen_nonces: dict[bytes, int] = {}

    def _now(self) -> int:
        return int(time.time())

    def _prune_old_nonces(self) -> None:
        now = self._now()
        cutoff = max(0, now - MAX_MESSAGE_AGE)
        self._seen_nonces = {
            n: ts for n, ts in self._seen_nonces.items() if ts >= cutoff
        }

    def _rekey_send_if_needed(self) -> None:
        now = self._now()
        while now - self.last_rekeyed_time >= self.rekey_interval:
            self._send_key = _rekey(self._send_key)
            self.send_rekey_counter += 1
            self.last_rekeyed_time += self.rekey_interval

    def encrypt(self, plaintext: bytes) -> TransportPacket:
        """Encrypt plaintext into a TransportPacket."""
        self._rekey_send_if_needed()

        aad = TransportPacketAad(
            timestamp=self._now(),
            chain_counter=self.send_rekey_counter,
            ciphersuite=self.ciphersuite,
        )
        aad_bytes = aad.encode()

        nonce = os.urandom(NONCE_SIZE)
        ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad_bytes, nonce, self._send_key
        )

        return TransportPacket(nonce=nonce, ciphertext=ciphertext, aad=aad_bytes)

    def decrypt(self, packet: TransportPacket) -> bytes:
        """Decrypt a TransportPacket, returning plaintext."""
        packet_aad = TransportPacketAad.decode(packet.aad)

        if packet_aad.ciphersuite != self.ciphersuite:
            raise TransportError("Ciphersuite mismatch")

        self._validate_timestamp(packet_aad)
        self._check_replay(packet, packet_aad)
        self._rekey_receive(packet_aad)

        # Determine decryption key
        if packet_aad.chain_counter == self.recv_rekey_counter:
            decrypt_key = self._recv_key
        else:
            decrypt_key = _rekey(self._recv_key)

        try:
            plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
                packet.ciphertext, packet.aad, packet.nonce, decrypt_key
            )
        except Exception as e:
            raise TransportError(f"Decryption failed: {e}") from e

        return plaintext

    def _validate_timestamp(self, aad: TransportPacketAad) -> None:
        now = self._now()
        if aad.timestamp < max(0, now - MAX_MESSAGE_AGE):
            raise TransportError(
                f"Message too old: timestamp={aad.timestamp}, now={now}"
            )
        if aad.timestamp > now + CLOCK_SKEW_TOLERANCE:
            raise TransportError(
                f"Message from future: timestamp={aad.timestamp}, now={now}"
            )

    def _check_replay(self, packet: TransportPacket, aad: TransportPacketAad) -> None:
        self._prune_old_nonces()
        if packet.nonce in self._seen_nonces:
            raise TransportError("Replay detected")
        self._seen_nonces[packet.nonce] = aad.timestamp

    def _rekey_receive(self, aad: TransportPacketAad) -> None:
        if aad.chain_counter < self.recv_rekey_counter:
            raise TransportError("Desynchronized: message uses old key")
        if aad.chain_counter > self.recv_rekey_counter + MAX_REKEY_GAP:
            raise TransportError("Desynchronized: rekey gap too large")

        # Catch up to one before the incoming counter
        while self.recv_rekey_counter < aad.chain_counter - 1:
            self._recv_key = _rekey(self._recv_key)
            self.recv_rekey_counter += 1

    @property
    def send_key(self) -> bytes:
        return self._send_key

    @property
    def recv_key(self) -> bytes:
        return self._recv_key
