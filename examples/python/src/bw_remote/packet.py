"""Wire-format packet encoding/decoding for Noise protocol messages.

Reference: crates/bw-noise-protocol/src/packet.rs

ciborium serializes Rust structs with #[derive(Serialize)] as CBOR arrays
(positional fields). Enums with #[repr(u8)] serialize as their integer value.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

import cbor2


class MessageType(IntEnum):
    HANDSHAKE_START = 0x01
    HANDSHAKE_FINISH = 0x02
    TRANSPORT = 0x10


class CiphersuiteId(IntEnum):
    CLASSICAL = 0x01
    POST_QUANTUM = 0x02


# Wire-format ciphersuite string (used in ProtocolMessage JSON)
CLASSICAL_CIPHERSUITE_STR = "ClassicalNNpsk2_25519_XChaCha20Poly1035"


@dataclass
class HandshakePacket:
    """CBOR-encoded handshake packet: [message_type, ciphersuite, payload]."""

    message_type: MessageType
    ciphersuite: CiphersuiteId
    payload: bytes

    def encode(self) -> bytes:
        """Encode to CBOR wire format (array of 3 elements)."""
        return cbor2.dumps([
            self.message_type.value,
            self.ciphersuite.value,
            self.payload,
        ])

    @classmethod
    def decode(cls, data: bytes) -> HandshakePacket:
        """Decode from CBOR wire format."""
        arr = cbor2.loads(data)
        if not isinstance(arr, list) or len(arr) != 3:
            raise ValueError("Invalid HandshakePacket: expected 3-element CBOR array")
        return cls(
            message_type=MessageType(arr[0]),
            ciphersuite=CiphersuiteId(arr[1]),
            payload=bytes(arr[2]),
        )


@dataclass
class TransportPacketAad:
    """Additional authenticated data: [timestamp, chain_counter, ciphersuite]."""

    timestamp: int
    chain_counter: int
    ciphersuite: CiphersuiteId

    def encode(self) -> bytes:
        return cbor2.dumps([self.timestamp, self.chain_counter, self.ciphersuite.value])

    @classmethod
    def decode(cls, data: bytes) -> TransportPacketAad:
        arr = cbor2.loads(data)
        if not isinstance(arr, list) or len(arr) != 3:
            raise ValueError("Invalid TransportPacketAad: expected 3-element CBOR array")
        return cls(
            timestamp=arr[0],
            chain_counter=arr[1],
            ciphersuite=CiphersuiteId(arr[2]),
        )


@dataclass
class TransportPacket:
    """CBOR-encoded transport packet: [nonce, ciphertext, aad]."""

    nonce: bytes
    ciphertext: bytes
    aad: bytes

    def encode(self) -> bytes:
        return cbor2.dumps([self.nonce, self.ciphertext, self.aad])

    @classmethod
    def decode(cls, data: bytes) -> TransportPacket:
        arr = cbor2.loads(data)
        if not isinstance(arr, list) or len(arr) != 3:
            raise ValueError("Invalid TransportPacket: expected 3-element CBOR array")
        return cls(
            nonce=bytes(arr[0]),
            ciphertext=bytes(arr[1]),
            aad=bytes(arr[2]),
        )
