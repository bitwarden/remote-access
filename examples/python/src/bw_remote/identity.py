"""Ed25519 identity keypair with COSE encoding and fingerprints.

Reference: crates/bw-proxy-protocol/src/auth.rs

COSE key parameter labels (from IANA COSE registry):
  kty (1), alg (3), OKP crv (-1), OKP X (-2), OKP D (-4)

EdDSA algorithm ID = -8 (iana::Algorithm::EdDSA)
OKP key type = 1

The Rust code stores the "crv" parameter with the value of the EdDSA algorithm
ID as an integer (iana::Algorithm::EdDSA as i64 = -8), not the standard OKP
curve identifier. We replicate this for wire compatibility.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import cbor2
from nacl.signing import SigningKey, VerifyKey

# COSE constants
_KTY_OKP = 1
_ALG_EDDSA = -8
_OKP_CRV = -1
_OKP_X = -2
_OKP_D = -4

# COSE_Sign1 tag
_COSE_SIGN1_TAG = 18


class IdentityKeyPair:
    """Ed25519 identity keypair derived from a 32-byte seed."""

    __slots__ = ("_seed", "_signing_key", "_verify_key")

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("Seed must be 32 bytes")
        self._seed = bytes(seed)
        self._signing_key = SigningKey(seed)
        self._verify_key = self._signing_key.verify_key

    @classmethod
    def generate(cls) -> IdentityKeyPair:
        return cls(os.urandom(32))

    @classmethod
    def from_cose(cls, cose_bytes: bytes) -> IdentityKeyPair:
        """Deserialize from COSE key bytes (CBOR-encoded CoseKey)."""
        cose_key = cbor2.loads(cose_bytes)
        if not isinstance(cose_key, dict):
            raise ValueError("Invalid COSE key: expected CBOR map")

        alg = cose_key.get(3)
        if alg != _ALG_EDDSA:
            raise ValueError(f"Unsupported algorithm: {alg}")

        seed = cose_key.get(_OKP_D)
        if seed is None or len(seed) != 32:
            raise ValueError("Missing or invalid Ed25519 seed (D parameter)")

        return cls(seed)

    def to_cose(self) -> bytes:
        """Serialize full keypair to COSE key bytes (CBOR map)."""
        cose_key = {
            1: _KTY_OKP,  # kty = OKP
            3: _ALG_EDDSA,  # alg = EdDSA
            _OKP_CRV: _ALG_EDDSA,  # crv = EdDSA (Rust compat)
            _OKP_X: bytes(self._verify_key),  # public key
            _OKP_D: self._seed,  # private seed
        }
        return cbor2.dumps(cose_key)

    def identity(self) -> Identity:
        return Identity(self._verify_key)

    @property
    def public_key_bytes(self) -> bytes:
        return bytes(self._verify_key)

    def sign(self, message: bytes) -> bytes:
        """Sign a message, returning the 64-byte Ed25519 signature."""
        signed = self._signing_key.sign(message)
        return signed.signature

    def sign_challenge(self, challenge: bytes) -> bytes:
        """Sign an auth challenge, returning COSE_Sign1 bytes.

        COSE_Sign1 = CBOR Tag(18, [protected, unprotected, payload, signature])
          protected = bstr(CBOR-encode({1: -8}))  (alg: EdDSA)
          unprotected = {}
          payload = challenge bytes
          signature = Ed25519 signature
        """
        protected_header = cbor2.dumps({1: _ALG_EDDSA})
        signature = self.sign(challenge)
        cose_sign1 = cbor2.CBORTag(
            _COSE_SIGN1_TAG,
            [protected_header, {}, challenge, signature],
        )
        return cbor2.dumps(cose_sign1)


class Identity:
    """A public identity (Ed25519 public key) with COSE encoding."""

    __slots__ = ("_verify_key",)

    def __init__(self, verify_key: VerifyKey) -> None:
        self._verify_key = verify_key

    @property
    def public_key_bytes(self) -> bytes:
        return bytes(self._verify_key)

    def cose_key_bytes(self) -> bytes:
        """Encode the public key as a COSE key (CBOR map, no private key)."""
        cose_key = {
            1: _KTY_OKP,  # kty = OKP
            3: _ALG_EDDSA,  # alg = EdDSA
            _OKP_CRV: _ALG_EDDSA,  # crv = EdDSA (Rust compat)
            _OKP_X: bytes(self._verify_key),  # public key
        }
        return cbor2.dumps(cose_key)

    def fingerprint(self) -> bytes:
        """SHA256 hash of the public key bytes → 32-byte fingerprint."""
        return hashlib.sha256(bytes(self._verify_key)).digest()

    def fingerprint_hex(self) -> str:
        return self.fingerprint().hex()


def load_identity(name: str, base_dir: Path | None = None) -> IdentityKeyPair:
    """Load an identity keypair from ~/.bw-remote/{name}.key."""
    if base_dir is None:
        base_dir = Path.home() / ".bw-remote"
    path = base_dir / f"{name}.key"
    if not path.exists():
        raise FileNotFoundError(f"Identity file not found: {path}")
    return IdentityKeyPair.from_cose(path.read_bytes())


def save_identity(keypair: IdentityKeyPair, name: str, base_dir: Path | None = None) -> Path:
    """Save an identity keypair to ~/.bw-remote/{name}.key."""
    if base_dir is None:
        base_dir = Path.home() / ".bw-remote"
    base_dir.mkdir(parents=True, exist_ok=True)
    path = base_dir / f"{name}.key"
    path.write_bytes(keypair.to_cose())
    return path


def load_or_generate_identity(name: str, base_dir: Path | None = None) -> IdentityKeyPair:
    """Load an existing identity or generate and save a new one."""
    try:
        return load_identity(name, base_dir)
    except FileNotFoundError:
        keypair = IdentityKeyPair.generate()
        save_identity(keypair, name, base_dir)
        return keypair
