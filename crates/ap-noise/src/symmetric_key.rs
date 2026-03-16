use std::fmt::Debug;

use serde::{Deserialize, Serialize};

pub const SYMMETRIC_KEY_LENGTH: usize = 32;

/// 256-bit symmetric key for encryption/decryption. This can be used
/// with any 256-bit symmetric cipher (e.g., XChaCha20-Poly1305).
#[derive(Clone, PartialEq, zeroize::ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SymmetricKey([u8; SYMMETRIC_KEY_LENGTH]);

impl Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use sha2::{Digest, Sha256 as Sha256Hash};
        let hash = Sha256Hash::digest(self.0);
        let preview = format!(
            "{:02x}{:02x}{:02x}{:02x}...",
            hash[0], hash[1], hash[2], hash[3]
        );
        write!(f, "SymmetricKey({preview})")
    }
}

#[cfg(test)]
pub(crate) const SYMMETRIC_KEY_TEST_VECTOR_1: SymmetricKey =
    SymmetricKey([0u8; SYMMETRIC_KEY_LENGTH]);
#[cfg(test)]
pub(crate) const SYMMETRIC_KEY_TEST_VECTOR_2: SymmetricKey =
    SymmetricKey([1u8; SYMMETRIC_KEY_LENGTH]);

impl SymmetricKey {
    pub(crate) fn from_bytes(bytes: [u8; SYMMETRIC_KEY_LENGTH]) -> Self {
        SymmetricKey(bytes)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn to_bytes(&self) -> [u8; SYMMETRIC_KEY_LENGTH] {
        self.0
    }
}
