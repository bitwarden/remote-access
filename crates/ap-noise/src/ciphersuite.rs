//! Cipher suite definitions for multi-device Noise protocol
//!
//! Supports both classical (Curve25519) and post-quantum (Kyber768) cipher suites.

use serde::{Deserialize, Serialize};
use std::fmt::Display;

use crate::error::NoiseProtocolError;

/// Supported cipher suites for multi-device Noise protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Ciphersuite {
    /// Classical: Noise_NNpsk2_25519_XChaChaPoly_SHA256
    /// Uses Curve25519 for DH, XChaCha20-Poly1305 for encryption, SHA256 for hashing
    /// Note: The handshake is currently using ChaChaPoly1305
    ClassicalNNpsk2_25519_XChaCha20Poly1035 = 0x01,

    /// Post-Quantum: pqNoise_NNpsk2_Kyber768_XChaChaPoly_SHA256
    /// Uses Kyber768 for KEM, XChaCha20-Poly1305 for encryption, SHA256 for hashing
    /// Note: The handshake is currently using ChaChaPoly1305
    PQNNpsk2_Kyber768_XChaCha20Poly1305 = 0x02,
}

impl Display for Ciphersuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035 => {
                "ClassicalNNpsk2_25519_XChaCha20Poly1035"
            }
            Ciphersuite::PQNNpsk2_Kyber768_XChaCha20Poly1305 => {
                "PQNNpsk2_Kyber768_XChaCha20Poly1305"
            }
        };
        write!(f, "{name}")
    }
}

impl Ciphersuite {
    /// Convert cipher suite to 1-byte wire format ID
    pub fn to_id(self) -> u8 {
        self as u8
    }

    /// Parse cipher suite from wire format ID
    pub fn from_id(id: u8) -> Result<Self, NoiseProtocolError> {
        match id {
            0x01 => Ok(Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035),
            0x02 => Ok(Ciphersuite::PQNNpsk2_Kyber768_XChaCha20Poly1305),
            _ => Err(NoiseProtocolError::UnsupportedCiphersuite(id)),
        }
    }

    pub(crate) fn default() -> Self {
        #[cfg(feature = "experimental-post-quantum-crypto")]
        {
            Ciphersuite::PQNNpsk2_Kyber768_XChaCha20Poly1305
        }
        #[cfg(not(feature = "experimental-post-quantum-crypto"))]
        {
            Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ciphersuite_roundtrip() {
        let suites = vec![
            Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035,
            Ciphersuite::PQNNpsk2_Kyber768_XChaCha20Poly1305,
        ];

        for suite in suites {
            let id = suite.to_id();
            let parsed = Ciphersuite::from_id(id).expect("should parse");
            assert_eq!(suite, parsed);
        }
    }

    #[test]
    fn test_invalid_ciphersuite() {
        assert!(Ciphersuite::from_id(0x00).is_err());
        assert!(Ciphersuite::from_id(0x03).is_err());
        assert!(Ciphersuite::from_id(0xFF).is_err());
    }

    #[test]
    fn test_ciphersuite_ids() {
        assert_eq!(
            Ciphersuite::ClassicalNNpsk2_25519_XChaCha20Poly1035.to_id(),
            0x01
        );
        assert_eq!(
            Ciphersuite::PQNNpsk2_Kyber768_XChaCha20Poly1305.to_id(),
            0x02
        );
    }
}
