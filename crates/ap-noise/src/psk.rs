//! PSK (Pre-Shared Key) module.
//!
//! Pre-Shared Keys (PSKs) provide authentication and protection against man-in-the-middle attacks
//! in Noise protocol handshakes. When both parties share a secret PSK established through a secure
//! out-of-band channel (e.g., QR code, NFC, secure messaging), the handshake will fail if an
//! attacker attempts to intercept or modify messages, and no fingerprint verification is needed.

use rand::RngCore;
use std::fmt::Debug;

/// PSK length in bytes (32 bytes for Noise protocol)
pub const PSK_LENGTH: usize = 32;

#[derive(Clone, PartialEq, zeroize::ZeroizeOnDrop)]
pub struct Psk([u8; PSK_LENGTH]);

impl Debug for Psk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use sha2::{Digest, Sha256 as Sha256Hash};
        let hash = Sha256Hash::digest(self.0);
        let preview = format!(
            "{:02x}{:02x}{:02x}{:02x}...",
            hash[0], hash[1], hash[2], hash[3]
        );
        write!(f, "Psk({preview})")
    }
}

impl Psk {
    /// A null PSK (all zeroes).
    ///
    /// This should only be used when PSK authentication is not required and only encryption
    /// is desired. Using a null PSK provides confidentiality but not authentication.
    pub fn null() -> Self {
        Psk([0u8; PSK_LENGTH])
    }

    /// Generate a random PSK using a cryptographically secure random number generator.
    ///
    /// This is the recommended way to create a PSK for secure authentication. The PSK
    /// must then be shared with the other party through a secure out-of-band channel
    /// (QR code, NFC, secure messaging, etc.).
    ///
    /// # Example
    ///
    /// ```rust
    /// use ap_noise::Psk;
    ///
    /// let psk = Psk::generate();
    /// ```
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; PSK_LENGTH];
        rng.fill_bytes(&mut bytes);
        Psk(bytes)
    }

    /// Construct a PSK from a 32-byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Psk(bytes)
    }

    /// Export the PSK as a 32-byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Encode the PSK as a hexadecimal string.
    ///
    /// This is the recommended format for storing or transmitting PSKs (e.g., in QR codes,
    /// configuration files, or secure storage). The resulting string is 64 characters long.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ap_noise::Psk;
    /// use rand::thread_rng;
    ///
    /// let psk = Psk::generate();
    /// let encoded = psk.to_hex();
    /// assert_eq!(encoded.len(), 64);
    /// ```
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Decode a PSK from a hexadecimal string.
    ///
    /// Returns an error if the string is not valid hex or does not decode to exactly
    /// 32 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ap_noise::Psk;
    /// use rand::thread_rng;
    ///
    /// let psk = Psk::generate();
    /// let encoded = psk.to_hex();
    /// let decoded = Psk::from_hex(&encoded).unwrap();
    /// assert_eq!(psk.to_bytes(), decoded.to_bytes());
    /// ```
    pub fn from_hex(s: &str) -> Result<Self, crate::error::NoiseProtocolError> {
        let bytes =
            hex::decode(s).map_err(|_| crate::error::NoiseProtocolError::InvalidPskEncoding)?;

        if bytes.len() != PSK_LENGTH {
            return Err(crate::error::NoiseProtocolError::InvalidPskLength);
        }

        let mut arr = [0u8; PSK_LENGTH];
        arr.copy_from_slice(&bytes);
        Ok(Psk(arr))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_psk() {
        let psk = Psk::null();
        assert_eq!(psk.to_bytes(), [0u8; PSK_LENGTH]);
    }

    #[test]
    fn test_generate_psk() {
        let psk1 = Psk::generate();
        let psk2 = Psk::generate();

        // PSKs should be different
        assert_ne!(psk1.to_bytes(), psk2.to_bytes());
    }

    #[test]
    fn test_bytes_roundtrip() {
        let psk = Psk::generate();
        let bytes = psk.to_bytes();
        let psk_from_bytes = Psk::from_bytes(bytes);
        assert_eq!(psk.to_bytes(), psk_from_bytes.to_bytes());
    }

    #[test]
    fn test_hex_roundtrip() {
        let psk = Psk::generate();
        let encoded = psk.to_hex();
        assert_eq!(encoded.len(), 64);
        let decoded = Psk::from_hex(&encoded).expect("Failed to decode PSK from hex");
        assert_eq!(psk.to_bytes(), decoded.to_bytes());
    }
}
