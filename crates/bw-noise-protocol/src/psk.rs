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
        let id = self.id();
        let preview = format!("{:02x}{:02x}{:02x}{:02x}...", id[0], id[1], id[2], id[3]);
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
    /// use bw_noise_protocol::Psk;
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
    /// use bw_noise_protocol::Psk;
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
    /// use bw_noise_protocol::Psk;
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

    /// Compute a 4-byte identifier for this PSK.
    ///
    /// The ID is the first 4 bytes of SHA-256(psk). This is used to identify
    /// which PSK to use during handshake without revealing the key itself.
    pub fn id(&self) -> [u8; 4] {
        use sha2::{Digest, Sha256 as Sha256Hash};
        let hash = Sha256Hash::digest(self.0);
        [hash[0], hash[1], hash[2], hash[3]]
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

    #[test]
    fn test_psk_id_is_deterministic() {
        let psk = Psk::generate();
        assert_eq!(psk.id(), psk.id());
    }

    #[test]
    fn test_psk_id_is_4_bytes() {
        let psk = Psk::generate();
        let id = psk.id();
        assert_eq!(id.len(), 4);
    }

    #[test]
    fn test_different_psks_have_different_ids() {
        let psk1 = Psk::generate();
        let psk2 = Psk::generate();
        // Extremely unlikely to collide with 4 bytes of SHA-256
        assert_ne!(psk1.id(), psk2.id());
    }
}
