//! Authentication module for the bw-proxy crate. Authentication works by creating a cryptographic
//! identity - a signature key-pair. The identity is the public key. It is proven to the relay, by
//! signing a challenge provided by the relay using the signature key.

use coset::{
    CborSerializable, CoseKey, CoseKeyBuilder, CoseSign1, HeaderBuilder, Label,
    iana::{self},
};
use ed25519_dalek::{Signer, SigningKey, Verifier as Ed25519Verifier, VerifyingKey};
#[cfg(feature = "experimental-post-quantum-crypto")]
use ml_dsa::MlDsa65;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::error::ProxyError;

/// Signature algorithm selection for key generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// Classical Ed25519 signatures (EdDSA)
    Ed25519,
    #[cfg(feature = "experimental-post-quantum-crypto")]
    /// Post-quantum ML-DSA-65 signatures (Dilithium)
    MlDsa65,
}

#[allow(clippy::derivable_impls)]
impl Default for SignatureAlgorithm {
    fn default() -> Self {
        #[cfg(not(feature = "experimental-post-quantum-crypto"))]
        {
            SignatureAlgorithm::Ed25519
        }
        #[cfg(feature = "experimental-post-quantum-crypto")]
        {
            SignatureAlgorithm::MlDsa65
        }
    }
}

/// A cryptographic identity key-pair for signing challenges.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum IdentityKeyPair {
    Ed25519 {
        private_key_encoded: [u8; 32],
        private_key: SigningKey,
        public_key: VerifyingKey,
    },
    #[cfg(feature = "experimental-post-quantum-crypto")]
    MlDsa65 {
        private_key_encoded: [u8; 32],
        private_key: ml_dsa::SigningKey<MlDsa65>,
        public_key: ml_dsa::VerifyingKey<MlDsa65>,
    },
}

impl IdentityKeyPair {
    /// Generate a new identity key-pair using the default algorithm.
    pub fn generate() -> Self {
        Self::generate_with_algorithm(SignatureAlgorithm::default())
    }

    fn generate_with_algorithm(algorithm: SignatureAlgorithm) -> Self {
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let mut seed = [0u8; 32];
                let mut rng = rand::thread_rng();
                rng.fill_bytes(&mut seed);
                let private_key = SigningKey::from_bytes(&seed);
                let public_key = VerifyingKey::from(&private_key);
                IdentityKeyPair::Ed25519 {
                    private_key_encoded: seed,
                    private_key,
                    public_key,
                }
            }
            #[cfg(feature = "experimental-post-quantum-crypto")]
            SignatureAlgorithm::MlDsa65 => {
                use ml_dsa::KeyGen;

                let mut seed = [0u8; 32];
                let mut rng = rand::thread_rng();
                rng.fill_bytes(&mut seed);
                let keypair = MlDsa65::key_gen_internal(&seed.into());
                let private_key = keypair.signing_key();
                let public_key = keypair.verifying_key();
                IdentityKeyPair::MlDsa65 {
                    private_key_encoded: seed,
                    private_key: private_key.clone(),
                    public_key: public_key.clone(),
                }
            }
        }
    }

    /// Serialize this key pair to COSE key format.
    pub fn to_cose(&self) -> Vec<u8> {
        match self {
            IdentityKeyPair::Ed25519 {
                private_key_encoded,
                public_key,
                ..
            } => {
                let cose_key = CoseKeyBuilder::new_okp_key()
                    .algorithm(iana::Algorithm::EdDSA)
                    .param(
                        iana::OkpKeyParameter::Crv as i64,
                        coset::cbor::Value::Integer((iana::Algorithm::EdDSA as i64).into()),
                    )
                    .param(
                        iana::OkpKeyParameter::X as i64,
                        coset::cbor::Value::Bytes(public_key.to_bytes().to_vec()),
                    )
                    .param(
                        iana::OkpKeyParameter::D as i64,
                        coset::cbor::Value::Bytes(private_key_encoded.to_vec()),
                    )
                    .build();
                cose_key
                    .to_vec()
                    .expect("COSE key serialization should succeed")
            }
            #[cfg(feature = "experimental-post-quantum-crypto")]
            IdentityKeyPair::MlDsa65 {
                private_key_encoded,
                public_key,
                ..
            } => {
                let cose_key = CoseKey {
                    kty: coset::KeyType::Assigned(iana::KeyType::AKP),
                    alg: Some(coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_65)),
                    params: vec![
                        (
                            Label::Int(iana::AkpKeyParameter::Pub as i64),
                            coset::cbor::Value::Bytes(public_key.encode().to_vec()),
                        ),
                        (
                            Label::Int(iana::AkpKeyParameter::Priv as i64),
                            coset::cbor::Value::Bytes(private_key_encoded.to_vec()),
                        ),
                    ],
                    ..Default::default()
                };
                cose_key
                    .to_vec()
                    .expect("COSE key serialization should succeed")
            }
        }
    }

    /// Deserialize a key pair from COSE key format.
    pub fn from_cose(cose_bytes: &[u8]) -> Result<Self, ProxyError> {
        let cose_key = CoseKey::from_slice(cose_bytes).map_err(|_| {
            ProxyError::InvalidMessage("Invalid COSE key encoding".to_string())
        })?;

        let alg = cose_key.alg.as_ref().ok_or_else(|| {
            ProxyError::InvalidMessage("Missing algorithm in COSE key".to_string())
        })?;

        match alg {
            coset::Algorithm::Assigned(iana::Algorithm::EdDSA) => {
                // Extract private key seed (D parameter)
                let mut seed: Option<[u8; 32]> = None;
                for (label, value) in &cose_key.params {
                    if *label == Label::Int(iana::OkpKeyParameter::D as i64) {
                        if let coset::cbor::Value::Bytes(bytes) = value {
                            if bytes.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(bytes);
                                seed = Some(arr);
                            }
                        }
                    }
                }

                let seed = seed.ok_or_else(|| {
                    ProxyError::InvalidMessage(
                        "Missing Ed25519 private key seed in COSE key".to_string(),
                    )
                })?;
                let private_key = SigningKey::from_bytes(&seed);
                let public_key = VerifyingKey::from(&private_key);

                Ok(IdentityKeyPair::Ed25519 {
                    private_key_encoded: seed,
                    private_key,
                    public_key,
                })
            }
            #[cfg(feature = "experimental-post-quantum-crypto")]
            coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_65) => {
                // Extract private key seed

                use ml_dsa::KeyGen;
                let mut seed: Option<[u8; 32]> = None;
                for (label, value) in &cose_key.params {
                    if *label == Label::Int(iana::AkpKeyParameter::Priv as i64) {
                        if let coset::cbor::Value::Bytes(bytes) = value {
                            if bytes.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(bytes);
                                seed = Some(arr);
                            }
                        }
                    }
                }

                let seed = seed.ok_or_else(|| {
                    ProxyError::InvalidMessage(
                        "Missing ML-DSA-65 private key seed in COSE key".to_string(),
                    )
                })?;
                let keypair = MlDsa65::key_gen_internal(&seed.into());
                let private_key = keypair.signing_key();
                let public_key = keypair.verifying_key();

                Ok(IdentityKeyPair::MlDsa65 {
                    private_key_encoded: seed,
                    private_key: private_key.clone(),
                    public_key: public_key.clone(),
                })
            }
            _ => Err(ProxyError::InvalidMessage(
                "Unsupported algorithm in COSE key".to_string(),
            )),
        }
    }

    /// Get the public identity corresponding to this key pair.
    ///
    /// The public [`Identity`] contains only the public key and can be shared freely.
    /// It is used to verify signatures and identify clients to the proxy.
    ///
    /// # Examples
    ///
    /// ```
    /// use bw_proxy::IdentityKeyPair;
    ///
    /// let keypair = IdentityKeyPair::generate();
    /// let public_identity = keypair.identity();
    ///
    /// // Share the public identity with others
    /// println!("My fingerprint: {:?}", public_identity.fingerprint());
    /// ```
    pub fn identity(&self) -> Identity {
        Identity::from(self)
    }
}

/// A public cryptographic identity.
///
/// Contains the COSE-encoded public key that identifies a client. This can be shared freely
/// and is used by the proxy to verify challenge-response signatures.
///
/// # Examples
///
/// ```
/// use bw_proxy::IdentityKeyPair;
///
/// let keypair = IdentityKeyPair::generate();
/// let identity = keypair.identity();
///
/// // Get a compact fingerprint for identification
/// let fingerprint = identity.fingerprint();
/// println!("Identity fingerprint: {:?}", fingerprint);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    cose_key_bytes: Vec<u8>,
}

impl From<&IdentityKeyPair> for Identity {
    fn from(keypair: &IdentityKeyPair) -> Self {
        match keypair {
            IdentityKeyPair::Ed25519 { public_key, .. } => {
                let cose_key = CoseKeyBuilder::new_okp_key()
                    .algorithm(iana::Algorithm::EdDSA)
                    .param(
                        iana::OkpKeyParameter::Crv as i64,
                        coset::cbor::Value::Integer((iana::Algorithm::EdDSA as i64).into()),
                    )
                    .param(
                        iana::OkpKeyParameter::X as i64,
                        coset::cbor::Value::Bytes(public_key.to_bytes().to_vec()),
                    )
                    .build();
                Identity {
                    cose_key_bytes: cose_key
                        .to_vec()
                        .expect("COSE key serialization should succeed"),
                }
            }
            #[cfg(feature = "experimental-post-quantum-crypto")]
            IdentityKeyPair::MlDsa65 { public_key, .. } => {
                let cose_key = CoseKey {
                    kty: coset::KeyType::Assigned(iana::KeyType::AKP),
                    alg: Some(coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_65)),
                    params: vec![(
                        Label::Int(iana::AkpKeyParameter::Pub as i64),
                        coset::cbor::Value::Bytes(public_key.encode().to_vec()),
                    )],
                    ..Default::default()
                };
                Identity {
                    cose_key_bytes: cose_key
                        .to_vec()
                        .expect("COSE key serialization should succeed"),
                }
            }
        }
    }
}

impl Identity {
    /// Get the signature algorithm for this identity.
    ///
    /// Returns the algorithm detected from the COSE key header.
    pub fn algorithm(&self) -> Option<SignatureAlgorithm> {
        let cose_key = CoseKey::from_slice(&self.cose_key_bytes).ok()?;
        match cose_key.alg? {
            coset::Algorithm::Assigned(iana::Algorithm::EdDSA) => Some(SignatureAlgorithm::Ed25519),
            #[cfg(feature = "experimental-post-quantum-crypto")]
            coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_65) => {
                Some(SignatureAlgorithm::MlDsa65)
            }
            _ => None,
        }
    }

    /// Extract the raw public key bytes from the COSE key.
    pub fn public_key_bytes(&self) -> Option<Vec<u8>> {
        let cose_key = CoseKey::from_slice(&self.cose_key_bytes).ok()?;
        let alg = self.algorithm()?;

        match alg {
            SignatureAlgorithm::Ed25519 => {
                // Ed25519: extract X parameter from OKP key
                for (label, value) in &cose_key.params {
                    if *label == Label::Int(iana::OkpKeyParameter::X as i64) {
                        if let coset::cbor::Value::Bytes(bytes) = value {
                            return Some(bytes.clone());
                        }
                    }
                }
                None
            }
            #[cfg(feature = "experimental-post-quantum-crypto")]
            SignatureAlgorithm::MlDsa65 => {
                // ML-DSA-65: extract K parameter (we store public key there)
                for (label, value) in &cose_key.params {
                    if *label == Label::Int(iana::SymmetricKeyParameter::K as i64) {
                        if let coset::cbor::Value::Bytes(bytes) = value {
                            return Some(bytes.clone());
                        }
                    }
                }
                None
            }
        }
    }

    /// Compute the SHA256 fingerprint of this identity.
    ///
    /// The fingerprint is a 32-byte hash of the public key, providing a compact
    /// and uniform-length identifier. Fingerprints are used for:
    /// - Identifying clients in message routing
    /// - Displaying identities to users
    /// - Indexing connections in the proxy server
    ///
    /// The fingerprint is deterministic - the same identity always produces
    /// the same fingerprint.
    ///
    /// # Examples
    ///
    /// ```
    /// use bw_proxy::IdentityKeyPair;
    ///
    /// let keypair = IdentityKeyPair::generate();
    /// let identity = keypair.identity();
    /// let fingerprint = identity.fingerprint();
    ///
    /// // Fingerprints can be compared for equality
    /// assert_eq!(identity.fingerprint(), fingerprint);
    /// ```
    pub fn fingerprint(&self) -> IdentityFingerprint {
        let hash = sha2::Sha256::digest(
            self.public_key_bytes()
                .expect("Public key bytes should be extractable for valid identity"),
        );
        IdentityFingerprint(hash.into())
    }
}

/// A compact SHA256 fingerprint of an [`Identity`].
///
/// Fingerprints are 32-byte hashes of public keys, providing a uniform-length
/// identifier that is easier to work with than full public keys. They are used
/// throughout the proxy protocol for addressing clients.
///
/// # Examples
///
/// ```
/// use bw_proxy::IdentityKeyPair;
/// use std::collections::HashMap;
///
/// let keypair = IdentityKeyPair::generate();
/// let fingerprint = keypair.identity().fingerprint();
///
/// // Use as a map key
/// let mut clients = HashMap::new();
/// clients.insert(fingerprint, "Alice");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityFingerprint(pub [u8; 32]);

impl std::fmt::Debug for IdentityFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityFingerprint({})", hex::encode(self.0))
    }
}

/// A cryptographic challenge issued by the proxy server for authentication.
///
/// The server sends a random challenge to newly connected clients. Clients must
/// sign this challenge with their private key to prove their identity without
/// revealing the private key itself.
///
/// # Protocol Flow
///
/// 1. Client connects via WebSocket
/// 2. Server generates and sends [`Challenge`]
/// 3. Client signs challenge using [`IdentityKeyPair`]
/// 4. Client sends [`ChallengeResponse`] with signature
/// 5. Server verifies signature to authenticate client
///
/// # Examples
///
/// Server-side challenge generation:
///
/// ```
/// use bw_proxy::Challenge;
///
/// let challenge = Challenge::new();
/// // Send to client for signing
/// ```
///
/// Client-side challenge signing:
///
/// ```
/// use bw_proxy::{Challenge, IdentityKeyPair};
///
/// let keypair = IdentityKeyPair::generate();
/// # let challenge = Challenge::new();
/// let response = challenge.sign(&keypair);
/// // Send response back to server
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge([u8; 32]);

impl Default for Challenge {
    fn default() -> Self {
        Self::new()
    }
}

impl Challenge {
    /// Generate a new random challenge using cryptographically secure randomness.
    ///
    /// Each challenge is 32 bytes of random data, providing sufficient entropy to
    /// prevent replay attacks and ensure uniqueness.
    ///
    /// # Examples
    ///
    /// ```
    /// use bw_proxy::Challenge;
    ///
    /// let challenge = Challenge::new();
    /// // Each call produces a different random challenge
    /// assert_ne!(format!("{:?}", challenge), format!("{:?}", Challenge::new()));
    /// ```
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Challenge(bytes)
    }

    /// Sign this challenge using the provided identity key-pair.
    ///
    /// # Examples
    ///
    /// ```
    /// use bw_proxy::{Challenge, IdentityKeyPair};
    ///
    /// let keypair = IdentityKeyPair::generate();
    /// let challenge = Challenge::new();
    /// let response = challenge.sign(&keypair);
    ///
    /// // Verify the signature
    /// let identity = keypair.identity();
    /// assert!(response.verify(&challenge, &identity));
    /// ```
    pub fn sign(&self, identity: &IdentityKeyPair) -> ChallengeResponse {
        match identity {
            IdentityKeyPair::Ed25519 { private_key, .. } => {
                let signature = private_key.sign(&self.0);

                let cose_sign1 = CoseSign1 {
                    protected: coset::ProtectedHeader {
                        original_data: None,
                        header: HeaderBuilder::new()
                            .algorithm(iana::Algorithm::EdDSA)
                            .build(),
                    },
                    unprotected: coset::Header::default(),
                    payload: Some(self.0.to_vec()),
                    signature: signature.to_bytes().to_vec(),
                };

                ChallengeResponse {
                    cose_sign1_bytes: cose_sign1
                        .to_vec()
                        .expect("COSE_Sign1 serialization should succeed"),
                }
            }
            #[cfg(feature = "experimental-post-quantum-crypto")]
            IdentityKeyPair::MlDsa65 { private_key, .. } => {
                let signature = private_key
                    .sign_deterministic(&self.0, &[])
                    .expect("ML-DSA signing should succeed");

                let header = coset::Header {
                    alg: Some(coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_65)),
                    ..Default::default()
                };

                let cose_sign1 = CoseSign1 {
                    protected: coset::ProtectedHeader {
                        original_data: None,
                        header,
                    },
                    unprotected: coset::Header::default(),
                    payload: Some(self.0.to_vec()),
                    signature: signature.encode().to_vec(),
                };

                ChallengeResponse {
                    cose_sign1_bytes: cose_sign1
                        .to_vec()
                        .expect("COSE_Sign1 serialization should succeed"),
                }
            }
        }
    }
}

/// A signed response to an authentication challenge.
///
/// Contains a COSE_Sign1 structure with the signature over the challenge bytes,
/// proving possession of the private key corresponding to the claimed identity.
///
/// # Examples
///
/// Create and verify a challenge response:
///
/// ```
/// use bw_proxy::{Challenge, IdentityKeyPair};
///
/// // Client signs challenge
/// let keypair = IdentityKeyPair::generate();
/// let challenge = Challenge::new();
/// let response = challenge.sign(&keypair);
///
/// // Server verifies response
/// let identity = keypair.identity();
/// assert!(response.verify(&challenge, &identity));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    cose_sign1_bytes: Vec<u8>,
}

impl ChallengeResponse {
    /// Verify this response against the original challenge and claimed identity.
    ///
    /// Returns `true` if the signature is valid and was created by the private key
    /// corresponding to the provided identity. Returns `false` if:
    /// - The signature is malformed
    /// - The signature verification fails
    /// - The identity public key is invalid
    /// - The algorithm in the signature doesn't match the identity
    ///
    /// # Authentication Process
    ///
    /// The server uses this method to authenticate clients:
    /// 1. Receive [`Identity`] and [`ChallengeResponse`] from client
    /// 2. Call `response.verify(&original_challenge, &claimed_identity)`
    /// 3. If `true`, the client possesses the private key (authenticated)
    /// 4. If `false`, reject the authentication attempt
    ///
    /// # Examples
    ///
    /// ```
    /// use bw_proxy::{Challenge, IdentityKeyPair};
    ///
    /// let keypair = IdentityKeyPair::generate();
    /// let challenge = Challenge::new();
    /// let response = challenge.sign(&keypair);
    ///
    /// // Valid signature
    /// assert!(response.verify(&challenge, &keypair.identity()));
    ///
    /// // Invalid signature (different challenge)
    /// let other_challenge = Challenge::new();
    /// assert!(!response.verify(&other_challenge, &keypair.identity()));
    ///
    /// // Invalid signature (different identity)
    /// let other_keypair = IdentityKeyPair::generate();
    /// assert!(!response.verify(&challenge, &other_keypair.identity()));
    /// ```
    pub fn verify(&self, challenge: &Challenge, identity: &Identity) -> bool {
        let cose_sign1 = match CoseSign1::from_slice(&self.cose_sign1_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Extract algorithm from protected header
        let sig_alg = match &cose_sign1.protected.header.alg {
            Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)) => SignatureAlgorithm::Ed25519,
            #[cfg(feature = "experimental-post-quantum-crypto")]
            Some(coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_65)) => {
                SignatureAlgorithm::MlDsa65
            }
            _ => return false,
        };

        // Algorithm must be valid and supported
        let identity_alg = match identity.algorithm() {
            Some(alg) => alg,
            None => return false,
        };

        // Algorithms must match
        if sig_alg != identity_alg {
            return false;
        }

        // Payload must match challenge
        let payload = match &cose_sign1.payload {
            Some(p) => p,
            None => return false,
        };
        if payload.as_slice() != challenge.0.as_slice() {
            return false;
        }

        // Extract public key bytes
        let pk_bytes = match identity.public_key_bytes() {
            Some(bytes) => bytes,
            None => return false,
        };

        // Dispatch to appropriate verification function
        match sig_alg {
            SignatureAlgorithm::Ed25519 => {
                verify_ed25519(&cose_sign1.signature, &challenge.0, &pk_bytes)
            }
            #[cfg(feature = "experimental-post-quantum-crypto")]
            SignatureAlgorithm::MlDsa65 => {
                verify_ml_dsa_65(&cose_sign1.signature, &challenge.0, &pk_bytes)
            }
        }
    }
}

fn verify_ed25519(sig: &[u8], msg: &[u8], pk: &[u8]) -> bool {
    let signature: ed25519_dalek::Signature = match sig.try_into() {
        Ok(sig_bytes) => ed25519_dalek::Signature::from_bytes(sig_bytes),
        Err(_) => return false,
    };

    let public_key: VerifyingKey = match pk.try_into() {
        Ok(pk_bytes) => match VerifyingKey::from_bytes(pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        },
        Err(_) => return false,
    };

    public_key.verify(msg, &signature).is_ok()
}

#[cfg(feature = "experimental-post-quantum-crypto")]
fn verify_ml_dsa_65(sig: &[u8], msg: &[u8], pk: &[u8]) -> bool {
    use ml_dsa::signature::Verifier;

    let signature = match sig.try_into() {
        Ok(sig_bytes) => match ml_dsa::Signature::<MlDsa65>::decode(&sig_bytes) {
            Some(sig) => sig,
            None => return false,
        },
        Err(_) => return false,
    };

    let public_key = match pk.try_into() {
        Ok(pk_bytes) => ml_dsa::VerifyingKey::<MlDsa65>::decode(&pk_bytes),
        Err(_) => return false,
    };

    public_key.verify(msg, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_keypair_generation() {
        let identity_keypair = IdentityKeyPair::generate();
        let challenge = Challenge::new();
        let response = challenge.sign(&identity_keypair);
        assert!(response.verify(&challenge, &identity_keypair.identity()));
    }

    #[test]
    fn test_encoding_roundtrip() {
        let identity_keypair = IdentityKeyPair::generate();
        let cose_bytes = identity_keypair.to_cose();
        let decoded_keypair =
            IdentityKeyPair::from_cose(&cose_bytes).expect("Decoding should succeed");

        // Sign and verify to ensure keys match
        let challenge = Challenge::new();
        let response = challenge.sign(&decoded_keypair);
        assert!(response.verify(&challenge, &decoded_keypair.identity()));
    }

    #[test]
    fn test_challenge_response() {
        let identity_keypair = IdentityKeyPair::generate();
        let public_identity = identity_keypair.identity();
        let challenge = Challenge::new();
        let response = challenge.sign(&identity_keypair);
        assert!(response.verify(&challenge, &public_identity));
    }

    #[test]
    fn test_challenge_response_wrong_challenge() {
        let identity_keypair = IdentityKeyPair::generate();
        let public_identity = identity_keypair.identity();
        let challenge1 = Challenge::new();
        let challenge2 = Challenge::new();
        let response = challenge1.sign(&identity_keypair);
        assert!(!response.verify(&challenge2, &public_identity));
    }

    #[test]
    fn test_challenge_response_wrong_identity() {
        let identity_keypair1 = IdentityKeyPair::generate();
        let identity_keypair2 = IdentityKeyPair::generate();
        let challenge = Challenge::new();
        let response = challenge.sign(&identity_keypair1);
        assert!(!response.verify(&challenge, &identity_keypair2.identity()));
    }

    #[test]
    fn test_ed25519_round_trip() {
        let keypair = IdentityKeyPair::generate_with_algorithm(SignatureAlgorithm::Ed25519);
        let challenge = Challenge::new();
        let response = challenge.sign(&keypair);
        assert!(response.verify(&challenge, &keypair.identity()));
    }

    #[cfg(feature = "experimental-post-quantum-crypto")]
    #[test]
    fn test_ml_dsa_round_trip() {
        let keypair = IdentityKeyPair::generate_with_algorithm(SignatureAlgorithm::MlDsa65);
        let challenge = Challenge::new();
        let response = challenge.sign(&keypair);
        assert!(response.verify(&challenge, &keypair.identity()));
    }

    #[test]
    fn test_cose_algorithm_detection() {
        let ed25519_keypair = IdentityKeyPair::generate_with_algorithm(SignatureAlgorithm::Ed25519);
        #[cfg(feature = "experimental-post-quantum-crypto")]
        let ml_dsa_keypair = IdentityKeyPair::generate_with_algorithm(SignatureAlgorithm::MlDsa65);

        assert_eq!(
            ed25519_keypair.identity().algorithm(),
            Some(SignatureAlgorithm::Ed25519)
        );
        #[cfg(feature = "experimental-post-quantum-crypto")]
        assert_eq!(
            ml_dsa_keypair.identity().algorithm(),
            Some(SignatureAlgorithm::MlDsa65)
        );
    }
}
