//! Rendezvous codes for temporary peer discovery.
//!
//! The rendezvous system provides short, human-readable codes that clients can share
//! to discover each other's identities without exchanging long-lived public keys.
//!
//! # Overview
//! 1. Client requests a rendezvous code from the server
//! 2. Server generates a unique code (e.g., "ABC-DEF") and maps it to the client's identity
//! 3. Peer uses the code to look up the client's identity
//! 4. Server returns the identity and deletes the code (single-use)

use rand::distributions::{Alphanumeric, DistString};
use serde::{Deserialize, Serialize};

/// A temporary rendezvous code for peer discovery.
///
/// Rendezvous codes are short, human-readable identifiers (format: "ABC-DEF") that
/// temporarily map to a client's identity on the proxy server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendevouzCode {
    code: String,
}

impl Default for RendevouzCode {
    fn default() -> Self {
        Self::new()
    }
}

impl RendevouzCode {
    /// Generate a new random rendezvous code.
    ///
    /// Creates a 6-character code from the alphanumeric alphabet (A-Z, 0-9),
    /// formatted with a hyphen separator (e.g., "ABC-DEF").
    ///
    /// # Entropy
    ///
    /// With an alphabet of 36 characters and 6 positions:
    /// - Total possibilities: 36^6 = 2,176,782,336
    /// - Given the 5-minute lifetime, brute-force is impractical
    ///
    /// # Examples
    ///
    /// ```
    /// use bw_proxy::RendevouzCode;
    ///
    /// let code1 = RendevouzCode::new();
    /// let code2 = RendevouzCode::new();
    ///
    /// // Each call generates a different random code
    /// assert_ne!(code1.as_str(), code2.as_str());
    ///
    /// // Format is always ABC-DEF style
    /// assert_eq!(code1.as_str().len(), 7); // 6 chars + 1 hyphen
    /// assert_eq!(code1.as_str().chars().nth(3), Some('-'));
    /// ```
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();

        // The code has an alphabet of size 36. With 6 characters, that's
        // 36^6 = 2,176,782,336 possible codes. The codes are short-lived, and the connections to the relay are rate-limited,
        // which is why this is considered sufficient.
        let code = Alphanumeric.sample_string(&mut rng, 6);
        let code = code.to_ascii_uppercase();
        // SAFETY: Alphanumeric + to_ascii_uppercase produces only ASCII characters,
        // so indexing at character boundaries is safe.
        #[allow(clippy::string_slice)]
        let code = format!("{}-{}", &code[..3], &code[3..]);

        RendevouzCode { code }
    }

    /// Create a rendezvous code from an existing string.
    ///
    /// Useful for:
    /// - Testing with known codes
    /// - Parsing user input
    /// - Deserializing from storage
    ///
    /// No validation is performed - the caller is responsible for ensuring
    /// the code is in the correct format.
    ///
    /// # Examples
    ///
    /// ```
    /// use bw_proxy::RendevouzCode;
    ///
    /// let code = RendevouzCode::from_string("ABC-DEF".to_string());
    /// assert_eq!(code.as_str(), "ABC-DEF");
    /// ```
    pub fn from_string(code: String) -> Self {
        RendevouzCode { code }
    }

    /// Get the code string.
    ///
    /// Returns the formatted code (e.g., "ABC-DEF") that can be displayed to
    /// users or sent to the server.
    ///
    /// # Examples
    ///
    /// ```
    /// use bw_proxy::RendevouzCode;
    ///
    /// let code = RendevouzCode::new();
    /// println!("Your code: {}", code.as_str());
    /// ```
    pub fn as_str(&self) -> &str {
        &self.code
    }
}

impl std::fmt::Display for RendevouzCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code)
    }
}
