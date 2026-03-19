//! Types for the remote client protocol

use std::fmt;

use ap_noise::Psk;
use ap_proxy_protocol::IdentityFingerprint;
use serde::{Deserialize, Serialize};

/// A stable identifier for a PSK, derived from `hex(SHA256(psk)[0..8])`.
///
/// Used as a lookup key to match incoming handshakes to the correct pending
/// pairing. Today this maps to in-memory pending pairings; in the future it
/// could index persistent/reusable PSKs from a `PskStore`.
pub type PskId = String;

/// What kind of credential to look up.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CredentialQuery {
    /// Look up by domain / URL.
    Domain(String),
    /// Look up by vault item ID.
    Id(String),
    /// Free-text search.
    Search(String),
}

impl CredentialQuery {
    /// Extract the inner search string from any query variant.
    pub fn search_string(&self) -> &str {
        match self {
            Self::Domain(d) => d.as_str(),
            Self::Id(id) => id.as_str(),
            Self::Search(s) => s.as_str(),
        }
    }
}

impl fmt::Display for CredentialQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialQuery::Domain(d) => write!(f, "domain: {d}"),
            CredentialQuery::Id(id) => write!(f, "id: {id}"),
            CredentialQuery::Search(s) => write!(f, "search: {s}"),
        }
    }
}

/// Connection mode for establishing a connection
#[derive(Debug, Clone)]
pub enum ConnectionMode {
    /// New connection requiring rendezvous code pairing
    New { rendezvous_code: String },
    /// New connection using PSK authentication
    NewPsk {
        psk: Psk,
        remote_fingerprint: IdentityFingerprint,
    },
    /// Existing connection using cached remote fingerprint
    Existing {
        remote_fingerprint: IdentityFingerprint,
    },
}

/// Credential data returned from a request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialData {
    /// Username for the credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password for the credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// TOTP code if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    /// URI associated with the credential
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Additional notes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Vault item ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    /// Domain associated with this credential
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// Internal protocol messages sent over WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(crate) enum ProtocolMessage {
    /// Noise handshake init (initiator -> responder)
    #[serde(rename = "handshake-init")]
    HandshakeInit {
        data: String,
        ciphersuite: String,
        /// PSK identifier — `Some(id)` for PSK mode, `None` for rendezvous mode.
        /// Backward-compatible: old clients omit this field (deserialized as `None`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        psk_id: Option<PskId>,
    },
    /// Noise handshake response (responder -> initiator)
    #[serde(rename = "handshake-response")]
    HandshakeResponse { data: String, ciphersuite: String },
    /// Encrypted credential request
    CredentialRequest { encrypted: String },
    /// Encrypted credential response
    CredentialResponse { encrypted: String },
}

/// Internal credential request structure (encrypted in transit)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CredentialRequestPayload {
    #[serde(rename = "type")]
    pub request_type: String,
    pub query: CredentialQuery,
    pub timestamp: u64,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

/// Internal credential response structure (encrypted in transit)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CredentialResponsePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "requestId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}
