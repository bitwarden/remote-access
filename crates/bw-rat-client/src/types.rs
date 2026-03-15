//! Types for the remote client protocol

use bw_noise_protocol::Psk;
use bw_proxy_protocol::IdentityFingerprint;
use serde::{Deserialize, Serialize};

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

pub enum ClientAction {
    Accept,
}

/// Responses from CLI to RemoteClient
#[derive(Debug, Clone)]
pub enum RemoteClientResponse {
    /// Response to fingerprint verification prompt
    VerifyFingerprint {
        /// Whether user confirmed fingerprint matches
        approved: bool,
    },
}

/// Events emitted by the remote client during connection and operation
#[derive(Debug, Clone)]
pub enum RemoteClientEvent {
    /// Connecting to the proxy server
    Connecting {
        /// The proxy URL being connected to
        proxy_url: String,
    },
    /// Successfully connected to the proxy
    Connected {
        /// The device's identity fingerprint (hex-encoded)
        fingerprint: IdentityFingerprint,
    },
    /// Reconnecting to an existing session
    ReconnectingToSession {
        /// The fingerprint being reconnected to
        fingerprint: IdentityFingerprint,
    },
    /// Rendezvous code resolution starting
    RendevouzResolving {
        /// The rendezvous code being resolved
        code: String,
    },
    /// Rendezvous code resolved to fingerprint
    RendevouzResolved {
        /// The resolved identity fingerprint
        fingerprint: IdentityFingerprint,
    },
    /// Using PSK mode for connection
    PskMode {
        /// The fingerprint being connected to
        fingerprint: IdentityFingerprint,
    },
    /// Noise handshake starting
    HandshakeStart,
    /// Noise handshake progress
    HandshakeProgress {
        /// Progress message
        message: String,
    },
    /// Noise handshake complete
    HandshakeComplete,
    /// Handshake fingerprint ready for verification
    HandshakeFingerprint {
        /// The 6-character hex fingerprint
        fingerprint: String,
    },
    /// User verified the fingerprint
    FingerprintVerified,
    /// User rejected the fingerprint
    FingerprintRejected {
        /// Reason for rejection
        reason: String,
    },
    /// Client is ready for credential requests
    Ready {
        /// Whether credentials can be requested
        can_request_credentials: bool,
    },
    /// Credential request was sent
    CredentialRequestSent {
        /// Domain requested
        domain: String,
    },
    /// Credential was received
    CredentialReceived {
        /// Domain of the credential
        domain: String,
        /// The credential data
        credential: CredentialData,
        /// Vault item ID (if provided by the user-client)
        credential_id: Option<String>,
    },
    /// An error occurred
    Error {
        /// Error message
        message: String,
        /// Context where error occurred
        context: Option<String>,
    },
    /// Client was disconnected
    Disconnected {
        /// Reason for disconnection
        reason: Option<String>,
    },
}

/// Credential data returned from a request
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Internal protocol messages sent over WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub(crate) enum ProtocolMessage {
    /// Noise handshake init (initiator -> responder)
    #[serde(rename = "handshake-init")]
    HandshakeInit { data: String, ciphersuite: String },
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
    pub domain: String,
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
