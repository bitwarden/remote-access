use ap_client::CredentialData;

/// Credential data returned from a remote access request.
#[derive(Clone, uniffi::Record)]
pub struct FfiCredentialData {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
    pub credential_id: Option<String>,
    pub domain: Option<String>,
}

impl From<CredentialData> for FfiCredentialData {
    fn from(cred: CredentialData) -> Self {
        Self {
            username: cred.username,
            password: cred.password.map(|p| (*p).clone()),
            totp: cred.totp,
            uri: cred.uri,
            notes: cred.notes,
            credential_id: cred.credential_id,
            domain: cred.domain,
        }
    }
}

/// Information about a cached connection.
#[derive(Clone, uniffi::Record)]
pub struct FfiConnectionInfo {
    /// Hex-encoded identity fingerprint of the remote peer.
    pub fingerprint: String,
    /// Optional human-readable name for the connection.
    pub name: Option<String>,
    /// Unix timestamp (seconds) when the connection was first cached.
    pub cached_at: u64,
    /// Unix timestamp (seconds) of the last successful connection.
    pub last_connected_at: u64,
}

/// Notification event from client event loops.
///
/// Covers events from both `RemoteClient` and `UserClient` in a single
/// FFI-friendly enum. All fingerprints are hex-encoded strings.
#[derive(Clone, uniffi::Enum)]
pub enum FfiEvent {
    /// Connecting to the proxy server.
    Connecting,
    /// Successfully connected to the proxy.
    Connected { fingerprint: String },
    /// Started listening for incoming connections.
    Listening,
    /// Noise handshake started.
    HandshakeStart,
    /// Noise handshake progress.
    HandshakeProgress { message: String },
    /// Noise handshake complete.
    HandshakeComplete,
    /// Handshake fingerprint for visual verification.
    HandshakeFingerprint {
        fingerprint: String,
        identity: Option<String>,
    },
    /// Fingerprint was verified and connection accepted.
    FingerprintVerified,
    /// Fingerprint was rejected.
    FingerprintRejected { reason: String },
    /// Client is ready for credential operations.
    Ready,
    /// Credential request was sent.
    CredentialRequestSent { domain: String },
    /// Credential was received.
    CredentialReceived,
    /// Credential was approved and sent (UserClient).
    CredentialApproved {
        domain: Option<String>,
        credential_id: Option<String>,
    },
    /// Credential was denied (UserClient).
    CredentialDenied {
        domain: Option<String>,
        credential_id: Option<String>,
    },
    /// Reconnecting to an existing session.
    ReconnectingToSession { fingerprint: String },
    /// A known device reconnected — transport keys refreshed.
    SessionRefreshed { fingerprint: String },
    /// Resolving a rendezvous code.
    RendezvousResolving { code: String },
    /// Rendezvous code resolved to a fingerprint.
    RendezvousResolved { fingerprint: String },
    /// Using PSK mode for connection.
    PskMode { fingerprint: String },
    /// Client disconnected from proxy.
    Disconnected { reason: Option<String> },
    /// Attempting to reconnect to proxy.
    Reconnecting { attempt: u32 },
    /// Successfully reconnected to proxy.
    Reconnected,
    /// An error occurred.
    Error {
        message: String,
        context: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn credential_data_from_all_fields() {
        let cred = CredentialData {
            username: Some("user@example.com".to_string()),
            password: Some(Zeroizing::new("secret123".to_string())),
            totp: Some("123456".to_string()),
            uri: Some("https://example.com".to_string()),
            notes: Some("test notes".to_string()),
            credential_id: Some("cred-001".to_string()),
            domain: Some("example.com".to_string()),
        };
        let converted = FfiCredentialData::from(cred);
        assert_eq!(converted.username.as_deref(), Some("user@example.com"));
        assert_eq!(converted.password.as_deref(), Some("secret123"));
        assert_eq!(converted.totp.as_deref(), Some("123456"));
        assert_eq!(converted.uri.as_deref(), Some("https://example.com"));
        assert_eq!(converted.notes.as_deref(), Some("test notes"));
        assert_eq!(converted.credential_id.as_deref(), Some("cred-001"));
        assert_eq!(converted.domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn credential_data_from_none_fields() {
        let cred = CredentialData {
            username: None,
            password: None,
            totp: None,
            uri: None,
            notes: None,
            credential_id: None,
            domain: None,
        };
        let converted = FfiCredentialData::from(cred);
        assert!(converted.username.is_none());
        assert!(converted.password.is_none());
        assert!(converted.totp.is_none());
        assert!(converted.uri.is_none());
        assert!(converted.notes.is_none());
        assert!(converted.credential_id.is_none());
        assert!(converted.domain.is_none());
    }

    #[test]
    fn credential_data_from_partial_fields() {
        let cred = CredentialData {
            username: Some("admin".to_string()),
            password: Some(Zeroizing::new("pass".to_string())),
            totp: None,
            uri: None,
            notes: None,
            credential_id: None,
            domain: None,
        };
        let converted = FfiCredentialData::from(cred);
        assert_eq!(converted.username.as_deref(), Some("admin"));
        assert_eq!(converted.password.as_deref(), Some("pass"));
        assert!(converted.totp.is_none());
    }
}
