use bw_rat_client::CredentialData;

/// Credential data returned from a remote access request.
#[derive(uniffi::Record)]
pub struct RemoteCredentialData {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
}

impl From<CredentialData> for RemoteCredentialData {
    fn from(cred: CredentialData) -> Self {
        Self {
            username: cred.username,
            password: cred.password,
            totp: cred.totp,
            uri: cred.uri,
            notes: cred.notes,
        }
    }
}

/// Information about a cached session.
#[derive(uniffi::Record)]
pub struct SessionInfo {
    /// Hex-encoded identity fingerprint of the remote peer.
    pub fingerprint: String,
    /// Optional human-readable name for the session.
    pub name: Option<String>,
    /// Unix timestamp (seconds) when the session was first cached.
    pub cached_at: u64,
    /// Unix timestamp (seconds) of the last successful connection.
    pub last_connected_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_data_from_all_fields() {
        let cred = CredentialData {
            username: Some("user@example.com".to_string()),
            password: Some("secret123".to_string()),
            totp: Some("123456".to_string()),
            uri: Some("https://example.com".to_string()),
            notes: Some("test notes".to_string()),
        };
        let converted = RemoteCredentialData::from(cred);
        assert_eq!(converted.username.as_deref(), Some("user@example.com"));
        assert_eq!(converted.password.as_deref(), Some("secret123"));
        assert_eq!(converted.totp.as_deref(), Some("123456"));
        assert_eq!(converted.uri.as_deref(), Some("https://example.com"));
        assert_eq!(converted.notes.as_deref(), Some("test notes"));
    }

    #[test]
    fn credential_data_from_none_fields() {
        let cred = CredentialData {
            username: None,
            password: None,
            totp: None,
            uri: None,
            notes: None,
        };
        let converted = RemoteCredentialData::from(cred);
        assert!(converted.username.is_none());
        assert!(converted.password.is_none());
        assert!(converted.totp.is_none());
        assert!(converted.uri.is_none());
        assert!(converted.notes.is_none());
    }

    #[test]
    fn credential_data_from_partial_fields() {
        let cred = CredentialData {
            username: Some("admin".to_string()),
            password: Some("pass".to_string()),
            totp: None,
            uri: None,
            notes: None,
        };
        let converted = RemoteCredentialData::from(cred);
        assert_eq!(converted.username.as_deref(), Some("admin"));
        assert_eq!(converted.password.as_deref(), Some("pass"));
        assert!(converted.totp.is_none());
        assert!(converted.uri.is_none());
        assert!(converted.notes.is_none());
    }
}
