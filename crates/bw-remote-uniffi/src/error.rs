use bw_rat_client::RemoteClientError;

/// FFI-friendly error enum that maps the 18+ variant RemoteClientError
/// into 6 categories suitable for cross-language consumption.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RemoteAccessError {
    #[error("Connection failed: {message}")]
    ConnectionFailed { message: String },
    #[error("Handshake failed: {message}")]
    HandshakeFailed { message: String },
    #[error("Credential request failed: {message}")]
    CredentialRequestFailed { message: String },
    #[error("Session error: {message}")]
    SessionError { message: String },
    #[error("Invalid argument: {message}")]
    InvalidArgument { message: String },
    #[error("Timeout: {message}")]
    Timeout { message: String },
}

impl From<RemoteClientError> for RemoteAccessError {
    fn from(err: RemoteClientError) -> Self {
        let message = err.to_string();
        match err {
            RemoteClientError::ConnectionFailed(_) | RemoteClientError::WebSocket(_) => {
                RemoteAccessError::ConnectionFailed { message }
            }

            RemoteClientError::ProxyAuthFailed(_)
            | RemoteClientError::HandshakeFailed(_)
            | RemoteClientError::NoiseProtocol(_)
            | RemoteClientError::FingerprintRejected => {
                RemoteAccessError::HandshakeFailed { message }
            }

            RemoteClientError::CredentialRequestFailed(_)
            | RemoteClientError::SecureChannelNotEstablished
            | RemoteClientError::NotInitialized => {
                RemoteAccessError::CredentialRequestFailed { message }
            }

            RemoteClientError::SessionCache(_)
            | RemoteClientError::IdentityStorageFailed(_)
            | RemoteClientError::KeypairStorage(_)
            | RemoteClientError::SessionNotFound
            | RemoteClientError::Serialization(_)
            | RemoteClientError::ChannelClosed => RemoteAccessError::SessionError { message },

            RemoteClientError::InvalidPairingCode(_)
            | RemoteClientError::InvalidRendevouzCode(_)
            | RemoteClientError::RendevouzResolutionFailed(_)
            | RemoteClientError::InvalidState { .. } => {
                RemoteAccessError::InvalidArgument { message }
            }

            RemoteClientError::Timeout(_) => RemoteAccessError::Timeout { message },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_failed_maps_correctly() {
        let err = RemoteClientError::ConnectionFailed("refused".to_string());
        let mapped = RemoteAccessError::from(err);
        assert!(matches!(mapped, RemoteAccessError::ConnectionFailed { .. }));
        assert!(mapped.to_string().contains("refused"));
    }

    #[test]
    fn websocket_error_maps_to_connection_failed() {
        let err = RemoteClientError::WebSocket("closed".to_string());
        let mapped = RemoteAccessError::from(err);
        assert!(matches!(mapped, RemoteAccessError::ConnectionFailed { .. }));
    }

    #[test]
    fn handshake_errors_map_correctly() {
        let cases = vec![
            RemoteClientError::ProxyAuthFailed("bad auth".to_string()),
            RemoteClientError::HandshakeFailed("noise error".to_string()),
            RemoteClientError::NoiseProtocol("decrypt failed".to_string()),
            RemoteClientError::FingerprintRejected,
        ];
        for err in cases {
            let mapped = RemoteAccessError::from(err);
            assert!(
                matches!(mapped, RemoteAccessError::HandshakeFailed { .. }),
                "Expected HandshakeFailed, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn credential_errors_map_correctly() {
        let cases = vec![
            RemoteClientError::CredentialRequestFailed("denied".to_string()),
            RemoteClientError::SecureChannelNotEstablished,
            RemoteClientError::NotInitialized,
        ];
        for err in cases {
            let mapped = RemoteAccessError::from(err);
            assert!(
                matches!(mapped, RemoteAccessError::CredentialRequestFailed { .. }),
                "Expected CredentialRequestFailed, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn session_errors_map_correctly() {
        let cases = vec![
            RemoteClientError::SessionCache("corrupt".to_string()),
            RemoteClientError::IdentityStorageFailed("missing".to_string()),
            RemoteClientError::KeypairStorage("bad key".to_string()),
            RemoteClientError::SessionNotFound,
            RemoteClientError::Serialization("invalid json".to_string()),
            RemoteClientError::ChannelClosed,
        ];
        for err in cases {
            let mapped = RemoteAccessError::from(err);
            assert!(
                matches!(mapped, RemoteAccessError::SessionError { .. }),
                "Expected SessionError, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn invalid_argument_errors_map_correctly() {
        let cases = vec![
            RemoteClientError::InvalidPairingCode("bad code".to_string()),
            RemoteClientError::InvalidRendevouzCode("too short".to_string()),
            RemoteClientError::RendevouzResolutionFailed("not found".to_string()),
            RemoteClientError::InvalidState {
                expected: "Ready".to_string(),
                current: "Init".to_string(),
            },
        ];
        for err in cases {
            let mapped = RemoteAccessError::from(err);
            assert!(
                matches!(mapped, RemoteAccessError::InvalidArgument { .. }),
                "Expected InvalidArgument, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn timeout_maps_correctly() {
        let err = RemoteClientError::Timeout("5s elapsed".to_string());
        let mapped = RemoteAccessError::from(err);
        assert!(matches!(mapped, RemoteAccessError::Timeout { .. }));
        assert!(mapped.to_string().contains("5s elapsed"));
    }

    #[test]
    fn invalid_state_preserves_fields_in_message() {
        let err = RemoteClientError::InvalidState {
            expected: "Connected".to_string(),
            current: "Disconnected".to_string(),
        };
        let mapped = RemoteAccessError::from(err);
        let msg = mapped.to_string();
        assert!(msg.contains("Connected"));
        assert!(msg.contains("Disconnected"));
    }
}
