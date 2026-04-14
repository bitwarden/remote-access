/// FFI-friendly error enum that maps the internal ClientError
/// into 6 categories suitable for cross-language consumption.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ClientError {
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

impl From<ap_client::ClientError> for ClientError {
    fn from(err: ap_client::ClientError) -> Self {
        let message = err.to_string();
        match err {
            ap_client::ClientError::ConnectionFailed(_) | ap_client::ClientError::WebSocket(_) => {
                ClientError::ConnectionFailed { message }
            }

            ap_client::ClientError::ProxyAuthFailed(_)
            | ap_client::ClientError::HandshakeFailed(_)
            | ap_client::ClientError::NoiseProtocol(_)
            | ap_client::ClientError::FingerprintRejected => {
                ClientError::HandshakeFailed { message }
            }

            ap_client::ClientError::CredentialRequestFailed(_)
            | ap_client::ClientError::SecureChannelNotEstablished
            | ap_client::ClientError::NotInitialized => {
                ClientError::CredentialRequestFailed { message }
            }

            ap_client::ClientError::ConnectionCache(_)
            | ap_client::ClientError::IdentityStorageFailed(_)
            | ap_client::ClientError::KeypairStorage(_)
            | ap_client::ClientError::ConnectionNotFound
            | ap_client::ClientError::Serialization(_)
            | ap_client::ClientError::ChannelClosed => ClientError::SessionError { message },

            ap_client::ClientError::InvalidPairingCode(_)
            | ap_client::ClientError::InvalidRendezvousCode(_)
            | ap_client::ClientError::RendezvousResolutionFailed(_)
            | ap_client::ClientError::InvalidState { .. } => {
                ClientError::InvalidArgument { message }
            }

            ap_client::ClientError::Timeout(_) => ClientError::Timeout { message },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_failed_maps_correctly() {
        let err = ap_client::ClientError::ConnectionFailed("refused".to_string());
        let mapped = ClientError::from(err);
        assert!(matches!(mapped, ClientError::ConnectionFailed { .. }));
        assert!(mapped.to_string().contains("refused"));
    }

    #[test]
    fn websocket_error_maps_to_connection_failed() {
        let err = ap_client::ClientError::WebSocket("closed".to_string());
        let mapped = ClientError::from(err);
        assert!(matches!(mapped, ClientError::ConnectionFailed { .. }));
    }

    #[test]
    fn handshake_errors_map_correctly() {
        let cases = vec![
            ap_client::ClientError::ProxyAuthFailed("bad auth".to_string()),
            ap_client::ClientError::HandshakeFailed("noise error".to_string()),
            ap_client::ClientError::NoiseProtocol("decrypt failed".to_string()),
            ap_client::ClientError::FingerprintRejected,
        ];
        for err in cases {
            let mapped = ClientError::from(err);
            assert!(
                matches!(mapped, ClientError::HandshakeFailed { .. }),
                "Expected HandshakeFailed, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn credential_errors_map_correctly() {
        let cases = vec![
            ap_client::ClientError::CredentialRequestFailed("denied".to_string()),
            ap_client::ClientError::SecureChannelNotEstablished,
            ap_client::ClientError::NotInitialized,
        ];
        for err in cases {
            let mapped = ClientError::from(err);
            assert!(
                matches!(mapped, ClientError::CredentialRequestFailed { .. }),
                "Expected CredentialRequestFailed, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn session_errors_map_correctly() {
        let cases = vec![
            ap_client::ClientError::ConnectionCache("corrupt".to_string()),
            ap_client::ClientError::IdentityStorageFailed("missing".to_string()),
            ap_client::ClientError::KeypairStorage("bad key".to_string()),
            ap_client::ClientError::ConnectionNotFound,
            ap_client::ClientError::Serialization("invalid json".to_string()),
            ap_client::ClientError::ChannelClosed,
        ];
        for err in cases {
            let mapped = ClientError::from(err);
            assert!(
                matches!(mapped, ClientError::SessionError { .. }),
                "Expected SessionError, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn invalid_argument_errors_map_correctly() {
        let cases = vec![
            ap_client::ClientError::InvalidPairingCode("bad code".to_string()),
            ap_client::ClientError::InvalidRendezvousCode("too short".to_string()),
            ap_client::ClientError::RendezvousResolutionFailed("not found".to_string()),
            ap_client::ClientError::InvalidState {
                expected: "Ready".to_string(),
                current: "Init".to_string(),
            },
        ];
        for err in cases {
            let mapped = ClientError::from(err);
            assert!(
                matches!(mapped, ClientError::InvalidArgument { .. }),
                "Expected InvalidArgument, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn timeout_maps_correctly() {
        let err = ap_client::ClientError::Timeout("5s elapsed".to_string());
        let mapped = ClientError::from(err);
        assert!(matches!(mapped, ClientError::Timeout { .. }));
        assert!(mapped.to_string().contains("5s elapsed"));
    }

    #[test]
    fn invalid_state_preserves_fields_in_message() {
        let err = ap_client::ClientError::InvalidState {
            expected: "Connected".to_string(),
            current: "Disconnected".to_string(),
        };
        let mapped = ClientError::from(err);
        let msg = mapped.to_string();
        assert!(msg.contains("Connected"));
        assert!(msg.contains("Disconnected"));
    }
}
