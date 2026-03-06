use crate::{Identity, IdentityFingerprint, RendevouzCode};

/// Messages received by the client from the proxy server.
#[derive(Debug, Clone)]
pub enum IncomingMessage {
    /// Server responded with a rendezvous code.
    RendevouzInfo(RendevouzCode),

    /// Server responded with a peer's identity.
    IdentityInfo {
        /// SHA256 fingerprint of the peer's identity
        fingerprint: IdentityFingerprint,
        /// The peer's full public identity
        identity: Identity,
    },

    /// Received a message from another client.
    Send {
        /// The sender's fingerprint (validated by proxy)
        source: IdentityFingerprint,
        /// Your fingerprint (the recipient)
        destination: IdentityFingerprint,
        /// Arbitrary message payload (should be encrypted by clients)
        payload: Vec<u8>,
    },
}
