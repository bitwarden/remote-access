//! Protocol message types for client-proxy communication.
//!
//! This module defines the message types used in the three-phase protocol:
//!
//! # Message Flow
//!
//! ## Phase 1: Authentication
//! 1. Server → Client: [`Messages::AuthChallenge`] - Random challenge for the client to sign
//! 2. Client → Server: [`Messages::AuthResponse`] - Client's identity and signature
//!
//! ## Phase 2: Rendezvous (Optional)
//! 3. Client → Server: [`Messages::GetRendevouz`] - Request a temporary code
//! 4. Server → Client: [`Messages::RendevouzInfo`] - The generated code (e.g., "ABC-DEF")
//! 5. Client → Server: [`Messages::GetIdentity`] - Look up identity by code
//! 6. Server → Client: [`Messages::IdentityInfo`] - The identity associated with the code
//!
//! ## Phase 3: Messaging
//! 7. Client → Server: [`Messages::Send`] - Client sends message (destination + payload only)
//! 8. Server → Client: [`Messages::Send`] - Server forwards with validated source added
//!
//! All messages are serialized as JSON over WebSocket connections.

use crate::{
    auth::{Challenge, ChallengeResponse, Identity, IdentityFingerprint},
    rendevouz::RendevouzCode,
};
use serde::{Deserialize, Serialize};

/// Protocol messages exchanged between clients and the proxy server.
///
/// Messages flow through three distinct phases: authentication, optional rendezvous
/// for peer discovery, and message routing between authenticated clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Messages {
    /// Server sends a random challenge to a newly connected client.
    ///
    /// The client must sign this challenge with its private key to authenticate.
    /// Sent immediately after WebSocket connection establishment.
    AuthChallenge(Challenge),

    /// Client responds to authentication challenge with identity and signature.
    ///
    /// Contains the client's public [`Identity`] and a [`ChallengeResponse`] (signature).
    /// The server verifies the signature to authenticate the client.
    AuthResponse(Identity, ChallengeResponse),

    /// Client requests a temporary rendezvous code.
    ///
    /// The server will generate a unique code (format: "ABC-DEF") and send it back
    /// via [`Messages::RendevouzInfo`]. The code expires after 5 minutes.
    GetRendevouz,

    /// Server responds with the generated rendezvous code.
    ///
    /// The code can be shared with other clients to enable them to discover
    /// this client's identity via [`Messages::GetIdentity`].
    RendevouzInfo(RendevouzCode),

    /// Client looks up an identity using a rendezvous code.
    ///
    /// If the code is valid and hasn't expired, the server responds with
    /// [`Messages::IdentityInfo`]. Codes are single-use and deleted after lookup.
    GetIdentity(RendevouzCode),

    /// Server responds with the identity associated with a rendezvous code.
    ///
    /// Contains both the [`IdentityFingerprint`] (SHA256 hash) and full [`Identity`]
    /// (public key). After sending this, the rendezvous code is deleted.
    IdentityInfo {
        /// SHA256 fingerprint of the identity's public key
        fingerprint: IdentityFingerprint,
        /// The full public identity (MlDsa65 public key)
        identity: Identity,
    },

    /// A message routed from one client to another through the proxy.
    ///
    /// When sent by clients, only contains destination and payload. The source is
    /// automatically set by the proxy based on the authenticated identity.
    /// When forwarded to recipients, includes the validated source fingerprint.
    Send {
        /// The authenticated sender's fingerprint (added by proxy)
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<IdentityFingerprint>,
        /// The recipient's fingerprint
        destination: IdentityFingerprint,
        /// Arbitrary payload data (should be encrypted by clients)
        payload: Vec<u8>,
    },
}
