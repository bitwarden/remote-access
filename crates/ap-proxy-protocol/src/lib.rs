//! Shared wire protocol types for the ap-proxy WebSocket server.
//!
//! This crate contains the protocol types used by both the proxy server
//! and proxy client, with zero TLS dependencies.

pub mod auth;
pub mod error;
pub mod messages;
pub mod rendevouz;

pub use auth::{
    Challenge, ChallengeResponse, Identity, IdentityFingerprint, IdentityKeyPair,
    SignatureAlgorithm,
};
pub use error::ProxyError;
pub use messages::Messages;
pub use rendevouz::RendevouzCode;
