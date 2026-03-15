//! Output formatting for single-shot (non-interactive) mode
//!
//! Provides structured output for agent/LLM consumption: JSON or plain text,
//! with well-defined exit codes for programmatic error handling.

use bw_rat_client::{CredentialData, RemoteClientError};
use clap::ValueEnum;

/// Output format for single-shot mode
#[derive(Clone, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    /// Plain text key: value lines (default)
    #[default]
    Text,
    /// Single JSON object
    Json,
}

/// Process exit codes for programmatic consumption
pub mod exit_code {
    pub const SUCCESS: i32 = 0;
    pub const GENERAL_ERROR: i32 = 1;
    pub const CONNECTION_FAILED: i32 = 2;
    pub const AUTH_HANDSHAKE_FAILED: i32 = 3;
    pub const CREDENTIAL_NOT_FOUND: i32 = 4;
    pub const FINGERPRINT_MISMATCH: i32 = 5;
}

/// Map a `RemoteClientError` to the appropriate exit code
pub fn exit_code_for_error(err: &RemoteClientError) -> i32 {
    match err {
        RemoteClientError::ConnectionFailed(_) | RemoteClientError::WebSocket(_) => {
            exit_code::CONNECTION_FAILED
        }
        RemoteClientError::ProxyAuthFailed(_)
        | RemoteClientError::HandshakeFailed(_)
        | RemoteClientError::NoiseProtocol(_)
        | RemoteClientError::Timeout(_)
        | RemoteClientError::InvalidPairingCode(_)
        | RemoteClientError::RendevouzResolutionFailed(_)
        | RemoteClientError::InvalidRendevouzCode(_) => exit_code::AUTH_HANDSHAKE_FAILED,
        RemoteClientError::CredentialRequestFailed(_)
        | RemoteClientError::SecureChannelNotEstablished => exit_code::CREDENTIAL_NOT_FOUND,
        RemoteClientError::FingerprintRejected => exit_code::FINGERPRINT_MISMATCH,
        _ => exit_code::GENERAL_ERROR,
    }
}

/// Print a successful credential result as JSON to stdout
pub fn emit_json_success(domain: &str, credential: &CredentialData) {
    let obj = serde_json::json!({
        "success": true,
        "domain": domain,
        "credential": {
            "username": credential.username,
            "password": credential.password,
            "totp": credential.totp,
            "uri": credential.uri,
            "notes": credential.notes,
            "credential_id": credential.credential_id,
        }
    });
    println!("{obj}");
}

/// Print an error as JSON to stdout
pub fn emit_json_error(message: &str, code: &str) {
    let obj = serde_json::json!({
        "success": false,
        "error": {
            "message": message,
            "code": code,
        }
    });
    println!("{obj}");
}

/// Return the string code name for an exit code constant
pub fn exit_code_name(code: i32) -> &'static str {
    match code {
        exit_code::SUCCESS => "success",
        exit_code::CONNECTION_FAILED => "connection_failed",
        exit_code::AUTH_HANDSHAKE_FAILED => "auth_handshake_failed",
        exit_code::CREDENTIAL_NOT_FOUND => "credential_not_found",
        exit_code::FINGERPRINT_MISMATCH => "fingerprint_mismatch",
        _ => "general_error",
    }
}

/// Print a credential result as plain text key: value lines to stdout
pub fn emit_text_credential(domain: &str, credential: &CredentialData) {
    println!("domain: {domain}");
    if let Some(username) = &credential.username {
        println!("username: {username}");
    }
    if let Some(password) = &credential.password {
        println!("password: {password}");
    }
    if let Some(totp) = &credential.totp {
        println!("totp: {totp}");
    }
    if let Some(uri) = &credential.uri {
        println!("uri: {uri}");
    }
    if let Some(notes) = &credential.notes {
        println!("notes: {notes}");
    }
    if let Some(credential_id) = &credential.credential_id {
        println!("credential_id: {credential_id}");
    }
}
