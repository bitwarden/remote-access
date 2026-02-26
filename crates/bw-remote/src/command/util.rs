//! Shared utilities for CLI commands
//!
//! Contains helper functions used across multiple commands.

use std::time::{SystemTime, UNIX_EPOCH};

use bw_rat_client::{RemoteClientEvent, RemoteClientResponse};
use inquire::Confirm;
use tokio::sync::mpsc;

/// Format a Unix timestamp as relative time (e.g., "2 hours ago", "3 days ago")
pub fn format_relative_time(timestamp: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let diff = now.saturating_sub(timestamp);

    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        let minutes = diff / 60;
        format!(
            "{} minute{} ago",
            minutes,
            if minutes == 1 { "" } else { "s" }
        )
    } else if diff < 86400 {
        let hours = diff / 3600;
        format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
    } else if diff < 604800 {
        let days = diff / 86400;
        format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
    } else if diff < 2592000 {
        let weeks = diff / 604800;
        format!("{} week{} ago", weeks, if weeks == 1 { "" } else { "s" })
    } else {
        let months = diff / 2592000;
        format!("{} month{} ago", months, if months == 1 { "" } else { "s" })
    }
}

/// Handle and display RemoteClientEvent messages
///
/// When `verify_fingerprint` is true, the user is prompted to verify the fingerprint
/// and a `VerifyFingerprint` response is sent. When false, the fingerprint is displayed
/// informationally without prompting.
///
/// # Panics
/// This function uses string slicing on hex-encoded fingerprints, which is safe
/// because hex encoding produces only ASCII characters.
#[allow(clippy::string_slice)]
pub async fn handle_event(
    event: &RemoteClientEvent,
    response_tx: &mpsc::Sender<RemoteClientResponse>,
    verify_fingerprint: bool,
) {
    match event {
        RemoteClientEvent::Connecting { proxy_url } => {
            eprintln!("Connecting to proxy: {proxy_url}");
        }
        RemoteClientEvent::Connected { fingerprint } => {
            let fp_hex = hex::encode(fingerprint.0);
            println!(
                "Connected as device: {}...",
                &fp_hex[..16.min(fp_hex.len())]
            );
        }
        RemoteClientEvent::ReconnectingToSession { fingerprint } => {
            let fp_hex = hex::encode(fingerprint.0);
            println!(
                "Reconnecting to session: {}",
                &fp_hex[..12.min(fp_hex.len())]
            );
        }
        RemoteClientEvent::RendevouzResolving { code } => {
            eprintln!("Resolving rendezvous code: {code}");
        }
        RemoteClientEvent::RendevouzResolved { fingerprint } => {
            let fp_hex = hex::encode(fingerprint.0);
            eprintln!("Resolved to fingerprint: {fp_hex}");
        }
        RemoteClientEvent::PskMode { fingerprint } => {
            let fp_hex = hex::encode(fingerprint.0);
            println!(
                "Using PSK authentication to: {}",
                &fp_hex[..12.min(fp_hex.len())]
            );
        }
        RemoteClientEvent::HandshakeStart => {
            println!("Starting secure channel handshake...");
        }
        RemoteClientEvent::HandshakeProgress { message } => {
            eprintln!("Handshake: {message}");
        }
        RemoteClientEvent::HandshakeComplete => {
            println!("Secure channel established");
        }
        RemoteClientEvent::Ready { .. } => {
            // Handled in main loop
        }
        RemoteClientEvent::CredentialRequestSent { domain } => {
            println!("Requesting credential for: {domain}...");
        }
        RemoteClientEvent::CredentialReceived { domain, .. } => {
            eprintln!("Credential received for: {domain}");
        }
        RemoteClientEvent::Error { message, context } => {
            let ctx = context.as_deref().unwrap_or("unknown");
            println!("Error ({ctx}): {message}");
        }
        RemoteClientEvent::Disconnected { reason } => {
            let reason_str = reason.as_deref().unwrap_or("unknown");
            println!("Disconnected: {reason_str}");
        }
        RemoteClientEvent::HandshakeFingerprint { fingerprint } => {
            if verify_fingerprint {
                println!("\n========================================");
                println!("  SECURITY VERIFICATION REQUIRED");
                println!("========================================");
                println!("  Handshake Fingerprint: {fingerprint}");
                println!("========================================");
                println!("\nPlease compare this fingerprint with the");
                println!("one shown on the trusted device.");
                println!("They must match EXACTLY.\n");

                let approved = Confirm::new("Do the fingerprints match?")
                    .with_default(false)
                    .prompt()
                    .unwrap_or(false);

                response_tx
                    .send(RemoteClientResponse::VerifyFingerprint { approved })
                    .await
                    .ok();
            } else {
                println!("\n========================================");
                println!("  HANDSHAKE FINGERPRINT");
                println!("========================================");
                println!("  {fingerprint}");
                println!("========================================");
                println!("Compare this fingerprint with the one");
                println!("shown on the trusted device.\n");
            }
        }
        RemoteClientEvent::FingerprintVerified => {
            println!("✓ Fingerprint verified successfully!\n");
        }
        RemoteClientEvent::FingerprintRejected { reason } => {
            println!("✗ Fingerprint rejected: {reason}\n");
            println!("Connection aborted for security.\n");
        }
    }
}
