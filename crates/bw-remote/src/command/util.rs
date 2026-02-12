//! Shared utilities for CLI commands
//!
//! Contains helper functions used across multiple commands.

use bw_rat_client::{RemoteClientEvent, RemoteClientResponse};
use inquire::Confirm;
use tokio::sync::mpsc;
use tracing::info;

/// Handle and display RemoteClientEvent messages
///
/// # Panics
/// This function uses string slicing on hex-encoded fingerprints, which is safe
/// because hex encoding produces only ASCII characters.
#[allow(clippy::string_slice)]
pub async fn handle_event(
    event: &RemoteClientEvent,
    response_tx: &mpsc::Sender<RemoteClientResponse>,
) {
    match event {
        RemoteClientEvent::Connecting { proxy_url } => {
            info!("Connecting to proxy: {}", proxy_url);
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
            info!("Resolving rendezvous code: {}", code);
        }
        RemoteClientEvent::RendevouzResolved { fingerprint } => {
            let fp_hex = hex::encode(fingerprint.0);
            info!("Resolved to fingerprint: {}", fp_hex);
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
            info!("Handshake: {}", message);
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
            info!("Credential received for: {}", domain);
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
