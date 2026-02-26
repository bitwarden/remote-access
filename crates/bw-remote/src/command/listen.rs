//! Listen command implementation
//!
//! Handles the user-client (trusted device) mode for receiving and
//! approving connection requests from remote clients.

use std::process::Command;

use bw_proxy::ProxyClientConfig;
use bw_rat_client::{
    DefaultProxyClient, IdentityProvider, SessionStore, UserClient, UserClientEvent,
    UserClientResponse, UserCredentialData,
};
use clap::Args;
use color_eyre::eyre::{Result, bail};
use inquire::Confirm;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::info;

use super::util::format_relative_time;
use crate::storage::{FileIdentityStorage, FileSessionCache};

const DEFAULT_PROXY_URL: &str = "ws://localhost:8080";

/// Arguments for the listen command
#[derive(Args)]
pub struct ListenArgs {
    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL)]
    pub proxy_url: String,

    /// Use PSK (Pre-Shared Key) mode instead of rendezvous code
    #[arg(long)]
    pub psk: bool,
}

impl ListenArgs {
    /// Execute the listen command
    pub async fn run(self) -> Result<()> {
        // Run interactive session
        run_user_client_session(self.proxy_url, self.psk).await
    }
}

/// Bitwarden CLI login item structure
#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwUri>>,
}

/// Bitwarden CLI URI structure
#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

/// Bitwarden CLI item structure
#[derive(Deserialize)]
struct BwItem {
    login: Option<BwLogin>,
}

/// Look up a credential from the Bitwarden CLI
fn lookup_credential(domain: &str) -> Option<UserCredentialData> {
    // Try to find bw on PATH first, then fall back to homebrew location
    let bw_path = which_bw().unwrap_or_else(|| "/opt/homebrew/bin/bw".to_string());

    let output = Command::new(&bw_path)
        .args(["get", "item", domain])
        .output()
        .ok()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("Not found") {
            info!("bw get item failed: {}", stderr);
        }
        return None;
    }

    let item: BwItem = serde_json::from_slice(&output.stdout).ok()?;
    let login = item.login?;

    // Get the first URI if available
    let uri = login
        .uris
        .as_ref()
        .and_then(|uris| uris.first())
        .and_then(|u| u.uri.clone());

    Some(UserCredentialData {
        username: login.username,
        password: login.password,
        totp: login.totp,
        uri,
        notes: None,
    })
}

/// Find bw executable on PATH
fn which_bw() -> Option<String> {
    Command::new("which")
        .arg("bw")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Run the user client interactive session
async fn run_user_client_session(proxy_url: String, psk_mode: bool) -> Result<()> {
    let local = tokio::task::LocalSet::new();

    local
        .run_until(async move {
            // Create channels for communication
            let (event_tx, mut event_rx) = mpsc::channel(32);
            let (response_tx, response_rx) = mpsc::channel(32);

            // Create identity provider and session store
            let identity_provider = Box::new(FileIdentityStorage::load_or_generate("user_client")?);
            let session_store = Box::new(FileSessionCache::load_or_create("user_client")?);

            // Check for cached sessions and prompt user
            let cached_sessions = session_store.list_sessions();
            let generate_new_code = if !cached_sessions.is_empty() {
                // Display cached sessions
                println!(
                    "Found {} cached session(s):\n",
                    cached_sessions.len()
                );

                let mut sorted_sessions = cached_sessions.clone();
                sorted_sessions.sort_by(|a, b| b.2.cmp(&a.2));

                for (fingerprint, _, last_connected_at) in &sorted_sessions {
                    let short_hex = hex::encode(fingerprint.0)
                        .chars()
                        .take(12)
                        .collect::<String>();
                    let relative_time = format_relative_time(*last_connected_at);
                    println!("  Session {short_hex}  (last used: {relative_time})");
                }
                println!();

                // Prompt user whether to generate a new connection code
                Confirm::new("Generate a new connection code for additional devices?")
                    .with_default(false)
                    .prompt()
                    .unwrap_or(false)
            } else {
                // No cached sessions - always generate a new code
                true
            };

            // Create proxy client
            let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
                proxy_url,
                identity_keypair: Some(identity_provider.identity().to_owned()),
            }));

            // Start the client listener in the background
            let client_handle = tokio::task::spawn_local(async move {
                let mut client =
                    UserClient::listen(identity_provider, session_store, proxy_client).await?;

                if generate_new_code {
                    if psk_mode {
                        client.enable_psk(event_tx, response_rx).await
                    } else {
                        client.enable_rendezvous(event_tx, response_rx).await
                    }
                } else {
                    client.listen_cached_only(event_tx, response_rx).await
                }
            });

            // Handle events from the client
            println!("Starting user client...\n");

            while let Some(event) = event_rx.recv().await {
                match event {
                    UserClientEvent::Listening {} => {
                        if !generate_new_code {
                            println!("Listening for cached sessions only...");
                            println!("(Press Ctrl+C to exit)\n");
                        }
                    }

                    UserClientEvent::RendevouzCodeGenerated { code } => {
                        info!("");
                        info!("╔════════════════════════════════════════╗");
                        info!("║  Your Rendezvous Code: {}  ║", code);
                        info!("╚════════════════════════════════════════╝");
                        info!("");
                        info!("Share this code with the remote device to connect.");
                        println!("\n========================================");
                        println!("  RENDEZVOUS CODE");
                        println!("========================================");
                        println!("  {code}");
                        println!("========================================\n");
                        println!("Share this code with your remote device.");
                        println!("The remote client will need this code to connect.\n");
                        println!("Waiting for remote clients...");
                        println!("(Press Ctrl+C to exit)\n");
                    }

                    UserClientEvent::PskTokenGenerated { token } => {
                        println!("\n========================================");
                        println!("  PSK TOKEN (COPY ENTIRE TOKEN)");
                        println!("========================================");
                        println!("  {token}");
                        println!("========================================\n");
                        println!("Share this token securely with the remote device.");
                        println!("Waiting for remote clients...");
                        println!("(Press Ctrl+C to exit)\n");
                    }

                    UserClientEvent::HandshakeStart {} => {
                        println!("Noise handshake started");
                    }

                    UserClientEvent::HandshakeProgress { message } => {
                        info!("Handshake progress: {}", message);
                    }

                    UserClientEvent::HandshakeComplete {} => {
                        println!("Secure channel established");
                    }

                    UserClientEvent::HandshakeFingerprint { fingerprint } => {
                        println!("\n========================================");
                        println!("  HANDSHAKE FINGERPRINT");
                        println!("========================================");
                        println!("  {fingerprint}");
                        println!("========================================");
                        println!("Compare this fingerprint with the one");
                        println!("shown on the remote device.\n");
                    }

                    UserClientEvent::CredentialRequest {
                        domain,
                        request_id,
                        session_id,
                    } => {
                        println!("\n--- Credential Request ---");
                        println!("  Domain: {domain}");

                        // Look up credential from Bitwarden CLI
                        match lookup_credential(&domain) {
                            Some(credential) => {
                                println!(
                                    "  Found: {} ({})",
                                    credential.username.as_deref().unwrap_or("no username"),
                                    credential.uri.as_deref().unwrap_or("no uri")
                                );
                                println!();

                                let approved =
                                    Confirm::new(&format!("Send credential for {domain}?"))
                                        .with_default(false)
                                        .prompt()
                                        .unwrap_or(false);

                                if approved {
                                    response_tx
                                        .send(UserClientResponse::RespondCredential {
                                            request_id,
                                            session_id: session_id.clone(),
                                            approved: true,
                                            credential: Some(credential),
                                        })
                                        .await
                                        .ok();

                                    println!("Credential sent for {domain}\n");
                                } else {
                                    response_tx
                                        .send(UserClientResponse::RespondCredential {
                                            request_id,
                                            session_id: session_id.clone(),
                                            approved: false,
                                            credential: None,
                                        })
                                        .await
                                        .ok();

                                    println!("Credential denied for {domain}\n");
                                }
                            }
                            None => {
                                println!("  No credential found in vault");
                                println!();

                                response_tx
                                    .send(UserClientResponse::RespondCredential {
                                        request_id,
                                        session_id,
                                        approved: false,
                                        credential: None,
                                    })
                                    .await
                                    .ok();

                                println!("No credential available for {domain}\n");
                            }
                        }
                    }

                    UserClientEvent::CredentialApproved { domain } => {
                        info!("Credential approved: {}", domain);
                    }

                    UserClientEvent::CredentialDenied { domain } => {
                        info!("Credential denied: {}", domain);
                    }

                    UserClientEvent::ClientDisconnected {} => {
                        println!("Client disconnected");
                    }

                    UserClientEvent::Error { message, context } => {
                        let ctx = context.as_deref().unwrap_or("unknown");
                        println!("Error ({ctx}): {message}");
                    }
                }
            }

            // Wait for client task to complete
            match client_handle.await {
                Ok(Ok(())) => {
                    println!("\nUser client session ended.");
                    Ok(())
                }
                Ok(Err(e)) => {
                    bail!("User client error: {}", e);
                }
                Err(e) => {
                    bail!("Task error: {}", e);
                }
            }
        })
        .await
}
