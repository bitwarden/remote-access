//! Connect command implementation
//!
//! Handles the interactive session for connecting to a proxy
//! and requesting credentials over a secure Noise Protocol channel.

use bw_noise_protocol::Psk;
use bw_proxy::ProxyClientConfig;
use bw_rat_client::{
    DefaultProxyClient, IdentityFingerprint, IdentityProvider, RemoteClient, SessionStore,
};
use clap::Args;
use color_eyre::eyre::{Result, bail};
use inquire::{Select, Text};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

use super::util::handle_event;
use crate::storage::{FileIdentityStorage, FileSessionCache};

const DEFAULT_PROXY_URL: &str = "ws://localhost:8080";

/// Arguments for the connect command
#[derive(Args)]
pub struct ConnectArgs {
    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL)]
    pub proxy_url: String,

    /// Token (rendezvous code or PSK token)
    #[arg(long)]
    pub token: Option<String>,

    /// Session fingerprint to reconnect to (hex string)
    #[arg(long)]
    pub session: Option<String>,

    /// Disable session caching
    #[arg(long)]
    pub no_cache: bool,
}

impl ConnectArgs {
    /// Execute the connect command
    pub async fn run(self) -> Result<()> {
        run_interactive_session(self.proxy_url, self.token, self.session, self.no_cache).await
    }
}

/// Connection mode for establishing a connection
enum ConnectionMode {
    /// New connection requiring rendezvous code pairing
    New { rendezvous_code: String },
    /// New connection using PSK authentication
    NewPsk {
        psk: Psk,
        remote_fingerprint: IdentityFingerprint,
    },
    /// Existing connection using cached remote fingerprint
    Existing {
        remote_fingerprint: IdentityFingerprint,
    },
}

/// Token type parsed from user input
enum TokenType {
    Rendezvous(String),
    Psk {
        psk: Psk,
        fingerprint: IdentityFingerprint,
    },
}

/// Parse a token (rendezvous code or PSK token)
fn parse_token(token: &str) -> Result<TokenType> {
    if token.contains('_') && token.len() == 129 {
        // PSK token: <64-char-hex>_<64-char-hex>
        let parts: Vec<&str> = token.split('_').collect();
        if parts.len() != 2 || parts[0].len() != 64 || parts[1].len() != 64 {
            bail!("Invalid PSK token format (expected 64-char hex + underscore + 64-char hex)");
        }

        let psk = Psk::from_hex(parts[0])
            .map_err(|e| color_eyre::eyre::eyre!("Invalid PSK in token: {}", e))?;
        let fingerprint = parse_fingerprint_hex(parts[1])?;

        Ok(TokenType::Psk { psk, fingerprint })
    } else {
        // Rendezvous code (6 chars)
        validate_rendezvous_code(token)?;
        Ok(TokenType::Rendezvous(token.to_string()))
    }
}

/// Run an interactive session for requesting credentials
async fn run_interactive_session(
    proxy_url: String,
    token: Option<String>,
    session_fingerprint: Option<String>,
    no_cache: bool,
) -> Result<()> {
    // Create identity provider and session store first
    let identity_provider = Box::new(FileIdentityStorage::load_or_generate("remote_client")?);
    let session_store = Box::new(FileSessionCache::load_or_create("remote_client")?);

    // Get cached sessions from session store
    let cached_sessions = session_store.list_sessions();

    // Determine connection mode
    let connection_mode = if let Some(session_hex) = session_fingerprint {
        // CLI flag for specific session
        let fingerprint = parse_fingerprint_hex(&session_hex)?;

        // Verify session exists
        if !cached_sessions.iter().any(|(fp, _, _)| *fp == fingerprint) {
            bail!("Session not found in cache: {}", session_hex);
        }

        ConnectionMode::Existing {
            remote_fingerprint: fingerprint,
        }
    } else if let Some(code_or_token) = token {
        // CLI flag for token (rendezvous or PSK)
        match parse_token(&code_or_token)? {
            TokenType::Rendezvous(code) => ConnectionMode::New {
                rendezvous_code: code,
            },
            TokenType::Psk { psk, fingerprint } => ConnectionMode::NewPsk {
                psk,
                remote_fingerprint: fingerprint,
            },
        }
    } else if !cached_sessions.is_empty() && !no_cache {
        // Interactive mode with cached sessions - show selection menu
        prompt_for_connection_choice(&cached_sessions)?
    } else {
        // No cached sessions or caching disabled - prompt for rendezvous code
        let code = prompt_for_rendezvous_code()?;
        ConnectionMode::New {
            rendezvous_code: code,
        }
    };

    println!("\nConnecting to proxy...");
    if no_cache {
        println!("Session caching disabled");
    } else {
        println!("Session caching enabled (use --no-cache to disable)");
    }
    println!("Establishing secure connection...\n");

    // Create event channels
    let (event_tx, mut event_rx) = mpsc::channel(32);
    let (response_tx, response_rx) = mpsc::channel(32);

    // Spawn event handler BEFORE connect (so Connecting/Connected events are handled)
    let event_handle = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            handle_event(&event, &response_tx).await;
        }
    });

    // Create proxy client
    let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
        proxy_url,
        identity_keypair: Some(identity_provider.identity().to_owned()),
    }));

    // Connect to proxy
    let mut client = RemoteClient::new(
        identity_provider,
        session_store,
        event_tx,
        response_rx,
        proxy_client,
    )
    .await
    .map_err(|e| color_eyre::eyre::eyre!("Connection to proxy failed: {}", e))?;

    // Phase 2: Perform pairing based on connection mode
    match connection_mode {
        ConnectionMode::New { rendezvous_code } => {
            if let Err(e) = client.pair_with_handshake(&rendezvous_code).await {
                bail!("Pairing failed: {}", e);
            }
        }
        ConnectionMode::NewPsk {
            psk,
            remote_fingerprint,
        } => {
            if let Err(e) = client.pair_with_psk(psk, remote_fingerprint).await {
                bail!("PSK pairing failed: {}", e);
            }
        }
        ConnectionMode::Existing { remote_fingerprint } => {
            if let Err(e) = client.load_cached_session(remote_fingerprint).await {
                bail!("Session reconnection failed: {}", e);
            }
        }
    }

    println!("\nConnection established! You can now request credentials.");
    println!("Enter a domain to request credentials, or 'exit' to quit.\n");

    // Credential request loop
    loop {
        let domain = Text::new("Domain (or 'exit'):")
            .prompt()
            .map_err(|e| color_eyre::eyre::eyre!("Input error: {}", e))?;

        let domain_lower = domain.to_lowercase();
        if domain_lower == "exit" || domain_lower == "quit" {
            break;
        }

        if domain.is_empty() {
            println!("Domain is required\n");
            continue;
        }

        match client.request_credential(&domain).await {
            Ok(credential) => {
                println!("\nCREDENTIAL RECEIVED");
                println!("  Domain: {domain}");
                if let Some(username) = &credential.username {
                    println!("  Username: {username}");
                }
                if let Some(password) = &credential.password {
                    println!("  Password: {password}");
                }
                if let Some(totp) = &credential.totp {
                    println!("  TOTP: {totp}");
                }
                if let Some(uri) = &credential.uri {
                    println!("  URI: {uri}");
                }
                println!();
            }
            Err(e) => {
                println!("Failed to get credential: {e}\n");
            }
        }
    }

    println!("\nClosing connection...");
    client.close().await;
    event_handle.abort();

    println!("Connection closed. Goodbye!");
    Ok(())
}

/// Prompt the user for a token (rendezvous code or PSK token) and validate it
fn prompt_for_rendezvous_code() -> Result<String> {
    let code = Text::new("Token (rendezvous code or PSK token):")
        .prompt()
        .map_err(|e| color_eyre::eyre::eyre!("Input error: {}", e))?;

    // Parse will validate it
    parse_token(&code)?;
    Ok(code)
}

/// Validate that a rendezvous code has the correct format
fn validate_rendezvous_code(code: &str) -> Result<()> {
    if code.is_empty() {
        bail!("Rendezvous code is required");
    }

    // Remove optional hyphen for validation
    let code_normalized = code.replace('-', "");

    if code_normalized.len() != 6 {
        bail!("Rendezvous code must be 6 characters (e.g., ABCD12 or ABCD-12)");
    }

    if !code_normalized.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("Rendezvous code must contain only letters and numbers");
    }

    Ok(())
}

/// Prompt user to choose between new connection or existing session
fn prompt_for_connection_choice(
    cached_sessions: &[(IdentityFingerprint, Option<String>, u64)],
) -> Result<ConnectionMode> {
    #[derive(Debug)]
    enum ConnectionChoice {
        New,
        Existing(IdentityFingerprint),
    }

    impl std::fmt::Display for ConnectionChoice {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ConnectionChoice::New => write!(f, "New connection (requires rendezvous code)"),
                ConnectionChoice::Existing(fp) => {
                    let short_hex = format!("{fp:?}").chars().take(6).collect::<String>();
                    write!(f, "Session {short_hex}")
                }
            }
        }
    }

    // Build options list
    let mut options = vec![ConnectionChoice::New];

    // Add cached sessions sorted by last_connected_at (most recent first)
    let mut sorted_sessions = cached_sessions.to_vec();
    sorted_sessions.sort_by(|a, b| b.2.cmp(&a.2));

    for (fingerprint, _, _last_connected_at) in sorted_sessions {
        options.push(ConnectionChoice::Existing(fingerprint));
    }

    // Create formatted display strings with relative time
    let display_options: Vec<String> = options
        .iter()
        .map(|choice| match choice {
            ConnectionChoice::New => "New connection (requires rendezvous code)".to_string(),
            ConnectionChoice::Existing(fp) => {
                let short_hex = format!("{fp:?}").chars().take(6).collect::<String>();
                let last_connected = cached_sessions
                    .iter()
                    .find(|(f, _, _)| f == fp)
                    .map(|(_, _, ts)| *ts)
                    .unwrap_or(0);
                let relative_time = format_relative_time(last_connected);
                format!("Session {short_hex} (last used: {relative_time})")
            }
        })
        .collect();

    // Show selection menu
    let selected_idx = Select::new("Select connection:", display_options.clone())
        .prompt()
        .and_then(|selection| {
            display_options
                .iter()
                .position(|s| *s == selection)
                .ok_or_else(|| inquire::InquireError::Custom("Invalid selection".into()))
        })
        .map_err(|e| color_eyre::eyre::eyre!("Selection error: {}", e))?;

    match &options[selected_idx] {
        ConnectionChoice::New => {
            let token_str = prompt_for_rendezvous_code()?;
            match parse_token(&token_str)? {
                TokenType::Rendezvous(code) => Ok(ConnectionMode::New {
                    rendezvous_code: code,
                }),
                TokenType::Psk { psk, fingerprint } => Ok(ConnectionMode::NewPsk {
                    psk,
                    remote_fingerprint: fingerprint,
                }),
            }
        }
        ConnectionChoice::Existing(fp) => Ok(ConnectionMode::Existing {
            remote_fingerprint: *fp,
        }),
    }
}

/// Format a Unix timestamp as relative time (e.g., "2 hours ago", "3 days ago")
fn format_relative_time(timestamp: u64) -> String {
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

/// Parse a fingerprint from hex string
#[allow(clippy::string_slice)]
fn parse_fingerprint_hex(hex: &str) -> Result<IdentityFingerprint> {
    // Remove any separators or whitespace
    let clean_hex = hex.replace(['-', ' ', ':'], "");

    if clean_hex.len() != 64 {
        bail!("Fingerprint must be 64 hex characters (32 bytes)");
    }

    // SAFETY: clean_hex is validated to be 64 hex characters (ASCII only),
    // so indexing at i*2 boundaries is safe.
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        let byte_str = &clean_hex[i * 2..i * 2 + 2];
        bytes[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| color_eyre::eyre::eyre!("Invalid hex string"))?;
    }

    Ok(IdentityFingerprint(bytes))
}
