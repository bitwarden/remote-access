//! Connection management commands
//!
//! Commands for managing connections and identity keys:
//! - `connections list`: List cached sessions and identity fingerprints
//! - `connections clear [sessions|all]`: Clear cached sessions and/or identity keys

use ap_client::SessionStore;
use clap::{Args, Subcommand, ValueEnum};
use color_eyre::eyre::Result;
use crossterm::style::Stylize;

use super::color_choice;
use super::util::format_relative_time;
use crate::storage::{FileIdentityStorage, FileSessionCache};

/// Apply a style function only when color is enabled, otherwise return the plain string.
fn styled(s: &str, style_fn: impl FnOnce(&str) -> crossterm::style::StyledContent<&str>) -> String {
    if matches!(color_choice(), clap::ColorChoice::Auto) {
        format!("{}", style_fn(s))
    } else {
        s.to_string()
    }
}

fn bold(s: &str) -> String {
    styled(s, |s| s.bold())
}

fn grey(s: &str) -> String {
    styled(s, |s| s.grey())
}

fn cyan(s: &str) -> String {
    styled(s, |s| s.cyan())
}

fn cyan_bold(s: &str) -> String {
    styled(s, |s| s.cyan().bold())
}

/// Which client type to operate on
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ClientType {
    /// Only the remote (connect) side
    Remote,
    /// Only the user (listen) side
    User,
}

/// What to clear
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum ClearScope {
    /// Clear sessions only (keep identity key)
    Sessions,
    /// Clear sessions and delete identity key
    #[default]
    All,
}

/// Manage connections
#[derive(Args)]
pub struct ConnectionsArgs {
    #[command(subcommand)]
    command: ConnectionsCommands,

    /// Limit to a specific client type (omit for both)
    #[arg(long, global = true)]
    client_type: Option<ClientType>,
}

#[derive(Subcommand)]
enum ConnectionsCommands {
    /// Clear cached sessions and/or identity keys
    Clear {
        /// What to clear: "sessions" (keep identity key) or "all" (sessions + identity key)
        #[arg(default_value = "all")]
        scope: ClearScope,
    },
    /// List cached sessions and identity info
    List,
}

impl ConnectionsArgs {
    pub async fn run(self) -> Result<()> {
        match self.command {
            ConnectionsCommands::Clear { scope } => clear_cache(self.client_type, scope).await,
            ConnectionsCommands::List => list_cache(self.client_type).await,
        }
    }
}

/// Describes one client side for display and storage lookup
struct CacheSide {
    label: &'static str,
    description: &'static str,
    storage_name: &'static str,
}

const REMOTE_SIDE: CacheSide = CacheSide {
    label: "Remote Client",
    description: "connect",
    storage_name: "remote_client",
};

const USER_SIDE: CacheSide = CacheSide {
    label: "User Client",
    description: "listen",
    storage_name: "user_client",
};

fn sides_for(client_type: Option<ClientType>) -> Vec<&'static CacheSide> {
    match client_type {
        Some(ClientType::Remote) => vec![&REMOTE_SIDE],
        Some(ClientType::User) => vec![&USER_SIDE],
        None => vec![&REMOTE_SIDE, &USER_SIDE],
    }
}

async fn clear_cache(client_type: Option<ClientType>, scope: ClearScope) -> Result<()> {
    let sides = sides_for(client_type);

    for side in &sides {
        // Always clear sessions
        let mut cache = FileSessionCache::load_or_create(side.storage_name)?;
        cache.clear().await?;
        println!(
            "{} ({}) session cache cleared.",
            side.label, side.description
        );

        // Clear identity key if scope is All
        if matches!(scope, ClearScope::All) {
            FileIdentityStorage::delete(side.storage_name)?;
            println!(
                "{} ({}) identity key deleted.",
                side.label, side.description
            );
        }
    }

    Ok(())
}

async fn list_cache(client_type: Option<ClientType>) -> Result<()> {
    let sides = sides_for(client_type);
    for (i, side) in sides.iter().enumerate() {
        if i > 0 {
            println!();
        }

        // Section header
        println!(
            "{}",
            bold(&format!(
                "── {} (ap-cli {}) ──",
                side.label, side.description
            ))
        );

        // Load identity fingerprint (if key exists)
        let fingerprint = FileIdentityStorage::load_fingerprint(side.storage_name)?;
        match &fingerprint {
            Some(fp) => println!("  {}: {}", grey("Your identity"), cyan(&hex::encode(fp.0))),
            None => println!(
                "  {}: {}",
                grey("Your identity"),
                grey("(none — no keypair generated yet)")
            ),
        };

        // Load and display sessions
        let cache = FileSessionCache::load_or_create(side.storage_name)?;
        let mut sessions = cache.list().await;

        if sessions.is_empty() {
            println!("  {}: {}", grey("Connections"), grey("(none)"));
        } else {
            sessions.sort_by(|a, b| b.last_connected_at.cmp(&a.last_connected_at));
            println!(
                "  {}: ({} peer{})",
                grey("Connections"),
                sessions.len(),
                if sessions.len() == 1 { "" } else { "s" }
            );
            for session in &sessions {
                let fp = hex::encode(session.fingerprint.0);
                let paired_ago = format_relative_time(session.cached_at);
                let used_ago = format_relative_time(session.last_connected_at);
                if let Some(name) = &session.name {
                    println!("    {} {} {}", grey("-"), cyan_bold(name), grey(&fp));
                } else {
                    println!("    {} {}", grey("-"), cyan(&fp));
                }
                println!(
                    "      {} {}  {}  {} {}",
                    grey("Paired:"),
                    paired_ago,
                    grey("|"),
                    grey("Last used:"),
                    used_ago
                );
            }
        }
    }

    Ok(())
}
