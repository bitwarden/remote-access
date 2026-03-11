//! Connection management commands
//!
//! Commands for managing connections and identity keys:
//! - `connections list`: List cached sessions and identity fingerprints
//! - `connections clear [sessions|all]`: Clear cached sessions and/or identity keys

use bw_rat_client::SessionStore;
use clap::{Args, Subcommand, ValueEnum};
use color_eyre::eyre::Result;

use super::util::format_relative_time;
use crate::storage::{FileIdentityStorage, FileSessionCache};

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
    pub fn run(self) -> Result<()> {
        match self.command {
            ConnectionsCommands::Clear { scope } => clear_cache(self.client_type, scope),
            ConnectionsCommands::List => list_cache(self.client_type),
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
    label: "Remote",
    description: "connect",
    storage_name: "remote_client",
};

const USER_SIDE: CacheSide = CacheSide {
    label: "User",
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

fn clear_cache(client_type: Option<ClientType>, scope: ClearScope) -> Result<()> {
    let sides = sides_for(client_type);

    for side in &sides {
        // Always clear sessions
        let mut cache = FileSessionCache::load_or_create(side.storage_name)?;
        cache.clear()?;
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

fn list_cache(client_type: Option<ClientType>) -> Result<()> {
    let sides = sides_for(client_type);
    for (i, side) in sides.iter().enumerate() {
        if i > 0 {
            println!();
        }

        // Load identity fingerprint (if key exists)
        let fingerprint = FileIdentityStorage::load_fingerprint(side.storage_name)?;
        let fp_display = match &fingerprint {
            Some(fp) => hex::encode(fp.0),
            None => "no identity key".to_string(),
        };

        println!(
            "{} ({}) \u{2014} identity: {}",
            side.label, side.description, fp_display
        );

        // Load and display sessions
        let cache = FileSessionCache::load_or_create(side.storage_name)?;
        let mut sessions = cache.list_sessions();

        if sessions.is_empty() {
            println!("  No cached sessions.");
        } else {
            sessions.sort_by(|a, b| b.3.cmp(&a.3));
            for (session_fp, name, _cached_at, last_connected) in &sessions {
                let hex = hex::encode(session_fp.0);
                let relative = format_relative_time(*last_connected);
                if let Some(name) = name {
                    println!("  {name}  {hex}  (last used: {relative})");
                } else {
                    println!("  {hex}  (last used: {relative})");
                }
            }
        }
    }

    Ok(())
}
