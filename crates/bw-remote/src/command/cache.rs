//! Cache management commands
//!
//! Commands for managing the session cache:
//! - `cache clear`: Clear all cached sessions
//! - `cache list`: List all cached sessions with fingerprints

use bw_rat_client::SessionStore;
use clap::{Args, Subcommand};
use color_eyre::eyre::Result;

use super::util::format_relative_time;
use crate::storage::FileSessionCache;

/// Manage the session cache
#[derive(Args)]
pub struct CacheArgs {
    #[command(subcommand)]
    command: CacheCommands,
}

#[derive(Subcommand)]
enum CacheCommands {
    /// Clear all cached sessions
    Clear,
    /// List cached sessions
    List,
}

impl CacheArgs {
    pub fn run(self) -> Result<()> {
        match self.command {
            CacheCommands::Clear => clear_cache(),
            CacheCommands::List => list_cache(),
        }
    }
}

fn clear_cache() -> Result<()> {
    let mut cache = FileSessionCache::load_or_create("remote_client")?;
    cache.clear()?;
    println!("Session cache cleared.");
    Ok(())
}

fn list_cache() -> Result<()> {
    let cache = FileSessionCache::load_or_create("remote_client")?;
    let mut sessions = cache.list_sessions();

    if sessions.is_empty() {
        println!("No cached sessions.");
        return Ok(());
    }

    // Sort by last_connected descending (most recent first)
    sessions.sort_by(|a, b| b.3.cmp(&a.3));

    for (fingerprint, name, _cached_at, last_connected) in &sessions {
        let hex = hex::encode(fingerprint.0);
        let relative = format_relative_time(*last_connected);
        if let Some(name) = name {
            println!("{name}  {hex}  (last used: {relative})");
        } else {
            println!("{hex}  (last used: {relative})");
        }
    }

    Ok(())
}
