//! Cache management commands
//!
//! Commands for managing the session cache:
//! - `cache clear`: Clear all cached sessions
//! - `cache list`: List all cached sessions with fingerprints

use bw_rat_client::SessionStore;
use clap::Subcommand;
use color_eyre::eyre::Result;

use super::util::format_relative_time;
use crate::storage::FileSessionCache;

/// Cache management subcommands
#[derive(Subcommand)]
pub enum CacheCommands {
    /// List all cached sessions
    List,
    /// Clear all cached sessions
    Clear,
}

impl CacheCommands {
    /// Execute the cache subcommand
    pub fn run(self) -> Result<()> {
        match self {
            CacheCommands::List => {
                let cache = FileSessionCache::load_or_create("remote_client")?;
                let mut sessions = cache.list_sessions();

                if sessions.is_empty() {
                    println!("No cached sessions.");
                    return Ok(());
                }

                // Sort by last_connected descending (most recent first)
                sessions.sort_by(|a, b| b.3.cmp(&a.3));

                for (fingerprint, _name, _cached_at, last_connected) in &sessions {
                    let hex = hex::encode(fingerprint.0);
                    let relative = format_relative_time(*last_connected);
                    println!("{hex}  (last used: {relative})");
                }

                Ok(())
            }
            CacheCommands::Clear => {
                let mut cache = FileSessionCache::load_or_create("remote_client")?;
                cache.clear()?;
                println!("Session cache cleared.");
                Ok(())
            }
        }
    }
}
