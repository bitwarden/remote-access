//! Cache management commands
//!
//! Commands for managing the session cache:
//! - `clear-cache`: Clear all cached sessions
//! - `list-cache`: List all cached sessions with fingerprints

use bw_rat_client::SessionStore;
use clap::Args;
use color_eyre::eyre::Result;

use super::util::format_relative_time;
use crate::storage::FileSessionCache;

/// Arguments for the clear-cache command
#[derive(Args)]
pub struct ClearCacheArgs;

impl ClearCacheArgs {
    /// Execute the clear-cache command
    pub fn run(self) -> Result<()> {
        let mut cache = FileSessionCache::load_or_create("remote_client")?;
        cache.clear()?;
        println!("Session cache cleared.");
        Ok(())
    }
}

/// Arguments for the list-cache command
#[derive(Args)]
pub struct ListCacheArgs;

impl ListCacheArgs {
    /// Execute the list-cache command
    pub fn run(self) -> Result<()> {
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
}
