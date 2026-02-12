//! Cache management commands
//!
//! Commands for managing the session cache:
//! - `clear-cache`: Clear all cached sessions
//! - `list-cache`: List all cached sessions
//!
//! NOTE: These commands are currently disabled because SessionCache
//! is now managed internally by RemoteClient and UserClient.

use clap::Args;
use color_eyre::eyre::Result;

/// Arguments for the clear-cache command
#[derive(Args)]
pub struct ClearCacheArgs;

impl ClearCacheArgs {
    /// Execute the clear-cache command
    pub fn run(self) -> Result<()> {
        println!("Cache management is now handled internally by the client.");
        println!("To disable caching, use the --no-cache flag with the connect command.");
        Ok(())
    }
}

/// Arguments for the list-cache command
#[derive(Args)]
pub struct ListCacheArgs;

impl ListCacheArgs {
    /// Execute the list-cache command
    pub fn run(self) -> Result<()> {
        println!("Cache management is now handled internally by the client.");
        println!("Session information is stored in ~/.bw-remote/");
        Ok(())
    }
}
