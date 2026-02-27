//! CLI command definitions and dispatch
//!
//! This module organizes all CLI commands into separate submodules,
//! following the pattern used in the main Bitwarden CLI.

mod cache;
mod connect;
mod listen;
pub(crate) mod tui;
mod util;

use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;

pub use cache::{ClearCacheArgs, ListCacheArgs};
pub use connect::ConnectArgs;
pub use listen::ListenArgs;

const DEFAULT_PROXY_URL: &str = "ws://localhost:8080";

/// Bitwarden Remote Client CLI
#[derive(Parser)]
#[command(name = "bw-remote")]
#[command(author, version, about = "Connect to a user-client through a proxy to request credentials over a secure channel", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL, global = true)]
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

    /// Require fingerprint verification on the connect side
    #[arg(long)]
    pub verify_fingerprint: bool,

    /// Enable verbose output
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Clear all cached sessions
    ClearCache(ClearCacheArgs),
    /// List cached sessions
    ListCache(ListCacheArgs),
    /// Connect to proxy and request credentials (default)
    Connect(ConnectArgs),
    /// Listen for remote client connections (user-client mode)
    Listen(ListenArgs),
}

/// Process the parsed command and execute the appropriate handler
pub async fn process_command(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::ClearCache(args)) => args.run(),
        Some(Commands::ListCache(args)) => args.run(),
        Some(Commands::Connect(args)) => args.run().await,
        Some(Commands::Listen(args)) => args.run().await,
        None => {
            // Default: run interactive session with CLI-level args
            let args = ConnectArgs {
                proxy_url: cli.proxy_url,
                token: cli.token,
                session: cli.session,
                no_cache: cli.no_cache,
                verify_fingerprint: cli.verify_fingerprint,
            };
            args.run().await
        }
    }
}
