//! CLI command definitions and dispatch
//!
//! This module organizes all CLI commands into separate submodules,
//! following the pattern used in the main Bitwarden CLI.

mod cache;
mod connect;
mod listen;
mod output;
pub(crate) mod tui;
mod util;

use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;

pub use cache::CacheCommands;
pub use connect::ConnectArgs;
pub use listen::ListenArgs;

const DEFAULT_PROXY_URL: &str = "ws://localhost:8080";

/// Bitwarden Remote Client CLI
#[derive(Parser)]
#[command(name = "bw-remote")]
#[command(author, version, about = "Connect to a user-client through a proxy to request credentials over a secure channel", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL, global = true)]
    pub proxy_url: String,

    /// Enable verbose output
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Connect to proxy and request credentials
    Connect(ConnectArgs),
    /// Listen for remote client connections (user-client mode)
    Listen(ListenArgs),
    /// Manage cached sessions
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
}

/// Process the parsed command and execute the appropriate handler
pub async fn process_command(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Connect(args) => args.run(&cli.proxy_url).await,
        Commands::Listen(args) => args.run(&cli.proxy_url).await,
        Commands::Cache { command } => command.run(),
    }
}
