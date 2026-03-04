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

use output::OutputFormat;

pub use cache::CacheArgs;
pub use connect::ConnectArgs;
pub use listen::ListenArgs;

const DEFAULT_PROXY_URL: &str = "wss://rat1.lesspassword.dev";

/// Bitwarden Remote Client CLI
#[derive(Parser)]
#[command(name = "bw-remote")]
#[command(author, version, about = "Connect to a user-client through a proxy to request credentials over a secure channel", long_about = None)]
#[command(after_help = "\
AUTOMATION / AGENT / LLM USE:
  For non-interactive (single-shot) credential retrieval:

    1. List cached sessions:  bw-remote cache list
    2. Request a credential:  bw-remote --domain <DOMAIN> --session <HEX> --output json

  --session accepts a full 64-char hex fingerprint or any unique prefix from cache list.
  --output json returns structured JSON to stdout (status to stderr).
  Exit codes: 0=success, 1=error, 2=connection failed, 3=auth failed, 4=not found, 5=fingerprint mismatch")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL, global = true)]
    pub proxy_url: String,

    /// Token (rendezvous code or PSK token)
    #[arg(long)]
    pub token: Option<String>,

    /// Session fingerprint to reconnect to (hex string or unique prefix)
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

    /// Domain to request credentials for (single-shot, non-interactive)
    #[arg(long)]
    pub domain: Option<String>,

    /// Output format (text or json) for single-shot mode
    #[arg(long, default_value = "text", value_enum, global = true)]
    pub output: OutputFormat,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage the session cache
    Cache(CacheArgs),
    /// Connect to proxy and request credentials (default)
    Connect(ConnectArgs),
    /// Listen for remote client connections (user-client mode)
    Listen(ListenArgs),
}

/// Process the parsed command and execute the appropriate handler
pub async fn process_command(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::Cache(args)) => args.run(),
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
                domain: cli.domain,
                output: cli.output,
            };
            args.run().await
        }
    }
}
