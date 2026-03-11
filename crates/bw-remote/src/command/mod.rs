//! CLI command definitions and dispatch
//!
//! This module organizes all CLI commands into separate submodules,
//! following the pattern used in the main Bitwarden CLI.

mod connect;
mod connections;
mod listen;
mod output;
pub(crate) mod tui;
mod util;

use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{ColorChoice, CommandFactory, Parser, Subcommand};
use color_eyre::eyre::Result;

use output::OutputFormat;

pub use connect::ConnectArgs;
pub use connections::ConnectionsArgs;
pub use listen::ListenArgs;

const DEFAULT_PROXY_URL: &str = "wss://rat1.lesspassword.dev";

/// Determine color choice: disabled when `LLM` or `NO_COLOR` is set,
/// otherwise auto-detect.
pub fn color_choice() -> ColorChoice {
    let llm = std::env::var("LLM").is_ok();
    let no_color = std::env::var("NO_COLOR").is_ok();
    if llm || no_color {
        ColorChoice::Never
    } else {
        ColorChoice::Auto
    }
}

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Green.on_default())
    .valid(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .invalid(AnsiColor::Red.on_default().effects(Effects::BOLD))
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD));

/// Bitwarden Remote Client CLI
#[derive(Parser)]
#[command(name = "bw-remote")]
#[command(author, version, about = "Retrieve credentials from your password manager over a secure channel", long_about = None)]
#[command(styles = STYLES)]
#[command(after_help = "\
AUTOMATION / AGENT / LLM USE:
  For non-interactive (single-shot) credential retrieval:

    1. List cached sessions:  bw-remote connections list
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

    /// Don't save this connection for future use
    #[arg(long)]
    pub ephemeral_connection: bool,

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
    /// Connect to proxy and request credentials
    Connect(ConnectArgs),
    /// Listen for remote client connections (user-client mode)
    Listen(ListenArgs),
    /// Manage connections
    Connections(ConnectionsArgs),
}

/// Process the parsed command and execute the appropriate handler
pub async fn process_command(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Commands::Connections(args)) => args.run(),
        Some(Commands::Connect(args)) => args.run().await,
        Some(Commands::Listen(args)) => args.run().await,
        None if cli.domain.is_some() || cli.token.is_some() || cli.session.is_some() => {
            // Single-shot / shorthand connect with top-level args
            let args = ConnectArgs {
                proxy_url: cli.proxy_url,
                token: cli.token,
                session: cli.session,
                ephemeral_connection: cli.ephemeral_connection,
                verify_fingerprint: cli.verify_fingerprint,
                domain: cli.domain,
                output: cli.output,
            };
            args.run().await
        }
        None => {
            // No subcommand and no shorthand args — print help
            Cli::command()
                .color(color_choice())
                .print_help()
                .expect("failed to print help");
            println!();
            Ok(())
        }
    }
}
