//! CLI command definitions and dispatch
//!
//! This module organizes all CLI commands into separate submodules,
//! following the pattern used in the main Bitwarden CLI.

mod connect;
mod connections;
mod listen;
pub(crate) mod output;
mod run;
pub(crate) mod tui;
pub(crate) mod tui_tracing;
mod util;

use std::sync::LazyLock;

use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{ColorChoice, CommandFactory, Parser, Subcommand};
use color_eyre::eyre::Result;

use output::OutputFormat;
use tui_tracing::LogReceiver;

pub use connect::ConnectArgs;
pub use connections::ConnectionsArgs;
pub use listen::ListenArgs;
pub use run::RunArgs;

const DEFAULT_PROXY_URL: &str = "wss://ap.lesspassword.dev";

/// Build a version string like "0.3.0 (abc1234)" when GIT_HASH is set by CI,
/// or just "0.3.0" for local dev builds.
fn version_string() -> &'static str {
    static VERSION: LazyLock<String> = LazyLock::new(|| match option_env!("GIT_HASH") {
        Some(hash) if !hash.is_empty() => {
            format!("{} ({})", env!("CARGO_PKG_VERSION"), hash)
        }
        _ => env!("CARGO_PKG_VERSION").to_string(),
    });
    &VERSION
}

fn header() -> &'static str {
    static HEADER: LazyLock<String> = LazyLock::new(|| {
        if *COLOR_CHOICE == ColorChoice::Never {
            format!("Agent Access CLI - {}", version_string())
        } else {
            format!("\x1b[1;36mAgent Access CLI\x1b[0m - {}", version_string())
        }
    });
    &HEADER
}

/// Color choice: disabled when `LLM` or `NO_COLOR` is set, otherwise auto-detect.
/// Cached once per process.
static COLOR_CHOICE: LazyLock<ColorChoice> = LazyLock::new(|| {
    let llm = std::env::var("LLM").is_ok();
    let no_color = std::env::var("NO_COLOR").is_ok();
    if llm || no_color {
        ColorChoice::Never
    } else {
        ColorChoice::Auto
    }
});

pub fn color_choice() -> ColorChoice {
    *COLOR_CHOICE
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
#[command(name = "aac")]
#[command(author, version = version_string(), about = "Retrieve credentials from your password manager over a secure channel", long_about = None)]
#[command(styles = STYLES, before_help = header())]
#[command(after_help = "\
AUTOMATION / AGENT / LLM USE:
  For non-interactive (single-shot) credential retrieval:

    1. List cached sessions:  aac connections list
    2. Request a credential:  aac --domain <DOMAIN> --session <HEX> --output json
       Or by vault item ID:  aac --id <ID> --session <HEX> --output json

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
    #[arg(long, env = "AAC_TOKEN")]
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
    #[arg(long, conflicts_with = "id")]
    pub domain: Option<String>,

    /// Vault item ID to request credentials for (single-shot, non-interactive)
    #[arg(long, conflicts_with = "domain")]
    pub id: Option<String>,

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
    /// Fetch a credential and run a command with it injected as env vars
    Run(RunArgs),
}

/// Process the parsed command and execute the appropriate handler
pub async fn process_command(cli: Cli, log_rx: Option<LogReceiver>) -> Result<()> {
    match cli.command {
        Some(Commands::Connections(args)) => args.run().await,
        Some(Commands::Connect(args)) => args.run(log_rx).await,
        Some(Commands::Listen(args)) => args.run(log_rx).await,
        Some(Commands::Run(args)) => args.run().await,
        None if cli.domain.is_some()
            || cli.id.is_some()
            || cli.token.is_some()
            || cli.session.is_some() =>
        {
            // Single-shot / shorthand connect with top-level args
            let args = ConnectArgs {
                proxy_url: cli.proxy_url,
                token: cli.token,
                session: cli.session,
                ephemeral_connection: cli.ephemeral_connection,
                verify_fingerprint: cli.verify_fingerprint,
                domain: cli.domain,
                id: cli.id,
                output: cli.output,
            };
            args.run(log_rx).await
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
