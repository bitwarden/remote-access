//! aac CLI
//!
//! A CLI interface for connecting to a user-client through a proxy
//! to request credentials over a secure Noise Protocol channel.

mod command;
mod storage;

use clap::{CommandFactory, FromArgMatches};
use color_eyre::eyre::Result;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use command::tui_tracing::TuiLayer;
use command::{Cli, Commands, process_command};

/// Returns `true` when the command will launch an interactive TUI session.
fn is_tui_mode(cli: &Cli) -> bool {
    match &cli.command {
        Some(Commands::Listen(_)) => true,
        Some(Commands::Connect(args)) => args.domain.is_none(),
        Some(Commands::Connections(_)) => false,
        // Default (no subcommand) behaves like `connect`
        None => cli.domain.is_none(),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize error handling
    color_eyre::install()?;

    // Parse CLI with color choice based on LLM env var
    let matches = Cli::command().color(command::color_choice()).get_matches();
    let cli = Cli::from_arg_matches(&matches)?;

    // Initialize logging with appropriate level
    let log_level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };

    let env_filter =
        tracing_subscriber::EnvFilter::from_default_env().add_directive(log_level.into());

    let log_rx = if is_tui_mode(&cli) {
        // TUI mode: route logs through a channel into the TUI message panel
        let (tui_layer, rx) = TuiLayer::new();
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tui_layer)
            .init();
        Some(rx)
    } else {
        // Non-TUI mode: write logs to stderr as before
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
        None
    };

    process_command(cli, log_rx).await
}
