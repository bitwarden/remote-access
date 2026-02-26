//! bw-remote CLI
//!
//! A CLI interface for connecting to a user-client through a proxy
//! to request credentials over a secure Noise Protocol channel.

mod command;
mod storage;

use clap::Parser;
use color_eyre::eyre::Result;

use command::{Cli, process_command};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize error handling
    color_eyre::install()?;

    // Parse CLI first to check for debug flag
    let cli = Cli::parse();

    // Initialize logging with appropriate level
    let log_level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(log_level.into()),
        )
        .init();

    eprintln!("Bitwarden Remote Access v{}", env!("CARGO_PKG_VERSION"));

    process_command(cli).await
}
