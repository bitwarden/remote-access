use bw_proxy::error::ProxyError;
use bw_proxy::server::{ProxyServer, ProxyServerConfig};
use std::env;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<(), ProxyError> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let bind_addr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .expect("Invalid BIND_ADDR");

    let max_buffered = env::var("MESSAGE_BUFFER_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);

    tracing::info!(
        "Starting proxy server on {} (message buffer: {})",
        bind_addr,
        max_buffered
    );

    let config = ProxyServerConfig {
        max_buffered_messages_per_destination: max_buffered,
    };
    let server = ProxyServer::with_config(bind_addr, config);

    tokio::select! {
        result = server.run() => {
            tracing::info!("Server stopped");
            result
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal");
            Ok(())
        }
    }
}
