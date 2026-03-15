use bw_proxy_protocol::{IdentityFingerprint, ProxyError};

use crate::connection::AuthenticatedConnection;
use crate::server::handler::ConnectionHandler;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_tungstenite::accept_async;

pub struct RendevouzEntry {
    pub fingerprint: IdentityFingerprint,
    pub created_at: SystemTime,
    pub used: bool,
}

pub struct ServerState {
    pub connections: Arc<RwLock<HashMap<IdentityFingerprint, Vec<Arc<AuthenticatedConnection>>>>>,
    pub rendezvous_map: Arc<RwLock<HashMap<String, RendevouzEntry>>>,
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            rendezvous_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

/// The proxy server that accepts client connections and relays messages.
///
/// This server handles:
/// - Client authentication using MlDsa65 challenge-response
/// - Rendezvous code generation and lookup
/// - Message routing between authenticated clients
/// - Automatic cleanup of expired rendezvous codes
///
/// # Examples
///
/// Run a standalone server:
///
/// ```no_run
/// use bw_proxy::server::ProxyServer;
/// use std::net::SocketAddr;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let addr: SocketAddr = "127.0.0.1:8080".parse()?;
/// let server = ProxyServer::new(addr);
///
/// println!("Starting proxy server on {}", addr);
/// server.run().await?;
/// # Ok(())
/// # }
/// ```
///
/// Embed in an application with cancellation:
///
/// ```no_run
/// use bw_proxy::server::ProxyServer;
/// use std::net::SocketAddr;
/// use tokio::signal;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let addr: SocketAddr = "127.0.0.1:8080".parse()?;
/// let server = ProxyServer::new(addr);
///
/// tokio::select! {
///     result = server.run() => {
///         result?;
///     }
///     _ = signal::ctrl_c() => {
///         println!("Shutting down...");
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct ProxyServer {
    bind_addr: SocketAddr,
    state: Arc<ServerState>,
    conn_counter: AtomicU64,
}

impl ProxyServer {
    /// Create a new proxy server that will listen on the given address.
    ///
    /// This does not start the server - call [`run()`](ProxyServer::run) to begin
    /// accepting connections.
    ///
    /// # Examples
    ///
    /// ```
    /// use bw_proxy::server::ProxyServer;
    /// use std::net::SocketAddr;
    ///
    /// let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    /// let server = ProxyServer::new(addr);
    /// ```
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            state: Arc::new(ServerState::new()),
            conn_counter: AtomicU64::new(0),
        }
    }

    /// Run the proxy server, accepting and handling connections.
    ///
    /// This method:
    /// 1. Binds to the configured address
    /// 2. Spawns a background task to clean up expired rendezvous codes
    /// 3. Accepts incoming WebSocket connections
    /// 4. Spawns a handler task for each connection
    /// 5. Runs indefinitely until an error occurs or cancelled
    ///
    /// # Cancellation
    ///
    /// Use `tokio::select!` or similar to cancel the server:
    ///
    /// ```no_run
    /// use bw_proxy::server::ProxyServer;
    /// use std::net::SocketAddr;
    /// use tokio::signal;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    /// let server = ProxyServer::new(addr);
    ///
    /// tokio::select! {
    ///     result = server.run() => result?,
    ///     _ = signal::ctrl_c() => {
    ///         println!("Shutting down gracefully");
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bind address is already in use
    /// - The address is invalid or cannot be bound
    /// - A network error occurs
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bw_proxy::server::ProxyServer;
    /// use std::net::SocketAddr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    /// let server = ProxyServer::new(addr);
    /// server.run().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run(&self) -> Result<(), ProxyError> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        tracing::info!("Proxy server listening on {}", self.bind_addr);
        self.run_with_listener(listener).await
    }

    /// Run the proxy server using an already-bound `TcpListener`.
    ///
    /// This is useful in tests to avoid the race condition of binding a port,
    /// dropping the listener, and re-binding.
    pub async fn run_with_listener(&self, listener: TcpListener) -> Result<(), ProxyError> {
        // Spawn background cleanup task for expired rendezvous codes
        let cleanup_state = Arc::clone(&self.state);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

                let mut rendezvous_map = cleanup_state.rendezvous_map.write().await;
                let now = SystemTime::now();
                let mut expired_codes = Vec::new();

                for (code, entry) in rendezvous_map.iter() {
                    let elapsed = now.duration_since(entry.created_at).unwrap_or_default();

                    if elapsed.as_secs() > 300 {
                        expired_codes.push(code.clone());
                    }
                }

                for code in expired_codes {
                    rendezvous_map.remove(&code);
                    tracing::debug!("Cleaned up expired rendezvous code: {}", code);
                }
            }
        });

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let conn_id = self.conn_counter.fetch_add(1, Ordering::SeqCst);

            tracing::info!("New connection #{} from {}", conn_id, peer_addr);

            let state = Arc::clone(&self.state);

            tokio::spawn(async move {
                match accept_async(stream).await {
                    Ok(ws_stream) => {
                        let handler = ConnectionHandler::new(conn_id, state, ws_stream);
                        if let Err(e) = handler.handle().await {
                            tracing::error!("Connection #{} error: {}", conn_id, e);
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to accept WebSocket connection #{}: {}",
                            conn_id,
                            e
                        );
                    }
                }
            });
        }
    }
}
