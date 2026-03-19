use pyo3::prelude::*;
use tokio::sync::mpsc;

use ap_proxy_client::ProxyClientConfig;
use ap_client::{
    DefaultProxyClient, IdentityFingerprint, IdentityProvider, Psk, RemoteClient,
    RemoteClientNotification, RemoteClientRequest, SessionStore,
};

use crate::storage::{FileIdentityStorage, FileSessionCache};
use crate::types::{PyCredentialData, RemoteAccessError};

/// A remote-access client backed by the full Rust crypto/protocol stack.
///
/// Usage::
///
///     client = RemoteClient("wss://rat1.lesspassword.dev", "python-remote")
///     client.connect(token="ABC-DEF-GHI")
///     cred = client.request_credential("example.com")
///     print(cred.username, cred.password)
///     client.close()
#[pyclass(name = "RemoteClient")]
pub struct PyRemoteClient {
    runtime: tokio::runtime::Runtime,
    inner: Option<RemoteClient>,
    notification_rx: Option<mpsc::Receiver<RemoteClientNotification>>,
    proxy_url: String,
    identity_name: String,
    ready: bool,
}

#[pymethods]
impl PyRemoteClient {
    /// Create a new RemoteClient.
    ///
    /// Args:
    ///     proxy_url: WebSocket URL of the proxy server.
    ///     identity_name: Name for the identity keypair file (~/.bw-remote/{name}.key).
    #[new]
    #[pyo3(signature = (proxy_url="wss://rat1.lesspassword.dev", identity_name="python-remote"))]
    pub fn new(proxy_url: &str, identity_name: &str) -> PyResult<Self> {
        // Enable RUST_LOG for debugging
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_writer(std::io::stderr)
            .try_init();

        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| RemoteAccessError::new_err(format!("Failed to create runtime: {e}")))?;

        Ok(Self {
            runtime,
            inner: None,
            notification_rx: None,
            proxy_url: proxy_url.to_string(),
            identity_name: identity_name.to_string(),
            ready: false,
        })
    }

    /// Connect to a remote peer.
    ///
    /// Args:
    ///     token: Rendezvous code (e.g. "ABC-DEF-GHI") or PSK token
    ///            (<64hex>_<64hex>). If None, uses a cached session.
    ///     session: Hex fingerprint of a specific cached session to reconnect.
    ///
    /// Returns:
    ///     The 6-char handshake fingerprint (for new connections) or None (cached).
    #[pyo3(signature = (token=None, session=None))]
    pub fn connect(
        &mut self,
        py: Python<'_>,
        token: Option<&str>,
        session: Option<&str>,
    ) -> PyResult<Option<String>> {
        let identity = FileIdentityStorage::load_or_generate(&self.identity_name)
            .map_err(|e| RemoteAccessError::new_err(e.to_string()))?;

        let session_store = FileSessionCache::load_or_create(&self.identity_name)
            .map_err(|e| RemoteAccessError::new_err(e.to_string()))?;

        let (notification_tx, notification_rx) = mpsc::channel(32);
        let (request_tx, _request_rx) = mpsc::channel::<RemoteClientRequest>(32);

        let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
            proxy_url: self.proxy_url.clone(),
            identity_keypair: Some(self.runtime.block_on(identity.identity())),
        }));

        // Create the client (connects to proxy, spawns event loop)
        let client = py
            .allow_threads(|| {
                self.runtime.block_on(async {
                    RemoteClient::connect(
                        Box::new(identity),
                        Box::new(session_store),
                        proxy_client,
                        notification_tx,
                        request_tx,
                    )
                    .await
                })
            })
            .map_err(|e| RemoteAccessError::new_err(e.to_string()))?;

        // Determine connection mode and connect
        let handshake_fingerprint = py
            .allow_threads(|| {
                self.runtime.block_on(async {
                    if let Some(token_str) = token {
                        // Parse token: PSK or rendezvous
                        if token_str.contains('_') && token_str.len() == 129 {
                            // PSK token: <64hex>_<64hex>
                            let parts: Vec<&str> = token_str.split('_').collect();
                            if parts.len() != 2 || parts[0].len() != 64 || parts[1].len() != 64 {
                                return Err("Invalid PSK token format".to_string());
                            }
                            let psk =
                                Psk::from_hex(parts[0]).map_err(|e| format!("Invalid PSK: {e}"))?;
                            let fingerprint = parse_fingerprint_hex(parts[1])?;

                            client
                                .pair_with_psk(psk, fingerprint)
                                .await
                                .map_err(|e| e.to_string())?;
                            Ok(None)
                        } else {
                            // Rendezvous code — no fingerprint verification (headless)
                            let fp = client
                                .pair_with_handshake(token_str.to_string(), false)
                                .await
                                .map_err(|e| e.to_string())?;
                            // Return the fingerprint hex for informational purposes
                            Ok(Some(hex::encode(fp.0)))
                        }
                    } else if let Some(session_hex) = session {
                        let fingerprint = parse_fingerprint_hex(session_hex)?;
                        client
                            .load_cached_session(fingerprint)
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok(None)
                    } else {
                        // Auto-select cached session if exactly one exists
                        let sessions = client
                            .list_sessions()
                            .await
                            .map_err(|e| e.to_string())?;
                        if sessions.len() == 1 {
                            let (fingerprint, _, _, _) = &sessions[0];
                            client
                                .load_cached_session(*fingerprint)
                                .await
                                .map_err(|e| e.to_string())?;
                            Ok(None)
                        } else if sessions.is_empty() {
                            Err(
                                "No cached sessions — provide a token to start a new connection"
                                    .to_string(),
                            )
                        } else {
                            Err(format!(
                                "Multiple cached sessions ({}) — specify one with session=",
                                sessions.len()
                            ))
                        }
                    }
                })
            })
            .map_err(|e: String| RemoteAccessError::new_err(e))?;

        self.inner = Some(client);
        self.notification_rx = Some(notification_rx);
        self.ready = true;

        Ok(handshake_fingerprint)
    }

    /// Request a credential for a domain.
    ///
    /// Args:
    ///     domain: The domain to look up (e.g. "example.com").
    ///
    /// Returns:
    ///     CredentialData with username, password, totp, uri, notes.
    pub fn request_credential(
        &mut self,
        py: Python<'_>,
        domain: &str,
    ) -> PyResult<PyCredentialData> {
        let client = self
            .inner
            .as_ref()
            .ok_or_else(|| RemoteAccessError::new_err("Not connected — call connect() first"))?;

        let query =
            ap_client::CredentialQuery::Domain(domain.to_string());
        let cred = py
            .allow_threads(|| {
                self.runtime
                    .block_on(async { client.request_credential(&query).await })
            })
            .map_err(|e| RemoteAccessError::new_err(e.to_string()))?;

        Ok(PyCredentialData::from(cred))
    }

    /// Close the connection and release resources.
    pub fn close(&mut self, _py: Python<'_>) -> PyResult<()> {
        self.inner.take(); // Drop the handle — shuts down event loop
        self.notification_rx = None;
        self.ready = false;
        Ok(())
    }

    /// Whether the secure channel is established and ready.
    #[getter]
    fn is_ready(&self) -> bool {
        self.ready
    }

    /// Clear all cached sessions for this identity.
    pub fn clear_sessions(&self) -> PyResult<()> {
        let mut store = FileSessionCache::load_or_create(&self.identity_name)
            .map_err(|e| RemoteAccessError::new_err(e.to_string()))?;
        self.runtime
            .block_on(store.clear())
            .map_err(|e| RemoteAccessError::new_err(e.to_string()))?;
        Ok(())
    }

    /// List cached sessions. Returns a list of (fingerprint_hex, name, cached_at, last_connected_at).
    pub fn list_sessions(&self) -> PyResult<Vec<(String, Option<String>, u64, u64)>> {
        let store = FileSessionCache::load_or_create(&self.identity_name)
            .map_err(|e| RemoteAccessError::new_err(e.to_string()))?;
        Ok(self
            .runtime
            .block_on(store.list_sessions())
            .into_iter()
            .map(|(fp, name, cached, last)| (hex::encode(fp.0), name, cached, last))
            .collect())
    }
}

/// Parse a 64-char hex string into an IdentityFingerprint.
fn parse_fingerprint_hex(hex_str: &str) -> Result<IdentityFingerprint, String> {
    let clean = hex_str.replace(['-', ' ', ':'], "");
    if clean.len() != 64 {
        return Err(format!(
            "Fingerprint must be 64 hex characters, got {}",
            clean.len()
        ));
    }
    let bytes = hex::decode(&clean).map_err(|e| format!("Invalid hex: {e}"))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(IdentityFingerprint(arr))
}
