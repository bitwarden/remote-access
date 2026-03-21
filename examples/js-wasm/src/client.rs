//! High-level WASM wrapper around `RemoteClient`.
//!
//! Provides a JavaScript-friendly async API that mirrors the Python
//! `PyRemoteClient` wrapper.

use ap_client::{ConnectionStore, IdentityFingerprint, PskToken, RemoteClient};
use wasm_bindgen::prelude::*;

use crate::proxy_client::WasmProxyClient;
use crate::storage::{LocalStorageConnectionStore, LocalStorageIdentityProvider};
use crate::types::{client_error_to_js, JsCredentialData};

/// A remote-access client for the browser.
///
/// Usage from JavaScript:
/// ```js
/// const client = new WasmRemoteClient("wss://ap.lesspassword.dev", "js-remote");
/// await client.connect("ABC-DEF-GHI");
/// const cred = await client.requestCredential("example.com");
/// console.log(cred.username, cred.password);
/// client.close();
/// ```
#[wasm_bindgen]
pub struct WasmRemoteClient {
    inner: Option<RemoteClient>,
    proxy_url: String,
    identity_name: String,
}

#[wasm_bindgen]
impl WasmRemoteClient {
    /// Create a new client.
    ///
    /// @param proxy_url - WebSocket URL of the proxy server
    /// @param identity_name - Name for the identity keypair stored in localStorage
    #[wasm_bindgen(constructor)]
    pub fn new(proxy_url: &str, identity_name: &str) -> Self {
        Self {
            inner: None,
            proxy_url: proxy_url.to_string(),
            identity_name: identity_name.to_string(),
        }
    }

    /// Connect to a remote peer.
    ///
    /// @param token - Rendezvous code (e.g. "ABC-DEF-GHI") or PSK token.
    ///                If omitted, uses a cached connection.
    /// @param session - Hex fingerprint of a specific cached connection.
    /// @returns The 6-char handshake fingerprint (new connections) or null (cached).
    pub async fn connect(
        &mut self,
        token: Option<String>,
        session: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let identity = LocalStorageIdentityProvider::load_or_generate(&self.identity_name)
            .map_err(client_error_to_js)?;

        let connection_store = LocalStorageConnectionStore::load_or_create(&self.identity_name)
            .map_err(client_error_to_js)?;

        let proxy_client = Box::new(WasmProxyClient::new(self.proxy_url.clone()));

        let handle = RemoteClient::connect(
            Box::new(identity),
            Box::new(connection_store),
            proxy_client,
        )
        .await
        .map_err(client_error_to_js)?;

        let client = handle.client;
        // Drop notification receiver — not used in this example.
        // Dropping is safe: the event loop ignores send failures.
        drop(handle.notifications);

        // Determine connection mode
        let handshake_fingerprint = if let Some(token_str) = token {
            if PskToken::looks_like_psk_token(&token_str) {
                let parsed = PskToken::parse(&token_str)
                    .map_err(|e| JsValue::from_str(&format!("Invalid PSK token: {e}")))?;
                let (psk, fingerprint) = parsed.into_parts();
                client
                    .pair_with_psk(psk, fingerprint)
                    .await
                    .map_err(client_error_to_js)?;
                None
            } else {
                // Rendezvous code — no fingerprint verification (headless)
                let fp = client
                    .pair_with_handshake(token_str, false)
                    .await
                    .map_err(client_error_to_js)?;
                Some(hex::encode(fp.0))
            }
        } else if let Some(session_hex) = session {
            let fingerprint = IdentityFingerprint::from_hex(&session_hex)
                .map_err(|e| JsValue::from_str(&format!("Invalid session fingerprint: {e}")))?;
            client
                .load_cached_connection(fingerprint)
                .await
                .map_err(client_error_to_js)?;
            None
        } else {
            // Auto-select cached session if exactly one exists
            let connections = client
                .list_connections()
                .await
                .map_err(client_error_to_js)?;
            if connections.len() == 1 {
                let fingerprint = connections[0].fingerprint;
                client
                    .load_cached_connection(fingerprint)
                    .await
                    .map_err(client_error_to_js)?;
                None
            } else if connections.is_empty() {
                return Err(JsValue::from_str(
                    "No cached connections — provide a token to start a new connection",
                ));
            } else {
                return Err(JsValue::from_str(&format!(
                    "Multiple cached connections ({}) — specify one with session",
                    connections.len()
                )));
            }
        };

        self.inner = Some(client);

        match handshake_fingerprint {
            Some(fp) => Ok(JsValue::from_str(&fp)),
            None => Ok(JsValue::NULL),
        }
    }

    /// Request a credential for a domain.
    ///
    /// @param domain - The domain to look up (e.g. "example.com")
    /// @returns CredentialData with username, password, totp, etc.
    #[wasm_bindgen(js_name = "requestCredential")]
    pub async fn request_credential(&self, domain: &str) -> Result<JsCredentialData, JsValue> {
        let client = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Not connected — call connect() first"))?;

        let query = ap_client::CredentialQuery::Domain(domain.to_string());
        let cred = client
            .request_credential(&query)
            .await
            .map_err(client_error_to_js)?;

        Ok(JsCredentialData::from(cred))
    }

    /// List cached connections.
    ///
    /// @returns Array of { fingerprint, name, cachedAt, lastConnectedAt }
    #[wasm_bindgen(js_name = "listConnections")]
    pub async fn list_connections(&self) -> Result<JsValue, JsValue> {
        let store = LocalStorageConnectionStore::load_or_create(&self.identity_name)
            .map_err(client_error_to_js)?;
        let connections = store.list().await;

        let arr = js_sys::Array::new();
        for conn in connections {
            let obj = js_sys::Object::new();
            let _ = js_sys::Reflect::set(
                &obj,
                &"fingerprint".into(),
                &JsValue::from_str(&hex::encode(conn.fingerprint.0)),
            );
            let _ = js_sys::Reflect::set(
                &obj,
                &"name".into(),
                &match &conn.name {
                    Some(n) => JsValue::from_str(n),
                    None => JsValue::NULL,
                },
            );
            let _ = js_sys::Reflect::set(
                &obj,
                &"cachedAt".into(),
                &JsValue::from_f64(conn.cached_at as f64),
            );
            let _ = js_sys::Reflect::set(
                &obj,
                &"lastConnectedAt".into(),
                &JsValue::from_f64(conn.last_connected_at as f64),
            );
            arr.push(&obj);
        }

        Ok(arr.into())
    }

    /// Clear all cached connections.
    #[wasm_bindgen(js_name = "clearConnections")]
    pub fn clear_connections(&self) -> Result<(), JsValue> {
        let mut store = LocalStorageConnectionStore::load_or_create(&self.identity_name)
            .map_err(client_error_to_js)?;
        store.clear().map_err(client_error_to_js)?;
        Ok(())
    }

    /// Close the connection and release resources.
    pub fn close(&mut self) {
        self.inner.take();
    }

    /// Whether the client is connected.
    #[wasm_bindgen(getter, js_name = "isConnected")]
    pub fn is_connected(&self) -> bool {
        self.inner.is_some()
    }
}
