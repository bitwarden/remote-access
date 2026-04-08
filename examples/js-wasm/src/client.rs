//! Thin WASM wrapper around `RemoteClient`.
//!
//! Exposes individual `RemoteClient` methods to JavaScript. Connection
//! mode orchestration (PSK vs rendezvous vs cached) lives in the JS
//! `RemoteAccessClient` class, not here.

use ap_client::{IdentityFingerprint, PskToken, RemoteClient};
use wasm_bindgen::prelude::*;

use crate::proxy_client::WasmProxyClient;
use crate::storage::{LocalStorageConnectionStore, LocalStorageIdentityProvider};
use crate::types::{client_error_to_js, JsCredentialData};

/// A remote-access client for the browser.
///
/// Usage from JavaScript:
/// ```js
/// const client = new WasmRemoteClient("wss://ap.lesspassword.dev", "js-remote");
/// await client.connect();
/// const fp = await client.pairWithHandshake("ABC-DEF-GHI");
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

    /// Connect to the proxy server.
    ///
    /// Establishes the WebSocket connection and authenticates. After this,
    /// call one of the pairing methods to establish a secure channel.
    pub async fn connect(&mut self) -> Result<(), JsValue> {
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

        self.inner = Some(handle.client);
        // Drop notification receiver — not used in this example.
        // Dropping is safe: the event loop ignores send failures.
        drop(handle.notifications);

        Ok(())
    }

    /// Pair with a new device using a rendezvous code.
    ///
    /// @param code - Rendezvous code (e.g. "ABC-DEF-GHI")
    /// @returns The 6-char handshake fingerprint as a hex string
    #[wasm_bindgen(js_name = "pairWithHandshake")]
    pub async fn pair_with_handshake(&self, code: String) -> Result<String, JsValue> {
        let client = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Not connected — call connect() first"))?;

        let fp = client
            .pair_with_handshake(code, false)
            .await
            .map_err(client_error_to_js)?;

        Ok(hex::encode(fp.0))
    }

    /// Pair with a new device using a PSK token.
    ///
    /// @param psk_token - PSK token string (<64-hex-psk>_<64-hex-fingerprint>)
    #[wasm_bindgen(js_name = "pairWithPsk")]
    pub async fn pair_with_psk(&self, psk_token: String) -> Result<(), JsValue> {
        let client = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Not connected — call connect() first"))?;

        let parsed = PskToken::parse(&psk_token)
            .map_err(|e| JsValue::from_str(&format!("Invalid PSK token: {e}")))?;
        let (psk, fingerprint) = parsed.into_parts();

        client
            .pair_with_psk(psk, fingerprint)
            .await
            .map_err(client_error_to_js)?;

        Ok(())
    }

    /// Reconnect to a previously paired device using a cached session.
    ///
    /// @param fingerprint_hex - Hex-encoded identity fingerprint
    #[wasm_bindgen(js_name = "loadCachedConnection")]
    pub async fn load_cached_connection(&self, fingerprint_hex: String) -> Result<(), JsValue> {
        let client = self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Not connected — call connect() first"))?;

        let fingerprint = IdentityFingerprint::from_hex(&fingerprint_hex)
            .map_err(|e| JsValue::from_str(&format!("Invalid fingerprint: {e}")))?;

        client
            .load_cached_connection(fingerprint)
            .await
            .map_err(client_error_to_js)?;

        Ok(())
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

    /// Close the connection and release resources.
    pub fn close(&mut self) {
        self.inner.take();
    }

}
