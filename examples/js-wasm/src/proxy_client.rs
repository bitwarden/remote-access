//! Browser WebSocket implementation of the `ProxyClient` trait.
//!
//! Uses `web_sys::WebSocket` to communicate with the proxy server,
//! bridging the browser's callback-driven API to the channel-based
//! `ProxyClient` trait.

use ap_client::error::ClientError;
use ap_client::ProxyClient;
use ap_proxy_client::IncomingMessage;
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair, Messages, RendezvousCode};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

/// A `ProxyClient` implementation using the browser's WebSocket API.
///
/// Closures are registered with `.forget()` (standard WASM practice for event
/// handlers). The struct only holds `Send + Sync` types.
pub struct WasmProxyClient {
    url: String,
    ws: Option<WebSocket>,
}

impl WasmProxyClient {
    pub fn new(url: String) -> Self {
        Self { url, ws: None }
    }

    fn send_json(&self, msg: &Messages) -> Result<(), ClientError> {
        let ws = self
            .ws
            .as_ref()
            .ok_or_else(|| ClientError::ConnectionFailed("Not connected".to_string()))?;
        let json = serde_json::to_string(msg)
            .map_err(|e| ClientError::ConnectionFailed(format!("Serialization error: {e}")))?;
        ws.send_with_str(&json)
            .map_err(|e| ClientError::ConnectionFailed(format!("WebSocket send error: {e:?}")))?;
        Ok(())
    }
}

#[async_trait]
impl ProxyClient for WasmProxyClient {
    async fn connect(
        &mut self,
        identity: IdentityKeyPair,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ClientError> {
        let ws = WebSocket::new(&self.url).map_err(|e| {
            ClientError::ConnectionFailed(format!("Failed to create WebSocket: {e:?}"))
        })?;

        // Channels for signaling connection open and auth completion
        let (open_tx, open_rx) = oneshot::channel::<Result<(), ClientError>>();
        let (auth_tx, auth_rx) = oneshot::channel::<Result<(), ClientError>>();
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel::<IncomingMessage>();

        // Use Arc<Mutex<Option<...>>> so closures are Send and can take the sender once
        let open_tx = Arc::new(Mutex::new(Some(open_tx)));
        let auth_tx = Arc::new(Mutex::new(Some(auth_tx)));

        // --- onopen: signal that the WebSocket is connected ---
        {
            let open_tx = Arc::clone(&open_tx);
            let cb = Closure::once(move |_: JsValue| {
                if let Some(tx) = open_tx
                    .lock()
                    .expect("open_tx lock poisoned")
                    .take()
                {
                    let _ = tx.send(Ok(()));
                }
            });
            ws.set_onopen(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }

        // --- onerror (pre-open): fail the open signal ---
        {
            let open_tx = Arc::clone(&open_tx);
            let cb = Closure::once(move |_: ErrorEvent| {
                if let Some(tx) = open_tx
                    .lock()
                    .expect("open_tx err lock poisoned")
                    .take()
                {
                    let _ = tx.send(Err(ClientError::ConnectionFailed(
                        "WebSocket connection error".to_string(),
                    )));
                }
            });
            ws.set_onerror(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }

        // Wait for the WebSocket to open
        open_rx
            .await
            .map_err(|_| ClientError::ConnectionFailed("Open channel dropped".to_string()))?
            .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;

        // --- onmessage: handle auth then route messages ---
        {
            let ws_clone = ws.clone();
            let auth_tx = Arc::clone(&auth_tx);
            let auth_done = Arc::new(Mutex::new(false));

            let cb = Closure::wrap(Box::new(move |event: MessageEvent| {
                let text = match event.data().as_string() {
                    Some(t) => t,
                    None => return,
                };

                let parsed: Messages = match serde_json::from_str(&text) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!("Failed to parse proxy message: {e}");
                        return;
                    }
                };

                let is_auth_done =
                    *auth_done.lock().expect("auth_done lock poisoned");
                if !is_auth_done {
                    match parsed {
                        Messages::AuthChallenge(challenge) => {
                            let response = challenge.sign(&identity);
                            let auth_msg =
                                Messages::AuthResponse(identity.identity(), response);
                            match serde_json::to_string(&auth_msg) {
                                Ok(json) => {
                                    if let Err(e) = ws_clone.send_with_str(&json) {
                                        tracing::error!("Failed to send auth response: {e:?}");
                                        if let Some(tx) = auth_tx
                                            .lock()
                                            .expect("auth_tx lock")
                                            .take()
                                        {
                                            let _ = tx.send(Err(ClientError::ConnectionFailed(
                                                "Failed to send auth response".to_string(),
                                            )));
                                        }
                                        return;
                                    }
                                    *auth_done
                                        .lock()
                                        .expect("auth_done lock") = true;
                                    if let Some(tx) = auth_tx
                                        .lock()
                                        .expect("auth_tx lock")
                                        .take()
                                    {
                                        let _ = tx.send(Ok(()));
                                    }
                                }
                                Err(e) => {
                                    if let Some(tx) = auth_tx
                                        .lock()
                                        .expect("auth_tx lock")
                                        .take()
                                    {
                                        let _ = tx.send(Err(ClientError::ConnectionFailed(
                                            format!("Auth serialization error: {e}"),
                                        )));
                                    }
                                }
                            }
                        }
                        _ => {
                            tracing::warn!("Expected AuthChallenge, got: {parsed:?}");
                            if let Some(tx) = auth_tx
                                .lock()
                                .expect("auth_tx lock")
                                .take()
                            {
                                let _ = tx.send(Err(ClientError::ConnectionFailed(
                                    "Expected AuthChallenge".to_string(),
                                )));
                            }
                        }
                    }
                } else {
                    match parsed {
                        Messages::Send {
                            source,
                            destination,
                            payload,
                        } => {
                            if let Some(source) = source {
                                let _ = incoming_tx.send(IncomingMessage::Send {
                                    source,
                                    destination,
                                    payload,
                                });
                            }
                        }
                        Messages::RendezvousInfo(code) => {
                            let _ = incoming_tx.send(IncomingMessage::RendezvousInfo(code));
                        }
                        Messages::IdentityInfo {
                            fingerprint,
                            identity,
                        } => {
                            let _ = incoming_tx.send(IncomingMessage::IdentityInfo {
                                fingerprint,
                                identity,
                            });
                        }
                        _ => {
                            tracing::debug!("Ignoring post-auth message: {parsed:?}");
                        }
                    }
                }
            }) as Box<dyn FnMut(MessageEvent)>);
            ws.set_onmessage(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }

        // --- onerror (post-open): just log ---
        {
            let cb = Closure::wrap(Box::new(move |_: ErrorEvent| {
                tracing::error!("WebSocket error");
            }) as Box<dyn FnMut(ErrorEvent)>);
            ws.set_onerror(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }

        // --- onclose: log ---
        {
            let cb = Closure::wrap(Box::new(move |event: CloseEvent| {
                tracing::info!(
                    "WebSocket closed: code={}, reason={}",
                    event.code(),
                    event.reason()
                );
            }) as Box<dyn FnMut(CloseEvent)>);
            ws.set_onclose(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }

        // Wait for authentication to complete
        auth_rx
            .await
            .map_err(|_| ClientError::ConnectionFailed("Auth channel dropped".to_string()))?
            .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;

        self.ws = Some(ws);
        Ok(incoming_rx)
    }

    async fn request_rendezvous(&self) -> Result<(), ClientError> {
        self.send_json(&Messages::GetRendezvous)
    }

    async fn request_identity(&self, code: RendezvousCode) -> Result<(), ClientError> {
        self.send_json(&Messages::GetIdentity(code))
    }

    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.send_json(&Messages::Send {
            source: None,
            destination: fingerprint,
            payload: data,
        })
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        if let Some(ws) = self.ws.take() {
            ws.set_onopen(None);
            ws.set_onmessage(None);
            ws.set_onerror(None);
            ws.set_onclose(None);
            let _ = ws.close();
        }
        Ok(())
    }
}
