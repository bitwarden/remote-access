//! Proxy client trait and default implementation
//!
//! This module provides the `ProxyClient` trait for abstracting proxy communication,
//! enabling dependency injection and easier testing.

use ap_proxy_client::IncomingMessage;
#[cfg(feature = "native-websocket")]
use ap_proxy_client::ProxyProtocolClient;
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair, RendezvousCode};
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::error::ClientError;

/// Trait abstracting the proxy client for communication between devices
#[async_trait]
pub trait ProxyClient: Send + Sync {
    /// Connect to the proxy server, returning a receiver for incoming messages
    async fn connect(
        &mut self,
        identity: IdentityKeyPair,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ClientError>;

    /// Request a rendezvous code from the proxy server
    async fn request_rendezvous(&self) -> Result<(), ClientError>;

    /// Request the identity associated with a rendezvous code
    async fn request_identity(&self, code: RendezvousCode) -> Result<(), ClientError>;

    /// Send a message to a peer by their fingerprint
    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), ClientError>;

    /// Disconnect from the proxy server
    async fn disconnect(&mut self) -> Result<(), ClientError>;
}

/// Default implementation using ProxyProtocolClient from ap-proxy
#[cfg(feature = "native-websocket")]
pub struct DefaultProxyClient {
    inner: ProxyProtocolClient,
}

#[cfg(feature = "native-websocket")]
impl DefaultProxyClient {
    pub fn from_url(proxy_url: String) -> Self {
        Self {
            inner: ProxyProtocolClient::from_url(proxy_url),
        }
    }
}

#[cfg(feature = "native-websocket")]
#[async_trait]
impl ProxyClient for DefaultProxyClient {
    async fn connect(
        &mut self,
        identity: IdentityKeyPair,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ClientError> {
        self.inner
            .connect(identity)
            .await
            .map_err(ClientError::from)
    }

    async fn request_rendezvous(&self) -> Result<(), ClientError> {
        self.inner
            .request_rendezvous()
            .await
            .map_err(ClientError::from)
    }

    async fn request_identity(&self, code: RendezvousCode) -> Result<(), ClientError> {
        self.inner
            .request_identity(code)
            .await
            .map_err(ClientError::from)
    }

    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.inner
            .send_to(fingerprint, data)
            .await
            .map_err(ClientError::from)
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
        self.inner.disconnect().await.map_err(ClientError::from)
    }
}
