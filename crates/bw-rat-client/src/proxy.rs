//! Proxy client trait and default implementation
//!
//! This module provides the `ProxyClient` trait for abstracting proxy communication,
//! enabling dependency injection and easier testing.

use async_trait::async_trait;
use bw_proxy::{
    IdentityFingerprint, IncomingMessage, ProxyClientConfig, ProxyProtocolClient, RendevouzCode,
};
use tokio::sync::mpsc;

use crate::error::RemoteClientError;

/// Trait abstracting the proxy client for communication between devices
#[async_trait]
pub trait ProxyClient: Send + Sync {
    /// Connect to the proxy server, returning a receiver for incoming messages
    async fn connect(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, RemoteClientError>;

    /// Request a rendezvous code from the proxy server
    async fn request_rendezvous(&self) -> Result<(), RemoteClientError>;

    /// Request the identity associated with a rendezvous code
    async fn request_identity(&self, code: RendevouzCode) -> Result<(), RemoteClientError>;

    /// Send a message to a peer by their fingerprint
    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), RemoteClientError>;

    /// Disconnect from the proxy server
    async fn disconnect(&mut self) -> Result<(), RemoteClientError>;
}

/// Default implementation using ProxyProtocolClient from bw-proxy
pub struct DefaultProxyClient {
    inner: ProxyProtocolClient,
}

impl DefaultProxyClient {
    pub fn new(config: ProxyClientConfig) -> Self {
        Self {
            inner: ProxyProtocolClient::new(config),
        }
    }
}

#[async_trait]
impl ProxyClient for DefaultProxyClient {
    async fn connect(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, RemoteClientError> {
        self.inner.connect().await.map_err(RemoteClientError::from)
    }

    async fn request_rendezvous(&self) -> Result<(), RemoteClientError> {
        self.inner
            .request_rendezvous()
            .await
            .map_err(RemoteClientError::from)
    }

    async fn request_identity(&self, code: RendevouzCode) -> Result<(), RemoteClientError> {
        self.inner
            .request_identity(code)
            .await
            .map_err(RemoteClientError::from)
    }

    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), RemoteClientError> {
        self.inner
            .send_to(fingerprint, data)
            .await
            .map_err(RemoteClientError::from)
    }

    async fn disconnect(&mut self) -> Result<(), RemoteClientError> {
        self.inner
            .disconnect()
            .await
            .map_err(RemoteClientError::from)
    }
}
