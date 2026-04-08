//! Browser localStorage-based storage implementations.
//!
//! Provides `IdentityProvider` and `ConnectionStore` backed by
//! the browser's `localStorage` API, plus standalone `#[wasm_bindgen]`
//! functions for listing and clearing connections from JavaScript.

use ap_client::error::ClientError;
use ap_client::{ConnectionInfo, ConnectionStore, ConnectionUpdate, IdentityProvider};
use ap_noise::{MultiDeviceTransport, PersistentTransportState};
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use web_sys::Storage;

use crate::types::client_error_to_js;

fn local_storage() -> Result<Storage, ClientError> {
    let window = web_sys::window()
        .ok_or_else(|| ClientError::IdentityStorageFailed("No window object".to_string()))?;
    window
        .local_storage()
        .map_err(|_| ClientError::IdentityStorageFailed("localStorage not available".to_string()))?
        .ok_or_else(|| ClientError::IdentityStorageFailed("localStorage is null".to_string()))
}

// ---------------------------------------------------------------------------
// LocalStorageIdentityProvider
// ---------------------------------------------------------------------------

/// Identity provider backed by browser localStorage.
///
/// Stores the identity keypair as base64-encoded COSE bytes under
/// the key `bw_remote_identity_{name}`.
pub struct LocalStorageIdentityProvider {
    keypair: IdentityKeyPair,
}

impl LocalStorageIdentityProvider {
    /// Load an existing identity from localStorage, or generate a new one.
    pub fn load_or_generate(name: &str) -> Result<Self, ClientError> {
        let storage = local_storage()?;
        let key = format!("bw_remote_identity_{name}");

        let keypair = match storage.get_item(&key).ok().flatten() {
            Some(b64) => {
                let cose_bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &b64,
                )
                .map_err(|e| {
                    ClientError::IdentityStorageFailed(format!("Base64 decode error: {e}"))
                })?;
                IdentityKeyPair::from_cose(&cose_bytes).map_err(|_| {
                    ClientError::IdentityStorageFailed(
                        "Failed to parse identity from COSE".to_string(),
                    )
                })?
            }
            None => {
                let keypair = IdentityKeyPair::generate();
                let cose_bytes = keypair.to_cose();
                let b64 =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cose_bytes);
                storage.set_item(&key, &b64).map_err(|_| {
                    ClientError::IdentityStorageFailed(
                        "Failed to write identity to localStorage".to_string(),
                    )
                })?;
                keypair
            }
        };

        Ok(Self { keypair })
    }
}

#[async_trait]
impl IdentityProvider for LocalStorageIdentityProvider {
    async fn identity(&self) -> IdentityKeyPair {
        self.keypair.clone()
    }
}

// ---------------------------------------------------------------------------
// LocalStorageConnectionStore
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionRecord {
    remote_fingerprint: IdentityFingerprint,
    cached_at: u64,
    last_connected_at: u64,
    #[serde(default)]
    transport_state: Option<Vec<u8>>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionCacheData {
    connections: Vec<ConnectionRecord>,
}

fn record_to_info(record: &ConnectionRecord) -> ConnectionInfo {
    let transport_state = record.transport_state.as_ref().and_then(|bytes| {
        PersistentTransportState::from_bytes(bytes)
            .map(MultiDeviceTransport::from)
            .ok()
    });
    ConnectionInfo {
        fingerprint: record.remote_fingerprint,
        name: record.name.clone(),
        cached_at: record.cached_at,
        last_connected_at: record.last_connected_at,
        transport_state,
    }
}

fn info_to_record(info: &ConnectionInfo) -> Result<ConnectionRecord, ClientError> {
    let transport_bytes = match &info.transport_state {
        Some(transport) => Some(
            PersistentTransportState::from(transport)
                .to_bytes()
                .map_err(|e| {
                    ClientError::NoiseProtocol(format!(
                        "Failed to serialize transport state: {e}"
                    ))
                })?,
        ),
        None => None,
    };
    Ok(ConnectionRecord {
        remote_fingerprint: info.fingerprint,
        cached_at: info.cached_at,
        last_connected_at: info.last_connected_at,
        transport_state: transport_bytes,
        name: info.name.clone(),
    })
}

/// Connection store backed by browser localStorage.
///
/// Stores sessions as a JSON array under the key
/// `bw_remote_connections_{name}`.
pub struct LocalStorageConnectionStore {
    storage_key: String,
    data: ConnectionCacheData,
}

impl LocalStorageConnectionStore {
    /// Load existing connections from localStorage, or create empty cache.
    pub fn load_or_create(name: &str) -> Result<Self, ClientError> {
        let storage_key = format!("bw_remote_connections_{name}");

        let data = match local_storage().ok().and_then(|s| s.get_item(&storage_key).ok().flatten())
        {
            Some(json) => serde_json::from_str(&json).unwrap_or_else(|e| {
                tracing::warn!("Corrupt connection cache in localStorage, resetting: {e}");
                ConnectionCacheData { connections: Vec::new() }
            }),
            None => ConnectionCacheData {
                connections: Vec::new(),
            },
        };

        Ok(Self { storage_key, data })
    }

    /// Clear all cached connections.
    pub fn clear(&mut self) -> Result<(), ClientError> {
        self.data.connections.clear();
        self.persist()
    }

    fn persist(&self) -> Result<(), ClientError> {
        let json = serde_json::to_string(&self.data)
            .map_err(|e| ClientError::ConnectionCache(format!("Serialization failed: {e}")))?;
        let storage = local_storage().map_err(|e| {
            ClientError::ConnectionCache(format!("localStorage not available: {e}"))
        })?;
        storage.set_item(&self.storage_key, &json).map_err(|_| {
            ClientError::ConnectionCache("Failed to write to localStorage".to_string())
        })?;
        Ok(())
    }
}

#[async_trait]
impl ConnectionStore for LocalStorageConnectionStore {
    async fn get(&self, fingerprint: &IdentityFingerprint) -> Option<ConnectionInfo> {
        self.data
            .connections
            .iter()
            .find(|s| s.remote_fingerprint == *fingerprint)
            .map(record_to_info)
    }

    async fn save(&mut self, connection: ConnectionInfo) -> Result<(), ClientError> {
        let record = info_to_record(&connection)?;
        if let Some(existing) = self
            .data
            .connections
            .iter_mut()
            .find(|s| s.remote_fingerprint == connection.fingerprint)
        {
            *existing = record;
        } else {
            self.data.connections.push(record);
        }
        self.persist()
    }

    async fn update(&mut self, update: ConnectionUpdate) -> Result<(), ClientError> {
        if let Some(connection) = self
            .data
            .connections
            .iter_mut()
            .find(|s| s.remote_fingerprint == update.fingerprint)
        {
            connection.last_connected_at = update.last_connected_at;
            self.persist()
        } else {
            Err(ClientError::ConnectionCache(
                "Connection not found".to_string(),
            ))
        }
    }

    async fn list(&self) -> Vec<ConnectionInfo> {
        self.data
            .connections
            .iter()
            .map(record_to_info)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Standalone WASM functions
// ---------------------------------------------------------------------------

/// List cached connections for an identity.
///
/// @param identity_name - Name of the localStorage identity
/// @returns Array of { fingerprint, name, cachedAt, lastConnectedAt }
#[wasm_bindgen(js_name = "listConnections")]
pub async fn list_connections(identity_name: &str) -> Result<JsValue, JsValue> {
    let store =
        LocalStorageConnectionStore::load_or_create(identity_name).map_err(client_error_to_js)?;
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

/// Clear all cached connections for an identity.
///
/// @param identity_name - Name of the localStorage identity
#[wasm_bindgen(js_name = "clearConnections")]
pub fn clear_connections(identity_name: &str) -> Result<(), JsValue> {
    let mut store =
        LocalStorageConnectionStore::load_or_create(identity_name).map_err(client_error_to_js)?;
    store.clear().map_err(client_error_to_js)?;
    Ok(())
}
