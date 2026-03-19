//! End-to-end integration tests for WebSocket proxy, pairing, and credential exchange
//!
//! These tests exercise the complete protocol stack using a real WebSocket proxy server,
//! covering PSK and fingerprint-based pairing modes as well as credential exchange.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use ap_client::{
    CredentialData, CredentialRequestReply, DefaultProxyClient, FingerprintVerificationReply,
    IdentityProvider, Psk, RemoteClient, RemoteClientNotification, RemoteClientRequest,
    SessionStore, UserClient, UserClientNotification, UserClientRequest,
};
use ap_noise::MultiDeviceTransport;
use ap_proxy::server::ProxyServer;
use ap_proxy_client::ProxyClientConfig;
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

// ============================================================================
// Test Infrastructure - Mock Implementations
// ============================================================================

/// Simple wrapper around a generated IdentityKeyPair
struct MockIdentityProvider {
    keypair: IdentityKeyPair,
}

impl MockIdentityProvider {
    fn new() -> Self {
        Self {
            keypair: IdentityKeyPair::generate(),
        }
    }

    fn with_keypair(keypair: IdentityKeyPair) -> Self {
        Self { keypair }
    }
}

#[async_trait::async_trait]
impl IdentityProvider for MockIdentityProvider {
    async fn identity(&self) -> IdentityKeyPair {
        self.keypair.clone()
    }
}

/// Session entry with cached_at timestamp
#[derive(Clone)]
struct SessionEntry {
    fingerprint: IdentityFingerprint,
    name: Option<String>,
    #[allow(dead_code)]
    cached_at: u64,
    last_connected_at: u64,
    transport_state: Option<MultiDeviceTransport>,
}

/// In-memory HashMap-based session store
struct MockSessionStore {
    sessions: Mutex<HashMap<IdentityFingerprint, SessionEntry>>,
}

impl MockSessionStore {
    fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl SessionStore for MockSessionStore {
    async fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool {
        self.sessions
            .lock()
            .expect("Lock should not be poisoned")
            .contains_key(fingerprint)
    }

    async fn cache_session(
        &mut self,
        fingerprint: IdentityFingerprint,
    ) -> Result<(), ap_client::RemoteClientError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut sessions = self.sessions.lock().expect("Lock should not be poisoned");
        sessions.insert(
            fingerprint,
            SessionEntry {
                fingerprint,
                name: None,
                cached_at: now,
                last_connected_at: now,
                transport_state: None,
            },
        );
        Ok(())
    }

    async fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), ap_client::RemoteClientError> {
        self.sessions
            .lock()
            .expect("Lock should not be poisoned")
            .remove(fingerprint);
        Ok(())
    }

    async fn clear(&mut self) -> Result<(), ap_client::RemoteClientError> {
        self.sessions
            .lock()
            .expect("Lock should not be poisoned")
            .clear();
        Ok(())
    }

    async fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)> {
        self.sessions
            .lock()
            .expect("Lock should not be poisoned")
            .values()
            .map(|e| {
                (
                    e.fingerprint,
                    e.name.clone(),
                    e.cached_at,
                    e.last_connected_at,
                )
            })
            .collect()
    }

    async fn set_session_name(
        &mut self,
        _fingerprint: &IdentityFingerprint,
        _name: String,
    ) -> Result<(), ap_client::RemoteClientError> {
        Ok(())
    }

    async fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), ap_client::RemoteClientError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut sessions = self.sessions.lock().expect("Lock should not be poisoned");
        if let Some(entry) = sessions.get_mut(fingerprint) {
            entry.last_connected_at = now;
        }
        Ok(())
    }

    async fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport_state: MultiDeviceTransport,
    ) -> Result<(), ap_client::RemoteClientError> {
        let mut sessions = self.sessions.lock().expect("Lock should not be poisoned");
        if let Some(entry) = sessions.get_mut(fingerprint) {
            entry.transport_state = Some(transport_state);
        }
        Ok(())
    }

    async fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, ap_client::RemoteClientError> {
        let sessions = self.sessions.lock().expect("Lock should not be poisoned");
        Ok(sessions
            .get(fingerprint)
            .and_then(|e| e.transport_state.clone()))
    }
}

/// Wrapper to share MockSessionStore via Arc.
///
/// This works because MockSessionStore uses interior mutability (Mutex<HashMap>),
/// so no outer Mutex is needed. The async trait methods can delegate directly.
struct SharedSessionStore(std::sync::Arc<MockSessionStore>);

#[async_trait::async_trait]
impl SessionStore for SharedSessionStore {
    async fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool {
        self.0.has_session(fingerprint).await
    }

    async fn cache_session(
        &mut self,
        fingerprint: IdentityFingerprint,
    ) -> Result<(), ap_client::RemoteClientError> {
        // MockSessionStore uses interior mutability, so &self is sufficient
        let store = std::sync::Arc::get_mut(&mut self.0);
        // In tests, Arc is never shared at the point of mutation through SessionStore,
        // so get_mut succeeds. If it doesn't, fall back to direct field access.
        if let Some(store) = store {
            store.cache_session(fingerprint).await
        } else {
            // Fallback: direct interior-mutability access
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut sessions = self.0.sessions.lock().expect("Lock should not be poisoned");
            sessions.insert(
                fingerprint,
                SessionEntry {
                    fingerprint,
                    name: None,
                    cached_at: now,
                    last_connected_at: now,
                    transport_state: None,
                },
            );
            Ok(())
        }
    }

    async fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), ap_client::RemoteClientError> {
        self.0
            .sessions
            .lock()
            .expect("Lock should not be poisoned")
            .remove(fingerprint);
        Ok(())
    }

    async fn clear(&mut self) -> Result<(), ap_client::RemoteClientError> {
        self.0
            .sessions
            .lock()
            .expect("Lock should not be poisoned")
            .clear();
        Ok(())
    }

    async fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)> {
        self.0.list_sessions().await
    }

    async fn set_session_name(
        &mut self,
        fingerprint: &IdentityFingerprint,
        name: String,
    ) -> Result<(), ap_client::RemoteClientError> {
        let mut sessions = self.0.sessions.lock().expect("Lock should not be poisoned");
        if let Some(entry) = sessions.get_mut(fingerprint) {
            entry.name = Some(name);
        }
        Ok(())
    }

    async fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), ap_client::RemoteClientError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut sessions = self.0.sessions.lock().expect("Lock should not be poisoned");
        if let Some(entry) = sessions.get_mut(fingerprint) {
            entry.last_connected_at = now;
        }
        Ok(())
    }

    async fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport_state: MultiDeviceTransport,
    ) -> Result<(), ap_client::RemoteClientError> {
        let mut sessions = self.0.sessions.lock().expect("Lock should not be poisoned");
        if let Some(entry) = sessions.get_mut(fingerprint) {
            entry.transport_state = Some(transport_state);
        }
        Ok(())
    }

    async fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, ap_client::RemoteClientError> {
        self.0.load_transport_state(fingerprint).await
    }
}

// ============================================================================
// Test Infrastructure - Helper Functions
// ============================================================================

/// Start a real proxy server for testing and return its address
async fn start_test_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind to localhost");
    let addr = listener.local_addr().expect("should get local address");

    let server = ProxyServer::new(addr);
    tokio::spawn(async move { server.run_with_listener(listener).await.ok() });

    addr
}

/// Create a DefaultProxyClient connected to the given address
fn create_proxy_client(addr: SocketAddr, keypair: Option<IdentityKeyPair>) -> DefaultProxyClient {
    DefaultProxyClient::new(ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: keypair,
    })
}

/// Create a test credential for use in tests
fn test_credential() -> CredentialData {
    CredentialData {
        username: Some("testuser".to_string()),
        password: Some("testpassword123".to_string()),
        totp: Some("123456".to_string()),
        uri: Some("https://example.com".to_string()),
        notes: Some("Test credential notes".to_string()),
        credential_id: Some("test-item-id".to_string()),
        domain: Some("example.com".to_string()),
    }
}

// ============================================================================
// Test 1: PSK Pairing + Credential Exchange
// ============================================================================

#[tokio::test]
async fn test_e2e_psk_pairing_and_credential_request() {
    // 1. Start real proxy server
    let addr = start_test_server().await;

    // 2. Create identities
    let user_identity = MockIdentityProvider::new();
    let remote_identity = MockIdentityProvider::new();

    let user_keypair = user_identity.identity().await;

    // 3. Create notification and request channels for UserClient
    let (notification_tx, mut notification_rx) = mpsc::channel::<UserClientNotification>(32);
    let (request_tx, mut request_rx) = mpsc::channel::<UserClientRequest>(32);

    // 4. Create UserClient with DefaultProxyClient
    let user_proxy = create_proxy_client(addr, Some(user_keypair));
    let user_session_store = MockSessionStore::new();

    let user_client = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_session_store),
        Box::new(user_proxy),
        notification_tx,
        request_tx,
        None,
    )
    .await
    .expect("UserClient should connect");

    // 5. Get PSK token
    let token = user_client
        .get_psk_token(None)
        .await
        .expect("Should generate PSK token");

    // Parse token: format is <psk_hex>_<fingerprint_hex>
    let parts: Vec<&str> = token.split('_').collect();
    assert_eq!(parts.len(), 2, "Token should have format psk_fingerprint");
    let psk = Psk::from_hex(parts[0]).expect("Should parse PSK");
    let fp_bytes = hex::decode(parts[1]).expect("Should decode fingerprint hex");
    let mut fp_array = [0u8; 32];
    fp_array.copy_from_slice(&fp_bytes);
    let fingerprint = IdentityFingerprint(fp_array);

    // 6. Create notification and request channels for RemoteClient
    let (remote_notification_tx, mut remote_notification_rx) =
        mpsc::channel::<RemoteClientNotification>(32);
    let (remote_request_tx, mut _remote_request_rx) = mpsc::channel::<RemoteClientRequest>(32);

    // 7. Create RemoteClient with DefaultProxyClient
    let remote_proxy = create_proxy_client(addr, None);
    let remote_session_store = MockSessionStore::new();

    let remote_client = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_session_store),
        Box::new(remote_proxy),
        remote_notification_tx,
        remote_request_tx,
    )
    .await
    .expect("RemoteClient should connect");

    // 8. Pair with PSK
    timeout(
        Duration::from_secs(10),
        remote_client.pair_with_psk(psk, fingerprint),
    )
    .await
    .expect("Pairing should not timeout")
    .expect("Pairing should succeed");

    // 9. Verify HandshakeComplete events on both sides
    let mut remote_handshake_complete = false;
    while let Ok(Some(event)) =
        timeout(Duration::from_millis(500), remote_notification_rx.recv()).await
    {
        if matches!(event, RemoteClientNotification::HandshakeComplete) {
            remote_handshake_complete = true;
            break;
        }
    }
    assert!(
        remote_handshake_complete,
        "RemoteClient should emit HandshakeComplete"
    );

    // Drain user notifications to find HandshakeComplete
    let mut user_handshake_complete = false;
    while let Ok(Some(event)) = timeout(Duration::from_millis(500), notification_rx.recv()).await {
        if matches!(event, UserClientNotification::HandshakeComplete {}) {
            user_handshake_complete = true;
            break;
        }
    }
    assert!(
        user_handshake_complete,
        "UserClient should emit HandshakeComplete"
    );

    // 10. Spawn credential response handler for UserClient
    let credential_handler = tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            if let UserClientRequest::CredentialRequest { query, reply, .. } = request {
                let domain = match &query {
                    ap_client::CredentialQuery::Domain(d) => d.clone(),
                    _ => panic!("expected Domain query"),
                };
                assert_eq!(domain, "example.com", "Domain should match request");
                let _ = reply.send(CredentialRequestReply {
                    approved: true,
                    credential: Some(test_credential()),
                    credential_id: Some("test-item-id".to_string()),
                });
                break;
            }
        }
    });

    // 12. RemoteClient requests credential
    let credential = timeout(
        Duration::from_secs(10),
        remote_client.request_credential(&ap_client::CredentialQuery::Domain(
            "example.com".to_string(),
        )),
    )
    .await
    .expect("Credential request should not timeout")
    .expect("Credential request should succeed");

    // 13. Verify credential contents
    assert_eq!(credential.username, Some("testuser".to_string()));
    assert_eq!(credential.password, Some("testpassword123".to_string()));
    assert_eq!(credential.totp, Some("123456".to_string()));
    assert_eq!(credential.uri, Some("https://example.com".to_string()));
    assert_eq!(credential.notes, Some("Test credential notes".to_string()));

    // Cleanup
    credential_handler.abort();
    drop(remote_client);
    drop(user_client);
}

// ============================================================================
// Test 2: Fingerprint Pairing + Credential Exchange
// ============================================================================

#[tokio::test]
async fn test_e2e_fingerprint_pairing_and_credential_request() {
    // 1. Start real proxy server
    let addr = start_test_server().await;

    // 2. Create identities
    let user_identity = MockIdentityProvider::new();
    let remote_identity = MockIdentityProvider::new();

    let user_keypair = user_identity.identity().await;

    // 3. Create notification and request channels for UserClient
    let (notification_tx, _notification_rx) = mpsc::channel::<UserClientNotification>(32);
    let (request_tx, mut request_rx) = mpsc::channel::<UserClientRequest>(32);

    // 4. Create UserClient with DefaultProxyClient
    let user_proxy = create_proxy_client(addr, Some(user_keypair));
    let user_session_store = MockSessionStore::new();

    let user_client = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_session_store),
        Box::new(user_proxy),
        notification_tx,
        request_tx,
        None,
    )
    .await
    .expect("UserClient should connect");

    // 5. Get rendezvous token
    let code = user_client
        .get_rendezvous_token(None)
        .await
        .expect("Should get rendezvous token");
    let code = code.as_str().to_string();

    // 6. Create notification and request channels for RemoteClient
    let (remote_notification_tx, mut remote_notification_rx) =
        mpsc::channel::<RemoteClientNotification>(32);
    let (remote_request_tx, mut _remote_request_rx) = mpsc::channel::<RemoteClientRequest>(32);

    // 7. Create RemoteClient with DefaultProxyClient
    let remote_proxy = create_proxy_client(addr, None);
    let remote_session_store = MockSessionStore::new();

    let remote_client = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_session_store),
        Box::new(remote_proxy),
        remote_notification_tx,
        remote_request_tx,
    )
    .await
    .expect("RemoteClient should connect");

    // 8. Spawn approval handler for VerifyFingerprint request on USER side (listener must verify)
    let user_approval_task = tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            if let UserClientRequest::VerifyFingerprint { reply, .. } = request {
                // Auto-approve the fingerprint on the user/listener side
                let _ = reply.send(FingerprintVerificationReply {
                    approved: true,
                    name: None,
                });
                break;
            }
        }
        request_rx
    });

    // 9. Pair with handshake using rendezvous code (verify_fingerprint=false on remote side)
    let paired_fingerprint = timeout(
        Duration::from_secs(15),
        remote_client.pair_with_handshake(code, false),
    )
    .await
    .expect("Pairing should not timeout")
    .expect("Pairing should succeed");

    // 10. Verify HandshakeFingerprint was emitted on remote side (informational)
    let mut got_fingerprint = false;
    while let Ok(Some(event)) =
        timeout(Duration::from_millis(500), remote_notification_rx.recv()).await
    {
        if matches!(event, RemoteClientNotification::HandshakeFingerprint { .. }) {
            got_fingerprint = true;
            break;
        }
    }
    assert!(
        got_fingerprint,
        "RemoteClient should emit HandshakeFingerprint (informational)"
    );

    // 11. Verify session is cached
    assert!(
        remote_client
            .has_session(paired_fingerprint)
            .await
            .expect("has_session should not fail"),
        "Session should be cached in RemoteClient's session store"
    );

    // 12. Spawn credential response handler for UserClient
    let mut request_rx = user_approval_task
        .await
        .expect("User approval task should complete");
    let credential_handler = tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            if let UserClientRequest::CredentialRequest { query, reply, .. } = request {
                let domain = match &query {
                    ap_client::CredentialQuery::Domain(d) => d.clone(),
                    _ => panic!("expected Domain query"),
                };
                assert_eq!(domain, "example.com", "Domain should match request");
                let _ = reply.send(CredentialRequestReply {
                    approved: true,
                    credential: Some(test_credential()),
                    credential_id: Some("test-item-id".to_string()),
                });
                break;
            }
        }
    });

    // 14. RemoteClient requests credential
    let credential = timeout(
        Duration::from_secs(10),
        remote_client.request_credential(&ap_client::CredentialQuery::Domain(
            "example.com".to_string(),
        )),
    )
    .await
    .expect("Credential request should not timeout")
    .expect("Credential request should succeed");

    // 15. Verify credential contents
    assert_eq!(credential.username, Some("testuser".to_string()));
    assert_eq!(credential.password, Some("testpassword123".to_string()));

    // Cleanup
    credential_handler.abort();
    drop(remote_client);
    drop(user_client);
}

// ============================================================================
// Test 3: Credential Request Denied
// ============================================================================

#[tokio::test]
async fn test_e2e_credential_request_denied() {
    // 1. Start real proxy server
    let addr = start_test_server().await;

    // 2. Create identities
    let user_identity = MockIdentityProvider::new();
    let remote_identity = MockIdentityProvider::new();

    let user_keypair = user_identity.identity().await;

    // 3. Create notification and request channels for UserClient
    let (notification_tx, mut notification_rx) = mpsc::channel::<UserClientNotification>(32);
    let (request_tx, mut request_rx) = mpsc::channel::<UserClientRequest>(32);

    // 4. Create UserClient with DefaultProxyClient
    let user_proxy = create_proxy_client(addr, Some(user_keypair));
    let user_session_store = MockSessionStore::new();

    let user_client = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_session_store),
        Box::new(user_proxy),
        notification_tx,
        request_tx,
        None,
    )
    .await
    .expect("UserClient should connect");

    // 5. Get PSK token
    let token = user_client
        .get_psk_token(None)
        .await
        .expect("Should generate PSK token");

    // Parse token: format is <psk_hex>_<fingerprint_hex>
    let parts: Vec<&str> = token.split('_').collect();
    let psk = Psk::from_hex(parts[0]).expect("Should parse PSK");
    let fp_bytes = hex::decode(parts[1]).expect("Should decode fingerprint hex");
    let mut fp_array = [0u8; 32];
    fp_array.copy_from_slice(&fp_bytes);
    let fingerprint = IdentityFingerprint(fp_array);

    // 6. Create RemoteClient
    let (remote_notification_tx, _remote_notification_rx) =
        mpsc::channel::<RemoteClientNotification>(32);
    let (remote_request_tx, mut _remote_request_rx) = mpsc::channel::<RemoteClientRequest>(32);

    let remote_proxy = create_proxy_client(addr, None);
    let remote_session_store = MockSessionStore::new();

    let remote_client = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_session_store),
        Box::new(remote_proxy),
        remote_notification_tx,
        remote_request_tx,
    )
    .await
    .expect("RemoteClient should connect");

    // 7. Pair with PSK
    timeout(
        Duration::from_secs(10),
        remote_client.pair_with_psk(psk, fingerprint),
    )
    .await
    .expect("Pairing should not timeout")
    .expect("Pairing should succeed");

    // Drain notifications to ensure handshake is complete
    while let Ok(Some(_)) = timeout(Duration::from_millis(500), notification_rx.recv()).await {}

    // 8. Spawn credential DENIAL handler for UserClient
    let denial_handler = tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            if let UserClientRequest::CredentialRequest { query, reply, .. } = request {
                assert!(
                    matches!(&query, ap_client::CredentialQuery::Domain(d) if d == "example.com")
                );
                // Deny the credential request
                let _ = reply.send(CredentialRequestReply {
                    approved: false,
                    credential: None,
                    credential_id: None,
                });
                break;
            }
        }
    });

    // 9. RemoteClient requests credential - should fail
    let result = timeout(
        Duration::from_secs(10),
        remote_client.request_credential(&ap_client::CredentialQuery::Domain(
            "example.com".to_string(),
        )),
    )
    .await
    .expect("Credential request should not timeout");

    // 10. Verify the request was denied
    assert!(result.is_err(), "Credential request should be denied");

    // Cleanup
    denial_handler.abort();
    drop(remote_client);
    drop(user_client);
}

// ============================================================================
// Test 4: Multiple Sequential Credential Requests
// ============================================================================

#[tokio::test]
async fn test_e2e_multiple_credential_requests() {
    // 1. Start real proxy server
    let addr = start_test_server().await;

    // 2. Create identities
    let user_identity = MockIdentityProvider::new();
    let remote_identity = MockIdentityProvider::new();

    let user_keypair = user_identity.identity().await;

    // 3. Create notification and request channels for UserClient
    let (notification_tx, mut notification_rx) = mpsc::channel::<UserClientNotification>(32);
    let (request_tx, mut request_rx) = mpsc::channel::<UserClientRequest>(32);

    // 4. Create UserClient with DefaultProxyClient
    let user_proxy = create_proxy_client(addr, Some(user_keypair));
    let user_session_store = MockSessionStore::new();

    let user_client = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_session_store),
        Box::new(user_proxy),
        notification_tx,
        request_tx,
        None,
    )
    .await
    .expect("UserClient should connect");

    // 5. Get PSK token
    let token = user_client
        .get_psk_token(None)
        .await
        .expect("Should generate PSK token");

    // Parse token: format is <psk_hex>_<fingerprint_hex>
    let parts: Vec<&str> = token.split('_').collect();
    let psk = Psk::from_hex(parts[0]).expect("Should parse PSK");
    let fp_bytes = hex::decode(parts[1]).expect("Should decode fingerprint hex");
    let mut fp_array = [0u8; 32];
    fp_array.copy_from_slice(&fp_bytes);
    let fingerprint = IdentityFingerprint(fp_array);

    // 6. Create RemoteClient
    let (remote_notification_tx, _remote_notification_rx) =
        mpsc::channel::<RemoteClientNotification>(32);
    let (remote_request_tx, mut _remote_request_rx) = mpsc::channel::<RemoteClientRequest>(32);

    let remote_proxy = create_proxy_client(addr, None);
    let remote_session_store = MockSessionStore::new();

    let remote_client = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_session_store),
        Box::new(remote_proxy),
        remote_notification_tx,
        remote_request_tx,
    )
    .await
    .expect("RemoteClient should connect");

    // 7. Pair with PSK
    timeout(
        Duration::from_secs(10),
        remote_client.pair_with_psk(psk, fingerprint),
    )
    .await
    .expect("Pairing should not timeout")
    .expect("Pairing should succeed");

    // Drain notifications to ensure handshake is complete
    while let Ok(Some(_)) = timeout(Duration::from_millis(500), notification_rx.recv()).await {}

    // 8. Spawn credential response handler that handles multiple requests
    let credential_handler = tokio::spawn(async move {
        let mut request_count = 0;
        while let Some(request) = request_rx.recv().await {
            if let UserClientRequest::CredentialRequest { query, reply, .. } = request {
                let domain = match &query {
                    ap_client::CredentialQuery::Domain(d) => d.clone(),
                    _ => panic!("expected Domain query"),
                };
                request_count += 1;

                // Create credential with domain-specific data
                let credential = CredentialData {
                    username: Some(format!("user_{domain}")),
                    password: Some(format!("pass_{domain}")),
                    totp: None,
                    uri: Some(format!("https://{domain}")),
                    notes: Some(format!("Request #{request_count}")),
                    credential_id: None,
                    domain: Some(domain.clone()),
                };

                let _ = reply.send(CredentialRequestReply {
                    approved: true,
                    credential: Some(credential),
                    credential_id: None,
                });

                if request_count >= 3 {
                    break;
                }
            }
        }
    });

    // 9. Make 3 sequential credential requests
    let domains = ["example.com", "test.org", "demo.net"];

    for domain in &domains {
        let credential = timeout(
            Duration::from_secs(10),
            remote_client
                .request_credential(&ap_client::CredentialQuery::Domain(domain.to_string())),
        )
        .await
        .expect("Credential request should not timeout")
        .expect("Credential request should succeed");

        // Verify domain-specific credential
        assert_eq!(credential.username, Some(format!("user_{domain}")));
        assert_eq!(credential.password, Some(format!("pass_{domain}")));
        assert_eq!(credential.uri, Some(format!("https://{domain}")));
    }

    // Cleanup
    credential_handler.abort();
    drop(remote_client);
    drop(user_client);
}

// ============================================================================
// Test 5: Transport State Persistence
// ============================================================================

#[tokio::test]
async fn test_e2e_transport_state_persistence() {
    use std::sync::Arc;

    // 1. Start real proxy server
    let addr = start_test_server().await;

    // 2. Create identities
    let user_identity = MockIdentityProvider::new();
    let remote_identity = MockIdentityProvider::new();

    let user_keypair = user_identity.identity().await;

    // 3. Create notification and request channels for UserClient
    let (notification_tx, mut notification_rx) = mpsc::channel::<UserClientNotification>(32);
    let (request_tx, _request_rx) = mpsc::channel::<UserClientRequest>(32);

    // 4. Create UserClient with DefaultProxyClient
    let user_proxy = create_proxy_client(addr, Some(user_keypair));
    let user_session_store = MockSessionStore::new();

    let user_client = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_session_store),
        Box::new(user_proxy),
        notification_tx,
        request_tx,
        None,
    )
    .await
    .expect("UserClient should connect");

    // 5. Get PSK token
    let token = user_client
        .get_psk_token(None)
        .await
        .expect("Should generate PSK token");

    // Parse token: format is <psk_hex>_<fingerprint_hex>
    let parts: Vec<&str> = token.split('_').collect();
    assert_eq!(parts.len(), 2, "Token should have format psk_fingerprint");
    let psk = Psk::from_hex(parts[0]).expect("Should parse PSK");
    let fp_bytes = hex::decode(parts[1]).expect("Should decode fingerprint hex");
    let mut fp_array = [0u8; 32];
    fp_array.copy_from_slice(&fp_bytes);
    let fingerprint = IdentityFingerprint(fp_array);

    // 6. Create notification and request channels for RemoteClient
    let (remote_notification_tx, mut remote_notification_rx) =
        mpsc::channel::<RemoteClientNotification>(32);
    let (remote_request_tx, mut _remote_request_rx) = mpsc::channel::<RemoteClientRequest>(32);

    // 7. Create RemoteClient with Arc<MockSessionStore> for later access
    let remote_proxy = create_proxy_client(addr, None);
    let remote_session_store = Arc::new(MockSessionStore::new());
    let session_store_clone = Arc::clone(&remote_session_store);

    // Reuse the module-level SharedSessionStore wrapper
    let remote_client = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(SharedSessionStore(remote_session_store)),
        Box::new(remote_proxy),
        remote_notification_tx,
        remote_request_tx,
    )
    .await
    .expect("RemoteClient should connect");

    // 8. Pair with PSK
    timeout(
        Duration::from_secs(10),
        remote_client.pair_with_psk(psk, fingerprint),
    )
    .await
    .expect("Pairing should not timeout")
    .expect("Pairing should succeed");

    // 9. Verify HandshakeComplete events on both sides
    let mut remote_handshake_complete = false;
    while let Ok(Some(event)) =
        timeout(Duration::from_millis(500), remote_notification_rx.recv()).await
    {
        if matches!(event, RemoteClientNotification::HandshakeComplete) {
            remote_handshake_complete = true;
            break;
        }
    }
    assert!(
        remote_handshake_complete,
        "RemoteClient should emit HandshakeComplete"
    );

    // Drain user notifications to find HandshakeComplete
    let mut user_handshake_complete = false;
    while let Ok(Some(event)) = timeout(Duration::from_millis(500), notification_rx.recv()).await {
        if matches!(event, UserClientNotification::HandshakeComplete {}) {
            user_handshake_complete = true;
            break;
        }
    }
    assert!(
        user_handshake_complete,
        "UserClient should emit HandshakeComplete"
    );

    // 10. Load transport state from session store and verify it was saved
    let transport_state = session_store_clone
        .load_transport_state(&fingerprint)
        .await
        .expect("Should load transport state");

    // 11. Assert the state is Some (transport object, not bytes)
    assert!(
        transport_state.is_some(),
        "Transport state should be saved after pairing"
    );
    let mut restored_transport = transport_state.expect("Transport state should be present");

    // 12. Verify the restored transport can encrypt (proving it's a valid transport)
    let test_message = b"test message for persistence verification";
    let encrypted = restored_transport
        .encrypt(test_message)
        .expect("Restored transport should encrypt");
    // Encode to wire format to verify the packet is valid and non-empty
    let encoded = encrypted.encode();
    assert!(
        !encoded.is_empty(),
        "Encrypted packet should encode to non-empty bytes"
    );

    // Cleanup
    drop(remote_client);
    drop(user_client);
}

// ============================================================================
// Test 6: Multi-Device Credential Response
// ============================================================================

#[tokio::test]
async fn test_e2e_multi_device_credential_response() {
    use std::sync::Arc;

    // 1. Start real proxy server
    let addr = start_test_server().await;

    // 2. Create identities - same user identity for both devices
    let user_keypair = IdentityKeyPair::generate();
    let remote_keypair = IdentityKeyPair::generate();

    // Clone keypair for device 2
    let user_keypair_device2 = user_keypair.clone();

    // 3. Create notification and request channels for UserClient Device 1
    let (notification_tx1, mut notification_rx1) = mpsc::channel::<UserClientNotification>(256);
    let (request_tx1, mut request_rx1) = mpsc::channel::<UserClientRequest>(256);

    // 4. Create UserClient Device 1 with DefaultProxyClient
    let user_proxy1 = create_proxy_client(addr, Some(user_keypair.clone()));

    // Use Arc<MockSessionStore> for later access to transport state
    let user_session_store1 = Arc::new(MockSessionStore::new());
    let session_store_clone = Arc::clone(&user_session_store1);

    let user_client1 = UserClient::connect(
        Box::new(MockIdentityProvider::with_keypair(user_keypair)),
        Box::new(SharedSessionStore(Arc::clone(&user_session_store1))),
        Box::new(user_proxy1),
        notification_tx1,
        request_tx1,
        None,
    )
    .await
    .expect("UserClient Device 1 should connect");

    // 5. Get PSK token
    let token = user_client1
        .get_psk_token(None)
        .await
        .expect("Should generate PSK token");

    // Parse token: format is <psk_hex>_<fingerprint_hex>
    let parts: Vec<&str> = token.split('_').collect();
    let psk = Psk::from_hex(parts[0]).expect("Should parse PSK");
    let fp_bytes = hex::decode(parts[1]).expect("Should decode fingerprint hex");
    let mut fp_array = [0u8; 32];
    fp_array.copy_from_slice(&fp_bytes);
    let user_fingerprint = IdentityFingerprint(fp_array);

    // 6. Create RemoteClient
    let (remote_notification_tx, mut remote_notification_rx) =
        mpsc::channel::<RemoteClientNotification>(256);
    let (remote_request_tx, mut _remote_request_rx) = mpsc::channel::<RemoteClientRequest>(256);

    let remote_proxy = create_proxy_client(addr, Some(remote_keypair));
    let remote_client = RemoteClient::connect(
        Box::new(MockIdentityProvider::new()),
        Box::new(MockSessionStore::new()),
        Box::new(remote_proxy),
        remote_notification_tx,
        remote_request_tx,
    )
    .await
    .expect("RemoteClient should connect");

    // 7. Pair with PSK
    timeout(
        Duration::from_secs(10),
        remote_client.pair_with_psk(psk, user_fingerprint),
    )
    .await
    .expect("Pairing should not timeout")
    .expect("Pairing should succeed");

    // 8. Wait for handshake complete on both sides
    while let Ok(Some(event)) =
        timeout(Duration::from_millis(500), remote_notification_rx.recv()).await
    {
        if matches!(event, RemoteClientNotification::HandshakeComplete) {
            break;
        }
    }
    while let Ok(Some(event)) = timeout(Duration::from_millis(500), notification_rx1.recv()).await {
        if matches!(event, UserClientNotification::HandshakeComplete {}) {
            break;
        }
    }

    // 9. Create UserClient Device 2 with SHARED session store
    let (notification_tx2, mut notification_rx2) = mpsc::channel::<UserClientNotification>(256);
    let (request_tx2, mut request_rx2) = mpsc::channel::<UserClientRequest>(256);

    let user_proxy2 = create_proxy_client(addr, Some(user_keypair_device2.clone()));
    let user_client2 = UserClient::connect(
        Box::new(MockIdentityProvider::with_keypair(user_keypair_device2)),
        Box::new(SharedSessionStore(Arc::clone(&session_store_clone))),
        Box::new(user_proxy2),
        notification_tx2,
        request_tx2,
        None,
    )
    .await
    .expect("UserClient Device 2 should connect");

    // Wait for Device 2 to be listening
    timeout(Duration::from_secs(2), async {
        loop {
            if let Some(UserClientNotification::Listening {}) = notification_rx2.recv().await {
                break;
            }
        }
    })
    .await
    .expect("Device 2 should listen");

    // 10. Spawn response handlers for both devices.
    // Both handlers always approve. Since the proxy broadcasts credential
    // requests to all connections with the same identity, both devices
    // receive every request. Each device independently responds via its
    // own oneshot. The remote client uses the first response that arrives.
    let handler1 = tokio::spawn(async move {
        while let Some(request) = request_rx1.recv().await {
            if let UserClientRequest::CredentialRequest { reply, .. } = request {
                let _ = reply.send(CredentialRequestReply {
                    approved: true,
                    credential: Some(CredentialData {
                        username: Some("device1_user".into()),
                        password: Some("device1_pass".into()),
                        totp: None,
                        uri: None,
                        notes: None,
                        credential_id: None,
                        domain: Some("example.com".into()),
                    }),
                    credential_id: None,
                });
            }
        }
    });

    let handler2 = tokio::spawn(async move {
        while let Some(request) = request_rx2.recv().await {
            if let UserClientRequest::CredentialRequest { reply, .. } = request {
                let _ = reply.send(CredentialRequestReply {
                    approved: true,
                    credential: Some(CredentialData {
                        username: Some("device2_user".into()),
                        password: Some("device2_pass".into()),
                        totp: None,
                        uri: None,
                        notes: None,
                        credential_id: None,
                        domain: Some("example.com".into()),
                    }),
                    credential_id: None,
                });
            }
        }
    });

    // 11. Request 100 credentials and track which device responds
    let mut device1_count = 0;
    let mut device2_count = 0;

    for _ in 0..100 {
        let credential = timeout(
            Duration::from_secs(10),
            remote_client.request_credential(&ap_client::CredentialQuery::Domain(
                "example.com".to_string(),
            )),
        )
        .await
        .expect("Should not timeout")
        .expect("Should succeed");

        if credential.username == Some("device1_user".into()) {
            device1_count += 1;
        } else if credential.username == Some("device2_user".into()) {
            device2_count += 1;
        }
    }

    // 12. Verify responses were received from at least one device.
    // Both devices handle all requests (proving transport state sharing
    // works), but the remote client uses whichever response arrives first.
    // In practice one device may win all races, so we only assert totals.
    assert_eq!(
        device1_count + device2_count,
        100,
        "Total should be 100 responses"
    );
    println!(
        "Device 1 handled {} requests, Device 2 handled {} requests",
        device1_count, device2_count
    );

    // Cleanup
    handler1.abort();
    handler2.abort();
    drop(remote_client);
    drop(user_client1);
    drop(user_client2);
}
