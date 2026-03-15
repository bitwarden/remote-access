//! End-to-end integration tests for WebSocket proxy, pairing, and credential exchange
//!
//! These tests exercise the complete protocol stack using a real WebSocket proxy server,
//! covering PSK and fingerprint-based pairing modes as well as credential exchange.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use bw_noise_protocol::MultiDeviceTransport;
use bw_proxy::server::ProxyServer;
use bw_proxy_client::ProxyClientConfig;
use bw_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use bw_rat_client::{
    DefaultProxyClient, IdentityProvider, Psk, RemoteClient, RemoteClientEvent,
    RemoteClientResponse, SessionStore, UserClient, UserClientEvent, UserClientResponse,
    UserCredentialData,
};
use tokio::sync::mpsc;
use tokio::task::LocalSet;
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

impl IdentityProvider for MockIdentityProvider {
    fn identity(&self) -> &IdentityKeyPair {
        &self.keypair
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

impl SessionStore for MockSessionStore {
    fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool {
        self.sessions
            .lock()
            .expect("Lock should not be poisoned")
            .contains_key(fingerprint)
    }

    fn cache_session(
        &mut self,
        fingerprint: IdentityFingerprint,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
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

    fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.sessions
            .lock()
            .expect("Lock should not be poisoned")
            .remove(fingerprint);
        Ok(())
    }

    fn clear(&mut self) -> Result<(), bw_rat_client::RemoteClientError> {
        self.sessions
            .lock()
            .expect("Lock should not be poisoned")
            .clear();
        Ok(())
    }

    fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)> {
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

    fn set_session_name(
        &mut self,
        _fingerprint: &IdentityFingerprint,
        _name: String,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        Ok(())
    }

    fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
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

    fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport_state: MultiDeviceTransport,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        let mut sessions = self.sessions.lock().expect("Lock should not be poisoned");
        if let Some(entry) = sessions.get_mut(fingerprint) {
            entry.transport_state = Some(transport_state);
        }
        Ok(())
    }

    fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, bw_rat_client::RemoteClientError> {
        let sessions = self.sessions.lock().expect("Lock should not be poisoned");
        Ok(sessions
            .get(fingerprint)
            .and_then(|e| e.transport_state.clone()))
    }
}

/// Wrapper to share MockSessionStore via Arc<Mutex<>>
struct SharedSessionStore(std::sync::Arc<Mutex<MockSessionStore>>);

impl SessionStore for SharedSessionStore {
    fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool {
        self.0
            .lock()
            .expect("Lock should not be poisoned")
            .has_session(fingerprint)
    }

    fn cache_session(
        &mut self,
        fingerprint: IdentityFingerprint,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("Lock should not be poisoned")
            .cache_session(fingerprint)
    }

    fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("Lock should not be poisoned")
            .remove_session(fingerprint)
    }

    fn clear(&mut self) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0.lock().expect("Lock should not be poisoned").clear()
    }

    fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)> {
        self.0
            .lock()
            .expect("Lock should not be poisoned")
            .list_sessions()
    }

    fn set_session_name(
        &mut self,
        fingerprint: &IdentityFingerprint,
        name: String,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("Lock should not be poisoned")
            .set_session_name(fingerprint, name)
    }

    fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("Lock should not be poisoned")
            .update_last_connected(fingerprint)
    }

    fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport_state: MultiDeviceTransport,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("Lock should not be poisoned")
            .save_transport_state(fingerprint, transport_state)
    }

    fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("Lock should not be poisoned")
            .load_transport_state(fingerprint)
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
fn test_credential() -> UserCredentialData {
    UserCredentialData {
        username: Some("testuser".to_string()),
        password: Some("testpassword123".to_string()),
        totp: Some("123456".to_string()),
        uri: Some("https://example.com".to_string()),
        notes: Some("Test credential notes".to_string()),
        credential_id: Some("test-item-id".to_string()),
    }
}

// ============================================================================
// Test 1: PSK Pairing + Credential Exchange
// ============================================================================

#[tokio::test(flavor = "current_thread")]
async fn test_e2e_psk_pairing_and_credential_request() {
    let local = LocalSet::new();
    local
        .run_until(async {
            // 1. Start real proxy server
            let addr = start_test_server().await;

            // 2. Create identities
            let user_identity = MockIdentityProvider::new();
            let remote_identity = MockIdentityProvider::new();

            let user_keypair = user_identity.identity().clone();

            // 3. Create event and response channels for UserClient
            let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
            let (user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

            // 4. Create UserClient with DefaultProxyClient
            let user_proxy = create_proxy_client(addr, Some(user_keypair));
            let user_session_store = MockSessionStore::new();

            let mut user_client = UserClient::listen(
                Box::new(user_identity),
                Box::new(user_session_store),
                Box::new(user_proxy),
            )
            .await
            .expect("UserClient should connect");

            // 5. Spawn UserClient's enable_psk in a local task
            let user_task = tokio::task::spawn_local(async move {
                user_client
                    .enable_psk(user_event_tx, user_response_rx)
                    .await
            });

            // 6. Wait for PskTokenGenerated event and parse token
            let (psk, fingerprint) = timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(UserClientEvent::PskTokenGenerated { token }) =
                        user_event_rx.recv().await
                    {
                        // Parse token: format is <psk_hex>_<fingerprint_hex>
                        let parts: Vec<&str> = token.split('_').collect();
                        assert_eq!(parts.len(), 2, "Token should have format psk_fingerprint");

                        let psk = Psk::from_hex(parts[0]).expect("Should parse PSK");
                        let fp_bytes =
                            hex::decode(parts[1]).expect("Should decode fingerprint hex");
                        let mut fp_array = [0u8; 32];
                        fp_array.copy_from_slice(&fp_bytes);
                        let fingerprint = IdentityFingerprint(fp_array);

                        return (psk, fingerprint);
                    }
                }
            })
            .await
            .expect("Should receive PskTokenGenerated event");

            // 7. Create event and response channels for RemoteClient
            let (remote_event_tx, mut remote_event_rx) = mpsc::channel::<RemoteClientEvent>(32);
            let (_remote_response_tx, remote_response_rx) =
                mpsc::channel::<RemoteClientResponse>(32);

            // 8. Create RemoteClient with DefaultProxyClient
            let remote_proxy = create_proxy_client(addr, None);
            let remote_session_store = MockSessionStore::new();

            let mut remote_client = RemoteClient::new(
                Box::new(remote_identity),
                Box::new(remote_session_store),
                remote_event_tx.clone(),
                remote_response_rx,
                Box::new(remote_proxy),
            )
            .await
            .expect("RemoteClient should connect");

            // 9. Pair with PSK
            timeout(
                Duration::from_secs(10),
                remote_client.pair_with_psk(psk, fingerprint),
            )
            .await
            .expect("Pairing should not timeout")
            .expect("Pairing should succeed");

            // 10. Verify HandshakeComplete events on both sides
            let mut remote_handshake_complete = false;
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(500), remote_event_rx.recv()).await
            {
                if matches!(event, RemoteClientEvent::HandshakeComplete) {
                    remote_handshake_complete = true;
                    break;
                }
            }
            assert!(
                remote_handshake_complete,
                "RemoteClient should emit HandshakeComplete"
            );

            // Drain user events to find HandshakeComplete
            let mut user_handshake_complete = false;
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(500), user_event_rx.recv()).await
            {
                if matches!(event, UserClientEvent::HandshakeComplete {}) {
                    user_handshake_complete = true;
                    break;
                }
            }
            assert!(
                user_handshake_complete,
                "UserClient should emit HandshakeComplete"
            );

            // 11. Verify remote_client is ready
            assert!(remote_client.is_ready(), "RemoteClient should be ready");

            // 12. Spawn credential response handler for UserClient
            let credential_handler = tokio::task::spawn_local(async move {
                while let Some(event) = user_event_rx.recv().await {
                    if let UserClientEvent::CredentialRequest {
                        request_id,
                        session_id,
                        domain,
                    } = event
                    {
                        assert_eq!(domain, "example.com", "Domain should match request");
                        user_response_tx
                            .send(UserClientResponse::RespondCredential {
                                request_id,
                                session_id,
                                domain,
                                approved: true,
                                credential: Some(test_credential()),
                                credential_id: Some("test-item-id".to_string()),
                            })
                            .await
                            .expect("Should send response");
                        break;
                    }
                }
            });

            // 13. RemoteClient requests credential
            let credential = timeout(
                Duration::from_secs(10),
                remote_client.request_credential("example.com"),
            )
            .await
            .expect("Credential request should not timeout")
            .expect("Credential request should succeed");

            // 14. Verify credential contents
            assert_eq!(credential.username, Some("testuser".to_string()));
            assert_eq!(credential.password, Some("testpassword123".to_string()));
            assert_eq!(credential.totp, Some("123456".to_string()));
            assert_eq!(credential.uri, Some("https://example.com".to_string()));
            assert_eq!(credential.notes, Some("Test credential notes".to_string()));

            // Cleanup
            credential_handler.abort();
            remote_client.close().await;
            user_task.abort();
        })
        .await;
}

// ============================================================================
// Test 2: Fingerprint Pairing + Credential Exchange
// ============================================================================

#[tokio::test(flavor = "current_thread")]
async fn test_e2e_fingerprint_pairing_and_credential_request() {
    let local = LocalSet::new();
    local
        .run_until(async {
            // 1. Start real proxy server
            let addr = start_test_server().await;

            // 2. Create identities
            let user_identity = MockIdentityProvider::new();
            let remote_identity = MockIdentityProvider::new();

            let user_keypair = user_identity.identity().clone();

            // 3. Create event and response channels for UserClient
            let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
            let (user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

            // 4. Create UserClient with DefaultProxyClient
            let user_proxy = create_proxy_client(addr, Some(user_keypair));
            let user_session_store = MockSessionStore::new();

            let mut user_client = UserClient::listen(
                Box::new(user_identity),
                Box::new(user_session_store),
                Box::new(user_proxy),
            )
            .await
            .expect("UserClient should connect");

            // 5. Spawn UserClient's enable_rendezvous in a local task
            let user_task = tokio::task::spawn_local(async move {
                user_client
                    .enable_rendezvous(user_event_tx, user_response_rx)
                    .await
            });

            // 6. Wait for RendevouzCodeGenerated event
            let code = timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(UserClientEvent::RendevouzCodeGenerated { code }) =
                        user_event_rx.recv().await
                    {
                        return code;
                    }
                }
            })
            .await
            .expect("Should receive RendevouzCodeGenerated event");

            // 7. Create event and response channels for RemoteClient
            let (remote_event_tx, mut remote_event_rx) = mpsc::channel::<RemoteClientEvent>(32);
            let (_remote_response_tx, remote_response_rx) =
                mpsc::channel::<RemoteClientResponse>(32);

            // 8. Create RemoteClient with DefaultProxyClient
            let remote_proxy = create_proxy_client(addr, None);
            let remote_session_store = MockSessionStore::new();

            let mut remote_client = RemoteClient::new(
                Box::new(remote_identity),
                Box::new(remote_session_store),
                remote_event_tx.clone(),
                remote_response_rx,
                Box::new(remote_proxy),
            )
            .await
            .expect("RemoteClient should connect");

            // 9. Spawn approval handler for HandshakeFingerprint event on USER side (listener must verify)
            let user_approval_task = tokio::task::spawn_local(async move {
                while let Some(event) = user_event_rx.recv().await {
                    if let UserClientEvent::HandshakeFingerprint { fingerprint: _ } = event {
                        // Auto-approve the fingerprint on the user/listener side
                        user_response_tx
                            .send(UserClientResponse::VerifyFingerprint {
                                approved: true,
                                name: None,
                            })
                            .await
                            .expect("Should send fingerprint approval");
                        break;
                    }
                }
                (user_event_rx, user_response_tx)
            });

            // 10. Pair with handshake using rendezvous code (verify_fingerprint=false on remote side)
            let paired_fingerprint = timeout(
                Duration::from_secs(15),
                remote_client.pair_with_handshake(&code, false),
            )
            .await
            .expect("Pairing should not timeout")
            .expect("Pairing should succeed");

            // 11. Verify HandshakeFingerprint was emitted on remote side (informational)
            let mut got_fingerprint = false;
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(500), remote_event_rx.recv()).await
            {
                if matches!(event, RemoteClientEvent::HandshakeFingerprint { .. }) {
                    got_fingerprint = true;
                    break;
                }
            }
            assert!(
                got_fingerprint,
                "RemoteClient should emit HandshakeFingerprint (informational)"
            );

            // 12. Verify remote_client is ready
            assert!(remote_client.is_ready(), "RemoteClient should be ready");

            // 13. Verify session is cached
            assert!(
                remote_client
                    .session_store()
                    .has_session(&paired_fingerprint),
                "Session should be cached in RemoteClient's session store"
            );

            // 14. Spawn credential response handler for UserClient
            let (mut user_event_rx, user_response_tx) = user_approval_task
                .await
                .expect("User approval task should complete");
            let credential_handler = tokio::task::spawn_local(async move {
                while let Some(event) = user_event_rx.recv().await {
                    if let UserClientEvent::CredentialRequest {
                        request_id,
                        session_id,
                        domain,
                    } = event
                    {
                        assert_eq!(domain, "example.com", "Domain should match request");
                        user_response_tx
                            .send(UserClientResponse::RespondCredential {
                                request_id,
                                session_id,
                                domain,
                                approved: true,
                                credential: Some(test_credential()),
                                credential_id: Some("test-item-id".to_string()),
                            })
                            .await
                            .expect("Should send response");
                        break;
                    }
                }
            });

            // 15. RemoteClient requests credential
            let credential = timeout(
                Duration::from_secs(10),
                remote_client.request_credential("example.com"),
            )
            .await
            .expect("Credential request should not timeout")
            .expect("Credential request should succeed");

            // 16. Verify credential contents
            assert_eq!(credential.username, Some("testuser".to_string()));
            assert_eq!(credential.password, Some("testpassword123".to_string()));

            // Cleanup
            credential_handler.abort();
            remote_client.close().await;
            user_task.abort();
        })
        .await;
}

// ============================================================================
// Test 3: Credential Request Denied
// ============================================================================

#[tokio::test(flavor = "current_thread")]
async fn test_e2e_credential_request_denied() {
    let local = LocalSet::new();
    local
        .run_until(async {
            // 1. Start real proxy server
            let addr = start_test_server().await;

            // 2. Create identities
            let user_identity = MockIdentityProvider::new();
            let remote_identity = MockIdentityProvider::new();

            let user_keypair = user_identity.identity().clone();

            // 3. Create event and response channels for UserClient
            let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
            let (user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

            // 4. Create UserClient with DefaultProxyClient
            let user_proxy = create_proxy_client(addr, Some(user_keypair));
            let user_session_store = MockSessionStore::new();

            let mut user_client = UserClient::listen(
                Box::new(user_identity),
                Box::new(user_session_store),
                Box::new(user_proxy),
            )
            .await
            .expect("UserClient should connect");

            // 5. Spawn UserClient's enable_psk in a local task
            let user_task = tokio::task::spawn_local(async move {
                user_client
                    .enable_psk(user_event_tx, user_response_rx)
                    .await
            });

            // 6. Wait for PskTokenGenerated event and parse token
            let (psk, fingerprint) = timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(UserClientEvent::PskTokenGenerated { token }) =
                        user_event_rx.recv().await
                    {
                        let parts: Vec<&str> = token.split('_').collect();
                        let psk = Psk::from_hex(parts[0]).expect("Should parse PSK");
                        let fp_bytes =
                            hex::decode(parts[1]).expect("Should decode fingerprint hex");
                        let mut fp_array = [0u8; 32];
                        fp_array.copy_from_slice(&fp_bytes);
                        let fingerprint = IdentityFingerprint(fp_array);
                        return (psk, fingerprint);
                    }
                }
            })
            .await
            .expect("Should receive PskTokenGenerated event");

            // 7. Create RemoteClient
            let (remote_event_tx, _remote_event_rx) = mpsc::channel::<RemoteClientEvent>(32);
            let (_remote_response_tx, remote_response_rx) =
                mpsc::channel::<RemoteClientResponse>(32);

            let remote_proxy = create_proxy_client(addr, None);
            let remote_session_store = MockSessionStore::new();

            let mut remote_client = RemoteClient::new(
                Box::new(remote_identity),
                Box::new(remote_session_store),
                remote_event_tx,
                remote_response_rx,
                Box::new(remote_proxy),
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

            // Drain events to ensure handshake is complete
            while let Ok(Some(_)) = timeout(Duration::from_millis(500), user_event_rx.recv()).await
            {
            }

            // 9. Spawn credential DENIAL handler for UserClient
            let denial_handler = tokio::task::spawn_local(async move {
                while let Some(event) = user_event_rx.recv().await {
                    if let UserClientEvent::CredentialRequest {
                        request_id,
                        session_id,
                        domain,
                    } = event
                    {
                        // Deny the credential request
                        user_response_tx
                            .send(UserClientResponse::RespondCredential {
                                request_id,
                                session_id,
                                domain,
                                approved: false,
                                credential: None,
                                credential_id: None,
                            })
                            .await
                            .expect("Should send denial response");
                        break;
                    }
                }
            });

            // 10. RemoteClient requests credential - should fail
            let result = timeout(
                Duration::from_secs(10),
                remote_client.request_credential("example.com"),
            )
            .await
            .expect("Credential request should not timeout");

            // 11. Verify the request was denied
            assert!(result.is_err(), "Credential request should be denied");

            // Cleanup
            denial_handler.abort();
            remote_client.close().await;
            user_task.abort();
        })
        .await;
}

// ============================================================================
// Test 4: Multiple Sequential Credential Requests
// ============================================================================

#[tokio::test(flavor = "current_thread")]
async fn test_e2e_multiple_credential_requests() {
    let local = LocalSet::new();
    local
        .run_until(async {
            // 1. Start real proxy server
            let addr = start_test_server().await;

            // 2. Create identities
            let user_identity = MockIdentityProvider::new();
            let remote_identity = MockIdentityProvider::new();

            let user_keypair = user_identity.identity().clone();

            // 3. Create event and response channels for UserClient
            let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
            let (user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

            // 4. Create UserClient with DefaultProxyClient
            let user_proxy = create_proxy_client(addr, Some(user_keypair));
            let user_session_store = MockSessionStore::new();

            let mut user_client = UserClient::listen(
                Box::new(user_identity),
                Box::new(user_session_store),
                Box::new(user_proxy),
            )
            .await
            .expect("UserClient should connect");

            // 5. Spawn UserClient's enable_psk in a local task
            let user_task = tokio::task::spawn_local(async move {
                user_client
                    .enable_psk(user_event_tx, user_response_rx)
                    .await
            });

            // 6. Wait for PskTokenGenerated event and parse token
            let (psk, fingerprint) = timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(UserClientEvent::PskTokenGenerated { token }) =
                        user_event_rx.recv().await
                    {
                        let parts: Vec<&str> = token.split('_').collect();
                        let psk = Psk::from_hex(parts[0]).expect("Should parse PSK");
                        let fp_bytes =
                            hex::decode(parts[1]).expect("Should decode fingerprint hex");
                        let mut fp_array = [0u8; 32];
                        fp_array.copy_from_slice(&fp_bytes);
                        let fingerprint = IdentityFingerprint(fp_array);
                        return (psk, fingerprint);
                    }
                }
            })
            .await
            .expect("Should receive PskTokenGenerated event");

            // 7. Create RemoteClient
            let (remote_event_tx, _remote_event_rx) = mpsc::channel::<RemoteClientEvent>(32);
            let (_remote_response_tx, remote_response_rx) =
                mpsc::channel::<RemoteClientResponse>(32);

            let remote_proxy = create_proxy_client(addr, None);
            let remote_session_store = MockSessionStore::new();

            let mut remote_client = RemoteClient::new(
                Box::new(remote_identity),
                Box::new(remote_session_store),
                remote_event_tx,
                remote_response_rx,
                Box::new(remote_proxy),
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

            // Drain events to ensure handshake is complete
            while let Ok(Some(_)) = timeout(Duration::from_millis(500), user_event_rx.recv()).await
            {
            }

            // 9. Spawn credential response handler that handles multiple requests
            let credential_handler = tokio::task::spawn_local(async move {
                let mut request_count = 0;
                while let Some(event) = user_event_rx.recv().await {
                    if let UserClientEvent::CredentialRequest {
                        request_id,
                        session_id,
                        domain,
                    } = event
                    {
                        request_count += 1;

                        // Create credential with domain-specific data
                        let credential = UserCredentialData {
                            username: Some(format!("user_{domain}")),
                            password: Some(format!("pass_{domain}")),
                            totp: None,
                            uri: Some(format!("https://{domain}")),
                            notes: Some(format!("Request #{request_count}")),
                            credential_id: None,
                        };

                        user_response_tx
                            .send(UserClientResponse::RespondCredential {
                                request_id,
                                session_id,
                                domain,
                                approved: true,
                                credential: Some(credential),
                                credential_id: None,
                            })
                            .await
                            .expect("Should send response");

                        if request_count >= 3 {
                            break;
                        }
                    }
                }
            });

            // 10. Make 3 sequential credential requests
            let domains = ["example.com", "test.org", "demo.net"];

            for domain in &domains {
                let credential = timeout(
                    Duration::from_secs(10),
                    remote_client.request_credential(domain),
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
            remote_client.close().await;
            user_task.abort();
        })
        .await;
}

// ============================================================================
// Test 5: Transport State Persistence
// ============================================================================

#[tokio::test(flavor = "current_thread")]
async fn test_e2e_transport_state_persistence() {
    use std::sync::Arc;

    let local = LocalSet::new();
    local
        .run_until(async {
            // 1. Start real proxy server
            let addr = start_test_server().await;

            // 2. Create identities
            let user_identity = MockIdentityProvider::new();
            let remote_identity = MockIdentityProvider::new();

            let user_keypair = user_identity.identity().clone();

            // 3. Create event and response channels for UserClient
            let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
            let (_user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

            // 4. Create UserClient with DefaultProxyClient
            let user_proxy = create_proxy_client(addr, Some(user_keypair));
            let user_session_store = MockSessionStore::new();

            let mut user_client = UserClient::listen(
                Box::new(user_identity),
                Box::new(user_session_store),
                Box::new(user_proxy),
            )
            .await
            .expect("UserClient should connect");

            // 5. Spawn UserClient's enable_psk in a local task
            let user_task = tokio::task::spawn_local(async move {
                user_client
                    .enable_psk(user_event_tx, user_response_rx)
                    .await
            });

            // 6. Wait for PskTokenGenerated event and parse token
            let (psk, fingerprint) = timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(UserClientEvent::PskTokenGenerated { token }) =
                        user_event_rx.recv().await
                    {
                        let parts: Vec<&str> = token.split('_').collect();
                        assert_eq!(parts.len(), 2, "Token should have format psk_fingerprint");

                        let psk = Psk::from_hex(parts[0]).expect("Should parse PSK");
                        let fp_bytes =
                            hex::decode(parts[1]).expect("Should decode fingerprint hex");
                        let mut fp_array = [0u8; 32];
                        fp_array.copy_from_slice(&fp_bytes);
                        let fingerprint = IdentityFingerprint(fp_array);

                        return (psk, fingerprint);
                    }
                }
            })
            .await
            .expect("Should receive PskTokenGenerated event");

            // 7. Create event and response channels for RemoteClient
            let (remote_event_tx, mut remote_event_rx) = mpsc::channel::<RemoteClientEvent>(32);
            let (_remote_response_tx, remote_response_rx) =
                mpsc::channel::<RemoteClientResponse>(32);

            // 8. Create RemoteClient with Arc<Mutex<MockSessionStore>> for later access
            let remote_proxy = create_proxy_client(addr, None);
            let remote_session_store = Arc::new(Mutex::new(MockSessionStore::new()));
            let session_store_clone = Arc::clone(&remote_session_store);

            // Wrap the Arc<Mutex<MockSessionStore>> in a newtype to implement SessionStore
            struct SharedSessionStore(Arc<Mutex<MockSessionStore>>);

            impl SessionStore for SharedSessionStore {
                fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool {
                    self.0
                        .lock()
                        .expect("Lock should not be poisoned")
                        .has_session(fingerprint)
                }

                fn cache_session(
                    &mut self,
                    fingerprint: IdentityFingerprint,
                ) -> Result<(), bw_rat_client::RemoteClientError> {
                    self.0
                        .lock()
                        .expect("Lock should not be poisoned")
                        .cache_session(fingerprint)
                }

                fn remove_session(
                    &mut self,
                    fingerprint: &IdentityFingerprint,
                ) -> Result<(), bw_rat_client::RemoteClientError> {
                    self.0
                        .lock()
                        .expect("Lock should not be poisoned")
                        .remove_session(fingerprint)
                }

                fn clear(&mut self) -> Result<(), bw_rat_client::RemoteClientError> {
                    self.0.lock().expect("Lock should not be poisoned").clear()
                }

                fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64, u64)> {
                    self.0
                        .lock()
                        .expect("Lock should not be poisoned")
                        .list_sessions()
                }

                fn set_session_name(
                    &mut self,
                    fingerprint: &IdentityFingerprint,
                    name: String,
                ) -> Result<(), bw_rat_client::RemoteClientError> {
                    self.0
                        .lock()
                        .expect("Lock should not be poisoned")
                        .set_session_name(fingerprint, name)
                }

                fn update_last_connected(
                    &mut self,
                    fingerprint: &IdentityFingerprint,
                ) -> Result<(), bw_rat_client::RemoteClientError> {
                    self.0
                        .lock()
                        .expect("Lock should not be poisoned")
                        .update_last_connected(fingerprint)
                }

                fn save_transport_state(
                    &mut self,
                    fingerprint: &IdentityFingerprint,
                    transport_state: MultiDeviceTransport,
                ) -> Result<(), bw_rat_client::RemoteClientError> {
                    self.0
                        .lock()
                        .expect("Lock should not be poisoned")
                        .save_transport_state(fingerprint, transport_state)
                }

                fn load_transport_state(
                    &self,
                    fingerprint: &IdentityFingerprint,
                ) -> Result<Option<MultiDeviceTransport>, bw_rat_client::RemoteClientError>
                {
                    self.0
                        .lock()
                        .expect("Lock should not be poisoned")
                        .load_transport_state(fingerprint)
                }
            }

            let mut remote_client = RemoteClient::new(
                Box::new(remote_identity),
                Box::new(SharedSessionStore(remote_session_store)),
                remote_event_tx.clone(),
                remote_response_rx,
                Box::new(remote_proxy),
            )
            .await
            .expect("RemoteClient should connect");

            // 9. Pair with PSK
            timeout(
                Duration::from_secs(10),
                remote_client.pair_with_psk(psk, fingerprint),
            )
            .await
            .expect("Pairing should not timeout")
            .expect("Pairing should succeed");

            // 10. Verify HandshakeComplete events on both sides
            let mut remote_handshake_complete = false;
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(500), remote_event_rx.recv()).await
            {
                if matches!(event, RemoteClientEvent::HandshakeComplete) {
                    remote_handshake_complete = true;
                    break;
                }
            }
            assert!(
                remote_handshake_complete,
                "RemoteClient should emit HandshakeComplete"
            );

            // Drain user events to find HandshakeComplete
            let mut user_handshake_complete = false;
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(500), user_event_rx.recv()).await
            {
                if matches!(event, UserClientEvent::HandshakeComplete {}) {
                    user_handshake_complete = true;
                    break;
                }
            }
            assert!(
                user_handshake_complete,
                "UserClient should emit HandshakeComplete"
            );

            // 11. Load transport state from session store and verify it was saved
            let transport_state = {
                let store = session_store_clone
                    .lock()
                    .expect("Lock should not be poisoned");
                store
                    .load_transport_state(&fingerprint)
                    .expect("Should load transport state")
            };

            // 12. Assert the state is Some (transport object, not bytes)
            assert!(
                transport_state.is_some(),
                "Transport state should be saved after pairing"
            );
            let mut restored_transport = transport_state.unwrap();

            // 13. Verify the restored transport can encrypt (proving it's a valid transport)
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
            remote_client.close().await;
            user_task.abort();
        })
        .await;
}

// ============================================================================
// Test 6: Multi-Device Credential Response
// ============================================================================

#[tokio::test(flavor = "current_thread")]
async fn test_e2e_multi_device_credential_response() {
    use std::sync::Arc;

    let local = LocalSet::new();
    local
        .run_until(async {
            // 1. Start real proxy server
            let addr = start_test_server().await;

            // 2. Create identities - same user identity for both devices
            let user_keypair = IdentityKeyPair::generate();
            let remote_keypair = IdentityKeyPair::generate();

            // Clone keypair for device 2
            let user_keypair_device2 = user_keypair.clone();

            // Helper function to determine which device should handle based on request_id
            fn should_device1_handle(request_id: &str) -> bool {
                // request_id format: "req-{timestamp}-{8_hex_chars}"
                // Get last character and check if its hex value is even
                request_id
                    .chars()
                    .last()
                    .and_then(|c| c.to_digit(16))
                    .map(|n| n % 2 == 0)
                    .unwrap_or(true) // Default to device1 if parsing fails
            }

            // 3. Create event and response channels for UserClient Device 1
            let (user_event_tx1, mut user_event_rx1) = mpsc::channel::<UserClientEvent>(256);
            let (user_response_tx1, user_response_rx1) = mpsc::channel::<UserClientResponse>(256);

            // 4. Create UserClient Device 1 with DefaultProxyClient
            let user_proxy1 = create_proxy_client(addr, Some(user_keypair.clone()));

            // Use Arc<Mutex<MockSessionStore>> for later access to transport state
            let user_session_store1 = Arc::new(Mutex::new(MockSessionStore::new()));
            let session_store_clone = Arc::clone(&user_session_store1);

            let mut user_client1 = UserClient::listen(
                Box::new(MockIdentityProvider::with_keypair(user_keypair)),
                Box::new(SharedSessionStore(Arc::clone(&user_session_store1))),
                Box::new(user_proxy1),
            )
            .await
            .expect("UserClient Device 1 should connect");

            // 5. Spawn UserClient Device 1's enable_psk in a local task
            let user_task1 = tokio::task::spawn_local(async move {
                user_client1
                    .enable_psk(user_event_tx1, user_response_rx1)
                    .await
            });

            // 6. Wait for PskTokenGenerated event and parse token
            let (psk, user_fingerprint) = timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(UserClientEvent::PskTokenGenerated { token }) =
                        user_event_rx1.recv().await
                    {
                        let parts: Vec<&str> = token.split('_').collect();
                        let psk = Psk::from_hex(parts[0]).expect("Should parse PSK");
                        let fp_bytes =
                            hex::decode(parts[1]).expect("Should decode fingerprint hex");
                        let mut fp_array = [0u8; 32];
                        fp_array.copy_from_slice(&fp_bytes);
                        return (psk, IdentityFingerprint(fp_array));
                    }
                }
            })
            .await
            .expect("Should receive PskTokenGenerated event");

            // 7. Create RemoteClient
            let (remote_event_tx, mut remote_event_rx) = mpsc::channel::<RemoteClientEvent>(256);
            let (_remote_response_tx, remote_response_rx) =
                mpsc::channel::<RemoteClientResponse>(256);

            let remote_proxy = create_proxy_client(addr, Some(remote_keypair));
            let mut remote_client = RemoteClient::new(
                Box::new(MockIdentityProvider::new()),
                Box::new(MockSessionStore::new()),
                remote_event_tx,
                remote_response_rx,
                Box::new(remote_proxy),
            )
            .await
            .expect("RemoteClient should connect");

            // 8. Pair with PSK
            timeout(
                Duration::from_secs(10),
                remote_client.pair_with_psk(psk, user_fingerprint),
            )
            .await
            .expect("Pairing should not timeout")
            .expect("Pairing should succeed");

            // 9. Wait for handshake complete on both sides
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(500), remote_event_rx.recv()).await
            {
                if matches!(event, RemoteClientEvent::HandshakeComplete) {
                    break;
                }
            }
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(500), user_event_rx1.recv()).await
            {
                if matches!(event, UserClientEvent::HandshakeComplete {}) {
                    break;
                }
            }

            // 10. Create UserClient Device 2 with SHARED session store
            let (user_event_tx2, mut user_event_rx2) = mpsc::channel::<UserClientEvent>(256);
            let (user_response_tx2, user_response_rx2) = mpsc::channel::<UserClientResponse>(256);

            let user_proxy2 = create_proxy_client(addr, Some(user_keypair_device2.clone()));
            let mut user_client2 = UserClient::listen(
                Box::new(MockIdentityProvider::with_keypair(user_keypair_device2)),
                Box::new(SharedSessionStore(Arc::clone(&session_store_clone))),
                Box::new(user_proxy2),
            )
            .await
            .expect("UserClient Device 2 should connect");

            // 11. Spawn Device 2's event loop (transports are loaded lazily when handling requests)
            let user_task2 = tokio::task::spawn_local(async move {
                user_client2
                    .enable_psk(user_event_tx2, user_response_rx2)
                    .await
            });

            // Wait for Device 2 to be listening
            timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(UserClientEvent::Listening {}) = user_event_rx2.recv().await {
                        break;
                    }
                }
            })
            .await
            .expect("Device 2 should listen");

            // 13. Spawn response handlers for both devices
            // Handler1 responds only when request_id last hex char is even
            let handler1 = tokio::task::spawn_local(async move {
                while let Some(event) = user_event_rx1.recv().await {
                    if let UserClientEvent::CredentialRequest {
                        request_id,
                        session_id,
                        domain,
                    } = event
                    {
                        if should_device1_handle(&request_id) {
                            user_response_tx1
                                .send(UserClientResponse::RespondCredential {
                                    request_id,
                                    session_id,
                                    domain,
                                    approved: true,
                                    credential: Some(UserCredentialData {
                                        username: Some("device1_user".into()),
                                        password: Some("device1_pass".into()),
                                        totp: None,
                                        uri: None,
                                        notes: None,
                                        credential_id: None,
                                    }),
                                    credential_id: None,
                                })
                                .await
                                .ok();
                        }
                    }
                }
            });

            // Handler2 responds only when request_id last hex char is odd
            let handler2 = tokio::task::spawn_local(async move {
                while let Some(event) = user_event_rx2.recv().await {
                    if let UserClientEvent::CredentialRequest {
                        request_id,
                        session_id,
                        domain,
                    } = event
                    {
                        if !should_device1_handle(&request_id) {
                            user_response_tx2
                                .send(UserClientResponse::RespondCredential {
                                    request_id,
                                    session_id,
                                    domain,
                                    approved: true,
                                    credential: Some(UserCredentialData {
                                        username: Some("device2_user".into()),
                                        password: Some("device2_pass".into()),
                                        totp: None,
                                        uri: None,
                                        notes: None,
                                        credential_id: None,
                                    }),
                                    credential_id: None,
                                })
                                .await
                                .ok();
                        }
                    }
                }
            });

            // 14. Request 100 credentials and track which device responds
            let mut device1_count = 0;
            let mut device2_count = 0;

            for _ in 0..100 {
                let credential = timeout(
                    Duration::from_secs(10),
                    remote_client.request_credential("example.com"),
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

            // 15. Verify both devices responded
            assert!(
                device1_count > 0,
                "Device 1 should respond to at least some requests"
            );
            assert!(
                device2_count > 0,
                "Device 2 should respond to at least some requests"
            );
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
            remote_client.close().await;
            user_task1.abort();
            user_task2.abort();
        })
        .await;
}
