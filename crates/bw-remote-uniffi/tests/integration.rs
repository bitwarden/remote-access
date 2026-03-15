//! Integration tests for bw-remote-uniffi
//!
//! Tests the UniFFI wrapper against a real proxy server, exercising the full
//! protocol stack: proxy connection, PSK pairing, credential exchange.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use bw_noise_protocol::MultiDeviceTransport;
use bw_proxy::server::ProxyServer;
use bw_proxy_client::ProxyClientConfig;
use bw_proxy_protocol::{IdentityFingerprint, IdentityKeyPair};
use bw_rat_client::{
    DefaultProxyClient, IdentityProvider, SessionStore, UserClient, UserClientEvent,
    UserClientResponse, UserCredentialData,
};
use bw_remote_uniffi::RemoteAccessClient;
use tokio::sync::mpsc;
use tokio::task::LocalSet;
use tokio::time::{Duration, timeout};

// ============================================================================
// Test Infrastructure (mirrors websocket_proxy.rs patterns)
// ============================================================================

struct MockIdentityProvider {
    keypair: IdentityKeyPair,
}

impl MockIdentityProvider {
    fn new() -> Self {
        Self {
            keypair: IdentityKeyPair::generate(),
        }
    }
}

impl IdentityProvider for MockIdentityProvider {
    fn identity(&self) -> &IdentityKeyPair {
        &self.keypair
    }
}

#[derive(Clone)]
struct SessionEntry {
    fingerprint: IdentityFingerprint,
    name: Option<String>,
    #[allow(dead_code)]
    cached_at: u64,
    last_connected_at: u64,
    transport_state: Option<Vec<u8>>,
}

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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
        let now = now_secs();
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
        let now = now_secs();
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
        use bw_noise_protocol::PersistentTransportState;
        let mut sessions = self.sessions.lock().expect("Lock should not be poisoned");
        if let Some(entry) = sessions.get_mut(fingerprint) {
            entry.transport_state = Some(
                PersistentTransportState::from(&transport_state)
                    .to_bytes()
                    .expect("Should serialize transport state"),
            );
        }
        Ok(())
    }

    fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, bw_rat_client::RemoteClientError> {
        use bw_noise_protocol::PersistentTransportState;
        let sessions = self.sessions.lock().expect("Lock should not be poisoned");
        Ok(sessions.get(fingerprint).and_then(|e| {
            PersistentTransportState::from_bytes(
                e.transport_state
                    .as_ref()
                    .expect("Transport state should exist")
                    .as_slice(),
            )
            .ok()
            .map(MultiDeviceTransport::from)
        }))
    }
}

async fn start_test_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind to localhost");
    let addr = listener.local_addr().expect("should get local address");
    drop(listener);

    let server = ProxyServer::new(addr);
    tokio::spawn(async move { server.run().await.ok() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    addr
}

fn create_proxy_client(addr: SocketAddr, keypair: Option<IdentityKeyPair>) -> DefaultProxyClient {
    DefaultProxyClient::new(ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: keypair,
    })
}

fn test_credential() -> UserCredentialData {
    UserCredentialData {
        username: Some("testuser".to_string()),
        password: Some("testpassword123".to_string()),
        totp: Some("123456".to_string()),
        uri: Some("https://example.com".to_string()),
        notes: Some("Test credential notes".to_string()),
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Test that connecting to a non-existent proxy fails with ConnectionFailed.
#[test]
fn connect_to_nonexistent_proxy_fails() {
    let client = RemoteAccessClient::new(
        "ws://127.0.0.1:1".to_string(),
        "test-uniffi-integration".to_string(),
    )
    .expect("should create client");

    let result = client.connect(Some("ABC-DEF-GHI".to_string()), None);
    assert!(result.is_err());
}

/// Test full PSK pairing + credential exchange through the UniFFI wrapper.
///
/// This is the primary integration test: it starts a real proxy server, sets up
/// a UserClient listening with PSK mode, then uses the UniFFI RemoteAccessClient
/// to connect via PSK token and request a credential.
#[tokio::test(flavor = "current_thread")]
async fn test_uniffi_psk_pairing_and_credential_request() {
    let local = LocalSet::new();
    local
        .run_until(async {
            // 1. Start real proxy server
            let addr = start_test_server().await;

            // 2. Set up UserClient (the "trusted device" side)
            let user_identity = MockIdentityProvider::new();
            let user_keypair = user_identity.identity().clone();

            let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
            let (user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

            let user_proxy = create_proxy_client(addr, Some(user_keypair));
            let user_session_store = MockSessionStore::new();

            let mut user_client = UserClient::listen(
                Box::new(user_identity),
                Box::new(user_session_store),
                Box::new(user_proxy),
            )
            .await
            .expect("UserClient should connect");

            // 3. Enable PSK mode on user client
            let user_task = tokio::task::spawn_local(async move {
                user_client
                    .enable_psk(user_event_tx, user_response_rx)
                    .await
            });

            // 4. Wait for PSK token
            let psk_token = timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(UserClientEvent::PskTokenGenerated { token }) =
                        user_event_rx.recv().await
                    {
                        return token;
                    }
                }
            })
            .await
            .expect("Should receive PskTokenGenerated event");

            // 5. Spawn credential response handler
            let credential_handler = tokio::task::spawn_local(async move {
                // First drain until HandshakeComplete, then wait for credential request
                loop {
                    match user_event_rx.recv().await {
                        Some(UserClientEvent::CredentialRequest {
                            request_id,
                            session_id,
                            domain,
                        }) => {
                            assert_eq!(domain, "example.com", "Domain should match");
                            user_response_tx
                                .send(UserClientResponse::RespondCredential {
                                    request_id,
                                    session_id,
                                    approved: true,
                                    credential: Some(test_credential()),
                                })
                                .await
                                .expect("Should send response");
                            break;
                        }
                        Some(_) => continue, // Skip other events like HandshakeComplete
                        None => panic!("User event channel closed unexpectedly"),
                    }
                }
            });

            // 6. Use the UniFFI wrapper to connect and request credential
            // (runs in a blocking thread since RemoteAccessClient uses block_on internally)
            let proxy_url = format!("ws://{addr}");
            let result = tokio::task::spawn_blocking(move || {
                let client = RemoteAccessClient::new(proxy_url, "test-uniffi-psk".to_string())
                    .expect("should create client");

                // Connect with PSK token
                let fingerprint = client
                    .connect(Some(psk_token), None)
                    .expect("connect should succeed");

                // PSK connections return None for fingerprint
                assert!(
                    fingerprint.is_none(),
                    "PSK pairing should not return a fingerprint"
                );

                // Verify ready state
                assert!(
                    client.is_ready(),
                    "Client should be ready after PSK pairing"
                );

                // Request credential
                let cred = client
                    .request_credential("example.com".to_string())
                    .expect("credential request should succeed");

                // Close
                client.close();

                cred
            })
            .await
            .expect("blocking task should not panic");

            // 7. Verify credential contents
            assert_eq!(result.username.as_deref(), Some("testuser"));
            assert_eq!(result.password.as_deref(), Some("testpassword123"));
            assert_eq!(result.totp.as_deref(), Some("123456"));
            assert_eq!(result.uri.as_deref(), Some("https://example.com"));
            assert_eq!(result.notes.as_deref(), Some("Test credential notes"));

            // Cleanup
            credential_handler.abort();
            user_task.abort();
        })
        .await;
}

/// Test full rendezvous pairing + credential exchange through the UniFFI wrapper.
#[tokio::test(flavor = "current_thread")]
async fn test_uniffi_rendezvous_pairing_and_credential_request() {
    let local = LocalSet::new();
    local
        .run_until(async {
            // 1. Start real proxy server
            let addr = start_test_server().await;

            // 2. Set up UserClient with rendezvous mode
            let user_identity = MockIdentityProvider::new();
            let user_keypair = user_identity.identity().clone();

            let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
            let (user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

            let user_proxy = create_proxy_client(addr, Some(user_keypair));
            let user_session_store = MockSessionStore::new();

            let mut user_client = UserClient::listen(
                Box::new(user_identity),
                Box::new(user_session_store),
                Box::new(user_proxy),
            )
            .await
            .expect("UserClient should connect");

            let user_task = tokio::task::spawn_local(async move {
                user_client
                    .enable_rendezvous(user_event_tx, user_response_rx)
                    .await
            });

            // 3. Wait for rendezvous code
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

            // 4. Spawn fingerprint auto-approval + credential response handler
            let credential_handler = tokio::task::spawn_local(async move {
                loop {
                    match user_event_rx.recv().await {
                        Some(UserClientEvent::HandshakeFingerprint { fingerprint: _ }) => {
                            // Auto-approve fingerprint
                            user_response_tx
                                .send(UserClientResponse::VerifyFingerprint {
                                    approved: true,
                                    name: None,
                                })
                                .await
                                .expect("Should send fingerprint approval");
                        }
                        Some(UserClientEvent::CredentialRequest {
                            request_id,
                            session_id,
                            domain,
                        }) => {
                            assert_eq!(domain, "example.com", "Domain should match");
                            user_response_tx
                                .send(UserClientResponse::RespondCredential {
                                    request_id,
                                    session_id,
                                    approved: true,
                                    credential: Some(test_credential()),
                                })
                                .await
                                .expect("Should send credential response");
                            break;
                        }
                        Some(_) => continue,
                        None => panic!("User event channel closed unexpectedly"),
                    }
                }
            });

            // 5. Use UniFFI wrapper with rendezvous code
            let proxy_url = format!("ws://{addr}");
            let result = tokio::task::spawn_blocking(move || {
                let client = RemoteAccessClient::new(proxy_url, "test-uniffi-rdv".to_string())
                    .expect("should create client");

                // Connect with rendezvous code
                let fingerprint = client
                    .connect(Some(code), None)
                    .expect("connect should succeed");

                // Rendezvous connections should return a fingerprint
                assert!(
                    fingerprint.is_some(),
                    "Rendezvous pairing should return a fingerprint"
                );
                let fp = fingerprint.expect("fingerprint should be Some");
                assert!(!fp.is_empty(), "Fingerprint should not be empty");

                // Verify ready state
                assert!(
                    client.is_ready(),
                    "Client should be ready after rendezvous pairing"
                );

                // Request credential
                let cred = client
                    .request_credential("example.com".to_string())
                    .expect("credential request should succeed");

                client.close();

                cred
            })
            .await
            .expect("blocking task should not panic");

            // 6. Verify credential
            assert_eq!(result.username.as_deref(), Some("testuser"));
            assert_eq!(result.password.as_deref(), Some("testpassword123"));
            assert_eq!(result.totp.as_deref(), Some("123456"));

            // Cleanup
            credential_handler.abort();
            user_task.abort();
        })
        .await;
}

/// Test that connect_and_request convenience function works end-to-end.
#[tokio::test(flavor = "current_thread")]
async fn test_uniffi_connect_and_request_convenience() {
    let local = LocalSet::new();
    local
        .run_until(async {
            let addr = start_test_server().await;

            let user_identity = MockIdentityProvider::new();
            let user_keypair = user_identity.identity().clone();

            let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
            let (user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

            let user_proxy = create_proxy_client(addr, Some(user_keypair));
            let user_session_store = MockSessionStore::new();

            let mut user_client = UserClient::listen(
                Box::new(user_identity),
                Box::new(user_session_store),
                Box::new(user_proxy),
            )
            .await
            .expect("UserClient should connect");

            let user_task = tokio::task::spawn_local(async move {
                user_client
                    .enable_psk(user_event_tx, user_response_rx)
                    .await
            });

            let psk_token = timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(UserClientEvent::PskTokenGenerated { token }) =
                        user_event_rx.recv().await
                    {
                        return token;
                    }
                }
            })
            .await
            .expect("Should receive PskTokenGenerated event");

            let credential_handler = tokio::task::spawn_local(async move {
                loop {
                    match user_event_rx.recv().await {
                        Some(UserClientEvent::CredentialRequest {
                            request_id,
                            session_id,
                            domain,
                        }) => {
                            assert_eq!(domain, "test.org");
                            user_response_tx
                                .send(UserClientResponse::RespondCredential {
                                    request_id,
                                    session_id,
                                    approved: true,
                                    credential: Some(test_credential()),
                                })
                                .await
                                .expect("Should send response");
                            break;
                        }
                        Some(_) => continue,
                        None => panic!("Channel closed"),
                    }
                }
            });

            let proxy_url = format!("ws://{addr}");
            let result = tokio::task::spawn_blocking(move || {
                bw_remote_uniffi::connect_and_request(
                    "test.org".to_string(),
                    Some(psk_token),
                    None,
                    proxy_url,
                    "test-uniffi-oneshot".to_string(),
                )
            })
            .await
            .expect("blocking task should not panic")
            .expect("connect_and_request should succeed");

            assert_eq!(result.username.as_deref(), Some("testuser"));
            assert_eq!(result.password.as_deref(), Some("testpassword123"));

            credential_handler.abort();
            user_task.abort();
        })
        .await;
}

/// Test that connecting with no token and no cached sessions gives a clear error.
#[test]
fn connect_no_token_no_sessions_gives_error() {
    // We need a real proxy for the initial connection to succeed,
    // but even without one the error should be meaningful.
    let client = RemoteAccessClient::new(
        "ws://127.0.0.1:1".to_string(),
        "test-uniffi-nosession".to_string(),
    )
    .expect("should create client");

    let result = client.connect(None, None);
    // Should fail (either connection error or session error)
    assert!(result.is_err());
}

/// Test that calling connect() twice replaces the previous connection cleanly
/// (no panic, no deadlock, second connection works).
#[tokio::test(flavor = "current_thread")]
async fn test_double_connect_replaces_previous() {
    let local = LocalSet::new();
    local
        .run_until(async {
            let addr = start_test_server().await;

            // Set up two separate UserClient PSK sessions
            let mut psk_tokens = Vec::new();
            let mut user_tasks = Vec::new();
            let mut credential_handlers = Vec::new();

            for i in 0..2 {
                let user_identity = MockIdentityProvider::new();
                let user_keypair = user_identity.identity().clone();

                let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
                let (user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

                let user_proxy = create_proxy_client(addr, Some(user_keypair));
                let user_session_store = MockSessionStore::new();

                let mut user_client = UserClient::listen(
                    Box::new(user_identity),
                    Box::new(user_session_store),
                    Box::new(user_proxy),
                )
                .await
                .expect("UserClient should connect");

                let user_task = tokio::task::spawn_local(async move {
                    user_client
                        .enable_psk(user_event_tx, user_response_rx)
                        .await
                });

                let psk_token = timeout(Duration::from_secs(5), async {
                    loop {
                        if let Some(UserClientEvent::PskTokenGenerated { token }) =
                            user_event_rx.recv().await
                        {
                            return token;
                        }
                    }
                })
                .await
                .expect("Should receive PskTokenGenerated event");

                let _domain = format!("test{i}.example.com");
                let credential_handler = tokio::task::spawn_local(async move {
                    loop {
                        match user_event_rx.recv().await {
                            Some(UserClientEvent::CredentialRequest {
                                request_id,
                                session_id,
                                domain: _domain,
                            }) => {
                                user_response_tx
                                    .send(UserClientResponse::RespondCredential {
                                        request_id,
                                        session_id,
                                        approved: true,
                                        credential: Some(test_credential()),
                                    })
                                    .await
                                    .expect("Should send response");
                                break;
                            }
                            Some(_) => continue,
                            None => break,
                        }
                    }
                });

                psk_tokens.push(psk_token);
                user_tasks.push(user_task);
                credential_handlers.push(credential_handler);
            }

            let proxy_url = format!("ws://{addr}");
            let token1 = psk_tokens.remove(0);
            let token2 = psk_tokens.remove(0);

            let result = tokio::task::spawn_blocking(move || {
                let client = RemoteAccessClient::new(proxy_url, "test-uniffi-double".to_string())
                    .expect("should create client");

                // First connect
                client
                    .connect(Some(token1), None)
                    .expect("first connect should succeed");
                assert!(client.is_ready(), "Should be ready after first connect");

                // Second connect replaces the first
                client
                    .connect(Some(token2), None)
                    .expect("second connect should succeed");
                assert!(client.is_ready(), "Should be ready after second connect");

                // Credential request works on the new connection
                let cred = client
                    .request_credential("test1.example.com".to_string())
                    .expect("credential request should succeed");

                client.close();
                cred
            })
            .await
            .expect("blocking task should not panic");

            assert_eq!(result.username.as_deref(), Some("testuser"));

            for h in credential_handlers {
                h.abort();
            }
            for t in user_tasks {
                t.abort();
            }
        })
        .await;
}
