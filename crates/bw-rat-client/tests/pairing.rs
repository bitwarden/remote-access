//! Integration tests for bw-rat-client pairing flows
//!
//! These tests verify the PSK and fingerprint-based pairing modes
//! using mock implementations of the identity provider, session store, and proxy.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use bw_noise_protocol::{MultiDeviceTransport, PersistentTransportState};
use bw_proxy::{IdentityFingerprint, IdentityKeyPair, IncomingMessage, RendevouzCode};
use bw_rat_client::{
    IdentityProvider, ProxyClient, Psk, RemoteClient, RemoteClientEvent, RemoteClientResponse,
    SessionStore, UserClient, UserClientEvent, UserClientResponse,
};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

// ============================================================================
// Mock Implementations
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
    transport_state: Option<Vec<u8>>,
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
        let sessions = self.sessions.lock().expect("Lock should not be poisoned");
        Ok(sessions.get(fingerprint).and_then(|e| {
            PersistentTransportState::from_bytes(
                e.transport_state
                    .as_ref()
                    .expect("Transport state should exist")
                    .as_slice(),
            )
            .ok()
            .map(|state| MultiDeviceTransport::from(state))
        }))
    }
}

/// Mock proxy client that relays messages through channels
struct MockProxyClient {
    /// Our identity fingerprint
    #[allow(dead_code)]
    own_fingerprint: IdentityFingerprint,
    /// Sender for outgoing messages (to the paired proxy)
    outgoing_tx: mpsc::UnboundedSender<(IdentityFingerprint, Vec<u8>)>,
    /// Receiver for incoming messages (from the paired proxy)
    incoming_rx: Option<mpsc::UnboundedReceiver<IncomingMessage>>,
    /// Sender to push incoming messages to ourselves
    incoming_tx: mpsc::UnboundedSender<IncomingMessage>,
    /// The paired proxy's fingerprint (for routing)
    peer_fingerprint: Option<IdentityFingerprint>,
    /// Rendezvous code (for user client)
    rendezvous_code: Option<RendevouzCode>,
}

impl MockProxyClient {
    fn new(
        own_fingerprint: IdentityFingerprint,
        outgoing_tx: mpsc::UnboundedSender<(IdentityFingerprint, Vec<u8>)>,
        incoming_rx: mpsc::UnboundedReceiver<IncomingMessage>,
        incoming_tx: mpsc::UnboundedSender<IncomingMessage>,
    ) -> Self {
        Self {
            own_fingerprint,
            outgoing_tx,
            incoming_rx: Some(incoming_rx),
            incoming_tx,
            peer_fingerprint: None,
            rendezvous_code: None,
        }
    }

    fn set_peer_fingerprint(&mut self, fingerprint: IdentityFingerprint) {
        self.peer_fingerprint = Some(fingerprint);
    }

    fn set_rendezvous_code(&mut self, code: RendevouzCode) {
        self.rendezvous_code = Some(code);
    }
}

#[async_trait]
impl ProxyClient for MockProxyClient {
    async fn connect(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, bw_rat_client::RemoteClientError> {
        self.incoming_rx
            .take()
            .ok_or(bw_rat_client::RemoteClientError::NotInitialized)
    }

    async fn request_rendezvous(&self) -> Result<(), bw_rat_client::RemoteClientError> {
        // Generate a rendezvous code and send it to ourselves
        let code = self
            .rendezvous_code
            .clone()
            .unwrap_or_else(|| RendevouzCode::from_string("TEST1234".to_string()));
        self.incoming_tx
            .send(IncomingMessage::RendevouzInfo(code))
            .map_err(|_| bw_rat_client::RemoteClientError::ChannelClosed)?;
        Ok(())
    }

    async fn request_identity(
        &self,
        _code: RendevouzCode,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        // Return the peer's identity
        if let Some(peer_fp) = self.peer_fingerprint {
            // Create a dummy identity for the peer
            let dummy_keypair = IdentityKeyPair::generate();
            self.incoming_tx
                .send(IncomingMessage::IdentityInfo {
                    fingerprint: peer_fp,
                    identity: dummy_keypair.identity(),
                })
                .map_err(|_| bw_rat_client::RemoteClientError::ChannelClosed)?;
        }
        Ok(())
    }

    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.outgoing_tx
            .send((fingerprint, data))
            .map_err(|_| bw_rat_client::RemoteClientError::ChannelClosed)?;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), bw_rat_client::RemoteClientError> {
        Ok(())
    }
}

/// Creates a pair of connected mock proxies that relay messages between each other
fn create_mock_proxy_pair(
    user_fingerprint: IdentityFingerprint,
    remote_fingerprint: IdentityFingerprint,
) -> (MockProxyClient, MockProxyClient) {
    // Channels for user -> remote communication
    let (user_to_remote_tx, mut user_to_remote_rx) =
        mpsc::unbounded_channel::<(IdentityFingerprint, Vec<u8>)>();
    // Channels for remote -> user communication
    let (remote_to_user_tx, mut remote_to_user_rx) =
        mpsc::unbounded_channel::<(IdentityFingerprint, Vec<u8>)>();

    // Incoming message channels for each client
    let (user_incoming_tx, user_incoming_rx) = mpsc::unbounded_channel::<IncomingMessage>();
    let (remote_incoming_tx, remote_incoming_rx) = mpsc::unbounded_channel::<IncomingMessage>();

    // Create mock proxies
    let mut user_proxy = MockProxyClient::new(
        user_fingerprint,
        user_to_remote_tx,
        user_incoming_rx,
        user_incoming_tx.clone(),
    );
    user_proxy.set_peer_fingerprint(remote_fingerprint);

    let mut remote_proxy = MockProxyClient::new(
        remote_fingerprint,
        remote_to_user_tx,
        remote_incoming_rx,
        remote_incoming_tx.clone(),
    );
    remote_proxy.set_peer_fingerprint(user_fingerprint);

    // Spawn relay tasks
    // user -> remote relay
    let user_incoming_tx_clone = user_incoming_tx;
    tokio::spawn(async move {
        while let Some((dest, data)) = remote_to_user_rx.recv().await {
            let _ = user_incoming_tx_clone.send(IncomingMessage::Send {
                source: remote_fingerprint,
                destination: dest,
                payload: data,
            });
        }
    });

    // remote -> user relay
    let remote_incoming_tx_clone = remote_incoming_tx;
    tokio::spawn(async move {
        while let Some((dest, data)) = user_to_remote_rx.recv().await {
            let _ = remote_incoming_tx_clone.send(IncomingMessage::Send {
                source: user_fingerprint,
                destination: dest,
                payload: data,
            });
        }
    });

    (user_proxy, remote_proxy)
}

// ============================================================================
// Test 1: PSK Pairing
// ============================================================================

#[tokio::test(flavor = "current_thread")]
async fn test_psk_pairing() {
    use tokio::task::LocalSet;

    let local = LocalSet::new();
    local
        .run_until(async {
            // Create identities
            let user_identity = MockIdentityProvider::new();
            let remote_identity = MockIdentityProvider::new();

            let user_fingerprint = user_identity.fingerprint();
            let remote_fingerprint = remote_identity.fingerprint();

            // Create mock proxy pair
            let (user_proxy, remote_proxy) =
                create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

            // Create session stores
            let user_session_store = MockSessionStore::new();
            let remote_session_store = MockSessionStore::new();

            // Create event and response channels for UserClient
            let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
            let (_user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

            // Create event and response channels for RemoteClient
            let (remote_event_tx, mut remote_event_rx) = mpsc::channel::<RemoteClientEvent>(32);
            let (_remote_response_tx, remote_response_rx) =
                mpsc::channel::<RemoteClientResponse>(32);

            // Create and connect UserClient
            let mut user_client = UserClient::listen(
                Box::new(user_identity),
                Box::new(user_session_store),
                Box::new(user_proxy),
            )
            .await
            .expect("UserClient should connect");

            // Spawn UserClient's enable_psk in a local task
            let user_task = tokio::task::spawn_local(async move {
                user_client
                    .enable_psk(user_event_tx, user_response_rx)
                    .await
            });

            // Wait for PskTokenGenerated event
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

            // Create and connect RemoteClient
            let mut remote_client = RemoteClient::new(
                Box::new(remote_identity),
                Box::new(remote_session_store),
                remote_event_tx.clone(),
                remote_response_rx,
                Box::new(remote_proxy),
            )
            .await
            .expect("RemoteClient should connect");

            // Pair with PSK
            timeout(
                Duration::from_secs(10),
                remote_client.pair_with_psk(psk, fingerprint),
            )
            .await
            .expect("Pairing should not timeout")
            .expect("Pairing should succeed");

            // Verify HandshakeComplete events
            let mut remote_handshake_complete = false;
            let mut user_handshake_complete = false;

            // Check remote events
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(100), remote_event_rx.recv()).await
            {
                if matches!(event, RemoteClientEvent::HandshakeComplete) {
                    remote_handshake_complete = true;
                }
            }

            // Check user events
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(100), user_event_rx.recv()).await
            {
                if matches!(event, UserClientEvent::HandshakeComplete {}) {
                    user_handshake_complete = true;
                }
            }

            assert!(
                remote_handshake_complete,
                "RemoteClient should emit HandshakeComplete"
            );
            assert!(
                user_handshake_complete,
                "UserClient should emit HandshakeComplete"
            );

            // Verify remote_client is ready
            assert!(remote_client.is_ready(), "RemoteClient should be ready");

            // Verify session is cached
            assert!(
                remote_client.session_store().has_session(&fingerprint),
                "Session should be cached in RemoteClient's session store"
            );

            // Cleanup
            remote_client.close().await;
            user_task.abort();
        })
        .await;
}

/// Test rendezvous pairing with user-side fingerprint verification (remote side does NOT verify)
#[tokio::test(flavor = "current_thread")]
async fn test_fingerprint_pairing() {
    use tokio::task::LocalSet;

    let local = LocalSet::new();
    local
        .run_until(async {
            // Create identities
            let user_identity = MockIdentityProvider::new();
            let remote_identity = MockIdentityProvider::new();

            let user_fingerprint = user_identity.fingerprint();
            let remote_fingerprint = remote_identity.fingerprint();

            // Create mock proxy pair
            let (mut user_proxy, mut remote_proxy) =
                create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

            // Set up rendezvous code
            let rendezvous_code = RendevouzCode::from_string("ABCD1234".to_string());
            user_proxy.set_rendezvous_code(rendezvous_code.clone());
            remote_proxy.set_peer_fingerprint(user_fingerprint);

            // Create session stores
            let user_session_store = MockSessionStore::new();
            let remote_session_store = MockSessionStore::new();

            // Create event and response channels for UserClient
            let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
            let (user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

            // Create event and response channels for RemoteClient
            let (remote_event_tx, mut remote_event_rx) = mpsc::channel::<RemoteClientEvent>(32);
            let (_remote_response_tx, remote_response_rx) =
                mpsc::channel::<RemoteClientResponse>(32);

            // Create and connect UserClient
            let mut user_client = UserClient::listen(
                Box::new(user_identity),
                Box::new(user_session_store),
                Box::new(user_proxy),
            )
            .await
            .expect("UserClient should connect");

            // Spawn UserClient's enable_rendezvous in a local task
            let user_task = tokio::task::spawn_local(async move {
                user_client
                    .enable_rendezvous(user_event_tx, user_response_rx)
                    .await
            });

            // Wait for RendevouzCodeGenerated event
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

            // Create and connect RemoteClient
            let mut remote_client = RemoteClient::new(
                Box::new(remote_identity),
                Box::new(remote_session_store),
                remote_event_tx.clone(),
                remote_response_rx,
                Box::new(remote_proxy),
            )
            .await
            .expect("RemoteClient should connect");

            // Spawn task to auto-approve fingerprint on the USER side (listener must verify)
            let user_approval_task = tokio::task::spawn_local(async move {
                while let Some(event) = user_event_rx.recv().await {
                    if let UserClientEvent::HandshakeFingerprint { fingerprint: _ } = event {
                        // Auto-approve the fingerprint on the user/listener side
                        let _ = user_response_tx
                            .send(UserClientResponse::VerifyFingerprint { approved: true })
                            .await;
                        break;
                    }
                }
                user_event_rx
            });

            // Pair with handshake using rendezvous code (verify_fingerprint=false on remote side)
            let pair_result = timeout(
                Duration::from_secs(10),
                remote_client.pair_with_handshake(&code, false),
            )
            .await
            .expect("Pairing should not timeout");

            // The pairing should succeed
            let paired_fingerprint = pair_result.expect("Pairing should succeed");

            // Verify remote_client is ready
            assert!(remote_client.is_ready(), "RemoteClient should be ready");

            // Verify session is cached
            assert!(
                remote_client
                    .session_store()
                    .has_session(&paired_fingerprint),
                "Session should be cached in RemoteClient's session store"
            );

            // Check that HandshakeFingerprint was emitted on remote side (informational)
            let mut got_fingerprint = false;
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(100), remote_event_rx.recv()).await
            {
                if matches!(event, RemoteClientEvent::HandshakeFingerprint { .. }) {
                    got_fingerprint = true;
                }
            }
            assert!(
                got_fingerprint,
                "RemoteClient should emit HandshakeFingerprint (informational)"
            );

            // Check that FingerprintVerified was emitted on the user side
            let mut user_event_rx = user_approval_task
                .await
                .expect("User approval task should complete");

            let mut user_fingerprint_verified = false;
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(100), user_event_rx.recv()).await
            {
                if matches!(event, UserClientEvent::FingerprintVerified {}) {
                    user_fingerprint_verified = true;
                }
            }
            assert!(
                user_fingerprint_verified,
                "UserClient should emit FingerprintVerified"
            );

            // Cleanup
            remote_client.close().await;
            user_task.abort();
        })
        .await;
}

/// Test rendezvous pairing with fingerprint verification on BOTH sides
#[tokio::test(flavor = "current_thread")]
async fn test_fingerprint_pairing_both_sides_verify() {
    use tokio::task::LocalSet;

    let local = LocalSet::new();
    local
        .run_until(async {
            // Create identities
            let user_identity = MockIdentityProvider::new();
            let remote_identity = MockIdentityProvider::new();

            let user_fingerprint = user_identity.fingerprint();
            let remote_fingerprint = remote_identity.fingerprint();

            // Create mock proxy pair
            let (mut user_proxy, mut remote_proxy) =
                create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

            // Set up rendezvous code
            let rendezvous_code = RendevouzCode::from_string("XYZW5678".to_string());
            user_proxy.set_rendezvous_code(rendezvous_code.clone());
            remote_proxy.set_peer_fingerprint(user_fingerprint);

            // Create session stores
            let user_session_store = MockSessionStore::new();
            let remote_session_store = MockSessionStore::new();

            // Create event and response channels for UserClient
            let (user_event_tx, mut user_event_rx) = mpsc::channel::<UserClientEvent>(32);
            let (user_response_tx, user_response_rx) = mpsc::channel::<UserClientResponse>(32);

            // Create event and response channels for RemoteClient
            let (remote_event_tx, mut remote_event_rx) = mpsc::channel::<RemoteClientEvent>(32);
            let (remote_response_tx, remote_response_rx) =
                mpsc::channel::<RemoteClientResponse>(32);

            // Create and connect UserClient
            let mut user_client = UserClient::listen(
                Box::new(user_identity),
                Box::new(user_session_store),
                Box::new(user_proxy),
            )
            .await
            .expect("UserClient should connect");

            // Spawn UserClient's enable_rendezvous in a local task
            let user_task = tokio::task::spawn_local(async move {
                user_client
                    .enable_rendezvous(user_event_tx, user_response_rx)
                    .await
            });

            // Wait for RendevouzCodeGenerated event
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

            // Create and connect RemoteClient
            let mut remote_client = RemoteClient::new(
                Box::new(remote_identity),
                Box::new(remote_session_store),
                remote_event_tx.clone(),
                remote_response_rx,
                Box::new(remote_proxy),
            )
            .await
            .expect("RemoteClient should connect");

            // Spawn task to auto-approve fingerprint on the USER side
            let user_approval_task = tokio::task::spawn_local(async move {
                while let Some(event) = user_event_rx.recv().await {
                    if let UserClientEvent::HandshakeFingerprint { fingerprint: _ } = event {
                        let _ = user_response_tx
                            .send(UserClientResponse::VerifyFingerprint { approved: true })
                            .await;
                        break;
                    }
                }
                user_event_rx
            });

            // Spawn task to auto-approve fingerprint on the REMOTE side
            let response_tx_clone = remote_response_tx.clone();
            let remote_approval_task = tokio::task::spawn_local(async move {
                while let Some(event) = remote_event_rx.recv().await {
                    if let RemoteClientEvent::HandshakeFingerprint { fingerprint: _ } = event {
                        let _ = response_tx_clone
                            .send(RemoteClientResponse::VerifyFingerprint { approved: true })
                            .await;
                        break;
                    }
                }
                remote_event_rx
            });

            // Pair with handshake using rendezvous code (verify_fingerprint=true on remote side)
            let pair_result = timeout(
                Duration::from_secs(10),
                remote_client.pair_with_handshake(&code, true),
            )
            .await
            .expect("Pairing should not timeout");

            // The pairing should succeed
            let paired_fingerprint = pair_result.expect("Pairing should succeed");

            // Verify remote_client is ready
            assert!(remote_client.is_ready(), "RemoteClient should be ready");

            // Verify session is cached
            assert!(
                remote_client
                    .session_store()
                    .has_session(&paired_fingerprint),
                "Session should be cached in RemoteClient's session store"
            );

            // Verify remote side emitted FingerprintVerified
            let mut remote_event_rx = remote_approval_task
                .await
                .expect("Remote approval task should complete");
            let mut remote_fingerprint_verified = false;
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(100), remote_event_rx.recv()).await
            {
                if matches!(event, RemoteClientEvent::FingerprintVerified) {
                    remote_fingerprint_verified = true;
                }
            }
            assert!(
                remote_fingerprint_verified,
                "RemoteClient should emit FingerprintVerified"
            );

            // Verify user side emitted FingerprintVerified
            let mut user_event_rx = user_approval_task
                .await
                .expect("User approval task should complete");
            let mut user_fingerprint_verified = false;
            while let Ok(Some(event)) =
                timeout(Duration::from_millis(100), user_event_rx.recv()).await
            {
                if matches!(event, UserClientEvent::FingerprintVerified {}) {
                    user_fingerprint_verified = true;
                }
            }
            assert!(
                user_fingerprint_verified,
                "UserClient should emit FingerprintVerified"
            );

            // Cleanup
            remote_client.close().await;
            user_task.abort();
        })
        .await;
}
