//! Integration tests for ap-client pairing flows
//!
//! These tests verify the PSK and fingerprint-based pairing modes
//! using mock implementations of the identity provider, session store, and proxy.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use ap_client::{
    FingerprintVerificationReply, IdentityProvider, ProxyClient, Psk, RemoteClient,
    RemoteClientError, RemoteClientFingerprintReply, RemoteClientNotification, RemoteClientRequest,
    SessionStore, UserClient, UserClientNotification, UserClientRequest,
};
use ap_noise::{MultiDeviceTransport, PersistentTransportState};
use ap_proxy_client::IncomingMessage;
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair, RendezvousCode};
use async_trait::async_trait;
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

#[async_trait]
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

#[async_trait]
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
            entry.transport_state = Some(
                PersistentTransportState::from(&transport_state)
                    .to_bytes()
                    .expect("Should serialize transport state"),
            );
        }
        Ok(())
    }

    async fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, ap_client::RemoteClientError> {
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
    rendezvous_code: Option<RendezvousCode>,
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

    fn set_rendezvous_code(&mut self, code: RendezvousCode) {
        self.rendezvous_code = Some(code);
    }
}

#[async_trait]
impl ProxyClient for MockProxyClient {
    async fn connect(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ap_client::RemoteClientError> {
        self.incoming_rx
            .take()
            .ok_or(ap_client::RemoteClientError::NotInitialized)
    }

    async fn request_rendezvous(&self) -> Result<(), ap_client::RemoteClientError> {
        // Generate a rendezvous code and send it to ourselves
        let code = self
            .rendezvous_code
            .clone()
            .unwrap_or_else(|| RendezvousCode::from_string("TEST12345".to_string()));
        self.incoming_tx
            .send(IncomingMessage::RendezvousInfo(code))
            .map_err(|_| ap_client::RemoteClientError::ChannelClosed)?;
        Ok(())
    }

    async fn request_identity(
        &self,
        _code: RendezvousCode,
    ) -> Result<(), ap_client::RemoteClientError> {
        // Return the peer's identity
        if let Some(peer_fp) = self.peer_fingerprint {
            // Create a dummy identity for the peer
            let dummy_keypair = IdentityKeyPair::generate();
            self.incoming_tx
                .send(IncomingMessage::IdentityInfo {
                    fingerprint: peer_fp,
                    identity: dummy_keypair.identity(),
                })
                .map_err(|_| ap_client::RemoteClientError::ChannelClosed)?;
        }
        Ok(())
    }

    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), ap_client::RemoteClientError> {
        self.outgoing_tx
            .send((fingerprint, data))
            .map_err(|_| ap_client::RemoteClientError::ChannelClosed)?;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), ap_client::RemoteClientError> {
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

#[tokio::test]
async fn test_psk_pairing() {
    // Create identities
    let user_identity = MockIdentityProvider::new();
    let remote_identity = MockIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    // Create mock proxy pair
    let (user_proxy, remote_proxy) = create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

    // Create session stores
    let user_session_store = MockSessionStore::new();
    let remote_session_store = MockSessionStore::new();

    // Create notification and request channels for UserClient
    let (notification_tx, mut notification_rx) = mpsc::channel::<UserClientNotification>(32);
    let (request_tx, _request_rx) = mpsc::channel::<UserClientRequest>(32);

    // Create notification and request channels for RemoteClient
    let (remote_notification_tx, mut remote_notification_rx) =
        mpsc::channel::<RemoteClientNotification>(32);
    let (remote_request_tx, _remote_request_rx) = mpsc::channel::<RemoteClientRequest>(32);

    // Create and connect UserClient (already listening)
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

    // Get PSK token
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

    // Create and connect RemoteClient
    let remote_client = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_session_store),
        Box::new(remote_proxy),
        remote_notification_tx,
        remote_request_tx,
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

    // Check remote notifications
    while let Ok(Some(event)) =
        timeout(Duration::from_millis(100), remote_notification_rx.recv()).await
    {
        if matches!(event, RemoteClientNotification::HandshakeComplete) {
            remote_handshake_complete = true;
        }
    }

    // Check user notifications
    while let Ok(Some(event)) = timeout(Duration::from_millis(100), notification_rx.recv()).await {
        if matches!(event, UserClientNotification::HandshakeComplete {}) {
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

    // Verify session is cached
    assert!(
        remote_client
            .has_session(fingerprint)
            .await
            .expect("has_session should not fail"),
        "Session should be cached in RemoteClient's session store"
    );

    // Cleanup
    drop(remote_client);
    drop(user_client);
}

/// Test rendezvous pairing with user-side fingerprint verification (remote side does NOT verify)
#[tokio::test]
async fn test_fingerprint_pairing() {
    // Create identities
    let user_identity = MockIdentityProvider::new();
    let remote_identity = MockIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    // Create mock proxy pair
    let (mut user_proxy, mut remote_proxy) =
        create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

    // Set up rendezvous code
    let rendezvous_code = RendezvousCode::from_string("ABCDEF123".to_string());
    user_proxy.set_rendezvous_code(rendezvous_code.clone());
    remote_proxy.set_peer_fingerprint(user_fingerprint);

    // Create session stores
    let user_session_store = MockSessionStore::new();
    let remote_session_store = MockSessionStore::new();

    // Create notification and request channels for UserClient
    let (notification_tx, notification_rx) = mpsc::channel::<UserClientNotification>(32);
    let (request_tx, mut request_rx) = mpsc::channel::<UserClientRequest>(32);

    // Create notification and request channels for RemoteClient
    let (remote_notification_tx, mut remote_notification_rx) =
        mpsc::channel::<RemoteClientNotification>(32);
    let (remote_request_tx, _remote_request_rx) = mpsc::channel::<RemoteClientRequest>(32);

    // Create and connect UserClient (already listening)
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

    // Get rendezvous token
    let code = user_client
        .get_rendezvous_token(None)
        .await
        .expect("Should get rendezvous token");
    let code = code.as_str().to_string();

    // Create and connect RemoteClient
    let remote_client = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_session_store),
        Box::new(remote_proxy),
        remote_notification_tx,
        remote_request_tx,
    )
    .await
    .expect("RemoteClient should connect");

    // Spawn task to auto-approve fingerprint on the USER side (listener must verify)
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
        notification_rx
    });

    // Pair with handshake using rendezvous code (verify_fingerprint=false on remote side)
    let pair_result = timeout(
        Duration::from_secs(10),
        remote_client.pair_with_handshake(code, false),
    )
    .await
    .expect("Pairing should not timeout");

    // The pairing should succeed
    let paired_fingerprint = pair_result.expect("Pairing should succeed");

    // Verify session is cached
    assert!(
        remote_client
            .has_session(paired_fingerprint)
            .await
            .expect("has_session should not fail"),
        "Session should be cached in RemoteClient's session store"
    );

    // Check that HandshakeFingerprint was emitted on remote side (informational)
    let mut got_fingerprint = false;
    while let Ok(Some(event)) =
        timeout(Duration::from_millis(100), remote_notification_rx.recv()).await
    {
        if matches!(event, RemoteClientNotification::HandshakeFingerprint { .. }) {
            got_fingerprint = true;
        }
    }
    assert!(
        got_fingerprint,
        "RemoteClient should emit HandshakeFingerprint (informational)"
    );

    // Check that FingerprintVerified was emitted on the user side
    let mut notification_rx = user_approval_task
        .await
        .expect("User approval task should complete");

    let mut user_fingerprint_verified = false;
    while let Ok(Some(event)) = timeout(Duration::from_millis(100), notification_rx.recv()).await {
        if matches!(event, UserClientNotification::FingerprintVerified {}) {
            user_fingerprint_verified = true;
        }
    }
    assert!(
        user_fingerprint_verified,
        "UserClient should emit FingerprintVerified"
    );

    // Cleanup
    drop(remote_client);
    drop(user_client);
}

// ============================================================================
// Reconnecting Mock Proxy Client
// ============================================================================

/// A mock proxy client that simulates connection drops and reconnections.
///
/// - First `connect()` succeeds normally.
/// - The incoming channel is closed after a configurable delay to simulate a drop.
/// - Subsequent `connect()` calls fail `fail_count` times, then succeed.
struct ReconnectingMockProxyClient {
    /// How many reconnection attempts should fail before succeeding
    fail_count: u32,
    /// Tracks total connect() calls (including the initial one)
    connect_calls: Arc<AtomicU32>,
    /// Channel for pushing incoming messages after reconnection
    incoming_tx: Option<mpsc::UnboundedSender<IncomingMessage>>,
    /// Delay before closing the first incoming channel (simulates proxy drop)
    drop_delay: Duration,
}

impl ReconnectingMockProxyClient {
    fn new(fail_count: u32, drop_delay: Duration) -> Self {
        Self {
            fail_count,
            connect_calls: Arc::new(AtomicU32::new(0)),
            incoming_tx: None,
            drop_delay,
        }
    }
}

#[async_trait]
impl ProxyClient for ReconnectingMockProxyClient {
    async fn connect(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, RemoteClientError> {
        let call_num = self.connect_calls.fetch_add(1, Ordering::SeqCst) + 1;

        if call_num == 1 {
            // First connect: succeed but drop the channel after a delay
            let (tx, rx) = mpsc::unbounded_channel();
            let drop_delay = self.drop_delay;
            tokio::spawn(async move {
                tokio::time::sleep(drop_delay).await;
                drop(tx); // Closes the receiver, simulating proxy drop
            });
            return Ok(rx);
        }

        // Subsequent connects: fail `fail_count` times, then succeed
        let reconnect_attempt = call_num - 1; // 1-based reconnection attempts
        if reconnect_attempt <= self.fail_count {
            return Err(RemoteClientError::ChannelClosed);
        }

        // Success: create a new channel that stays open
        let (tx, rx) = mpsc::unbounded_channel();
        self.incoming_tx = Some(tx);
        Ok(rx)
    }

    async fn request_rendezvous(&self) -> Result<(), RemoteClientError> {
        Ok(())
    }

    async fn request_identity(&self, _code: RendezvousCode) -> Result<(), RemoteClientError> {
        Ok(())
    }

    async fn send_to(
        &self,
        _fingerprint: IdentityFingerprint,
        _data: Vec<u8>,
    ) -> Result<(), RemoteClientError> {
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), RemoteClientError> {
        self.incoming_tx = None;
        Ok(())
    }
}

// ============================================================================
// Test: Reconnection on channel close
// ============================================================================

/// Helper: run a reconnection test with the given `fail_count` and verify
/// the expected event sequence and connect-call count.
///
/// Uses `tokio::time::pause()` so backoff delays resolve instantly.
async fn run_reconnection_test(fail_count: u32) -> (Vec<UserClientNotification>, u32) {
    // Pause time so exponential backoff sleeps resolve instantly
    tokio::time::pause();

    let identity = MockIdentityProvider::new();
    let session_store = MockSessionStore::new();

    let proxy = ReconnectingMockProxyClient::new(fail_count, Duration::from_millis(10));
    let connect_calls = Arc::clone(&proxy.connect_calls);

    let (notification_tx, mut event_rx) = mpsc::channel::<UserClientNotification>(32);
    let (request_tx, _request_rx) = mpsc::channel::<UserClientRequest>(32);

    let client = UserClient::connect(
        Box::new(identity),
        Box::new(session_store),
        Box::new(proxy),
        notification_tx,
        request_tx,
        None,
    )
    .await
    .expect("Initial connect should succeed");

    // Collect events with a timeout
    let events = timeout(Duration::from_secs(60), async {
        let mut collected = Vec::new();
        while let Some(event) = event_rx.recv().await {
            match &event {
                UserClientNotification::Listening {} => {}
                UserClientNotification::ClientDisconnected {}
                | UserClientNotification::Reconnecting { .. }
                | UserClientNotification::Reconnected {} => {
                    collected.push(event.clone());
                }
                other => {
                    panic!("Unexpected event during reconnection test: {:?}", other);
                }
            }
            // Stop after seeing Reconnected
            if matches!(
                collected.last(),
                Some(UserClientNotification::Reconnected {})
            ) {
                break;
            }
        }
        collected
    })
    .await
    .expect("Should receive reconnection events within timeout");

    let calls = connect_calls.load(Ordering::SeqCst);
    drop(client);
    (events, calls)
}

/// Test that UserClient reconnects immediately when proxy drops and first retry succeeds.
///
/// Verifies: ClientDisconnected → Reconnected (no Reconnecting events)
#[tokio::test(flavor = "current_thread")]
async fn test_user_client_reconnects_immediately() {
    let (events, connect_calls) = run_reconnection_test(0).await;

    assert_eq!(
        events.len(),
        2,
        "Expected [Disconnected, Reconnected], got: {events:?}"
    );
    assert!(
        matches!(events[0], UserClientNotification::ClientDisconnected {}),
        "First event should be ClientDisconnected, got {:?}",
        events[0]
    );
    assert!(
        matches!(events[1], UserClientNotification::Reconnected {}),
        "Second event should be Reconnected, got {:?}",
        events[1]
    );

    // 1 initial connect + 1 reconnect (success)
    assert_eq!(
        connect_calls, 2,
        "Should have called connect() 2 times total"
    );
}

/// Test that UserClient retries with backoff when reconnection fails multiple times.
///
/// Verifies: ClientDisconnected → Reconnecting(1) → Reconnecting(2) → Reconnected
#[tokio::test(flavor = "current_thread")]
async fn test_user_client_reconnects_after_failures() {
    let (events, connect_calls) = run_reconnection_test(2).await;

    assert_eq!(
        events.len(),
        4,
        "Expected [Disconnected, Reconnecting(1), Reconnecting(2), Reconnected], got: {events:?}"
    );
    assert!(matches!(
        events[0],
        UserClientNotification::ClientDisconnected {}
    ));
    assert!(matches!(
        events[1],
        UserClientNotification::Reconnecting { attempt: 1 }
    ));
    assert!(matches!(
        events[2],
        UserClientNotification::Reconnecting { attempt: 2 }
    ));
    assert!(matches!(events[3], UserClientNotification::Reconnected {}));

    // 1 initial + 3 reconnect attempts (2 fail + 1 success)
    assert_eq!(
        connect_calls, 4,
        "Should have called connect() 4 times total"
    );
}

/// Test rendezvous pairing with fingerprint verification on BOTH sides
#[tokio::test]
async fn test_fingerprint_pairing_both_sides_verify() {
    // Create identities
    let user_identity = MockIdentityProvider::new();
    let remote_identity = MockIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    // Create mock proxy pair
    let (mut user_proxy, mut remote_proxy) =
        create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

    // Set up rendezvous code
    let rendezvous_code = RendezvousCode::from_string("XYZW56789".to_string());
    user_proxy.set_rendezvous_code(rendezvous_code.clone());
    remote_proxy.set_peer_fingerprint(user_fingerprint);

    // Create session stores
    let user_session_store = MockSessionStore::new();
    let remote_session_store = MockSessionStore::new();

    // Create notification and request channels for UserClient
    let (notification_tx, notification_rx) = mpsc::channel::<UserClientNotification>(32);
    let (request_tx, mut request_rx) = mpsc::channel::<UserClientRequest>(32);

    // Create notification and request channels for RemoteClient
    let (remote_notification_tx, remote_notification_rx) =
        mpsc::channel::<RemoteClientNotification>(32);
    let (remote_request_tx, mut remote_request_rx) = mpsc::channel::<RemoteClientRequest>(32);

    // Create and connect UserClient (already listening)
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

    // Get rendezvous token
    let code = user_client
        .get_rendezvous_token(None)
        .await
        .expect("Should get rendezvous token");
    let code = code.as_str().to_string();

    // Create and connect RemoteClient
    let remote_client = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_session_store),
        Box::new(remote_proxy),
        remote_notification_tx,
        remote_request_tx,
    )
    .await
    .expect("RemoteClient should connect");

    // Spawn task to auto-approve fingerprint on the USER side
    let user_approval_task = tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            if let UserClientRequest::VerifyFingerprint { reply, .. } = request {
                let _ = reply.send(FingerprintVerificationReply {
                    approved: true,
                    name: None,
                });
                break;
            }
        }
        notification_rx
    });

    // Spawn task to auto-approve fingerprint on the REMOTE side via request channel
    let remote_approval_task = tokio::spawn(async move {
        while let Some(request) = remote_request_rx.recv().await {
            let RemoteClientRequest::VerifyFingerprint { reply, .. } = request;
            let _ = reply.send(RemoteClientFingerprintReply { approved: true });
            break;
        }
        remote_notification_rx
    });

    // Pair with handshake using rendezvous code (verify_fingerprint=true on remote side)
    let pair_result = timeout(
        Duration::from_secs(10),
        remote_client.pair_with_handshake(code, true),
    )
    .await
    .expect("Pairing should not timeout");

    // The pairing should succeed
    let paired_fingerprint = pair_result.expect("Pairing should succeed");

    // Verify session is cached
    assert!(
        remote_client
            .has_session(paired_fingerprint)
            .await
            .expect("has_session should not fail"),
        "Session should be cached in RemoteClient's session store"
    );

    // Verify remote side emitted FingerprintVerified
    let mut remote_notification_rx = remote_approval_task
        .await
        .expect("Remote approval task should complete");
    let mut remote_fingerprint_verified = false;
    while let Ok(Some(event)) =
        timeout(Duration::from_millis(100), remote_notification_rx.recv()).await
    {
        if matches!(event, RemoteClientNotification::FingerprintVerified) {
            remote_fingerprint_verified = true;
        }
    }
    assert!(
        remote_fingerprint_verified,
        "RemoteClient should emit FingerprintVerified"
    );

    // Verify user side emitted FingerprintVerified
    let mut notification_rx = user_approval_task
        .await
        .expect("User approval task should complete");
    let mut user_fingerprint_verified = false;
    while let Ok(Some(event)) = timeout(Duration::from_millis(100), notification_rx.recv()).await {
        if matches!(event, UserClientNotification::FingerprintVerified {}) {
            user_fingerprint_verified = true;
        }
    }
    assert!(
        user_fingerprint_verified,
        "UserClient should emit FingerprintVerified"
    );

    // Cleanup
    drop(remote_client);
    drop(user_client);
}

// ============================================================================
// Test: Dual-mode PSK + Rendezvous on same UserClient
// ============================================================================

/// Test that a single UserClient accepts PSK connections when both PSK and
/// rendezvous pairings are pending. This verifies that `psk_id` in `HandshakeInit`
/// correctly routes to the right pending pairing.
#[tokio::test]
async fn test_dual_mode_psk_pairing_with_both_modes_pending() {
    // Create identities
    let user_identity = MockIdentityProvider::new();
    let remote_identity = MockIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    // Create mock proxy pair
    let (mut user_proxy, remote_proxy) =
        create_mock_proxy_pair(user_fingerprint, remote_fingerprint);
    // Set up rendezvous so get_rendezvous_token doesn't hang
    user_proxy.set_rendezvous_code(RendezvousCode::from_string("DUAL12345".to_string()));

    let user_session_store = MockSessionStore::new();
    let remote_session_store = MockSessionStore::new();

    let (notification_tx, mut notification_rx) = mpsc::channel::<UserClientNotification>(32);
    let (request_tx, _request_rx) = mpsc::channel::<UserClientRequest>(32);

    let (remote_notification_tx, mut remote_notification_rx) =
        mpsc::channel::<RemoteClientNotification>(32);
    let (remote_request_tx, _remote_request_rx) = mpsc::channel::<RemoteClientRequest>(32);

    // Create UserClient (already listening)
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

    // Set up BOTH pairings
    let psk_token = user_client
        .get_psk_token(Some("psk-device".to_string()))
        .await
        .expect("Should generate PSK token");

    let _rendezvous_code = user_client
        .get_rendezvous_token(Some("rendezvous-device".to_string()))
        .await
        .expect("Should get rendezvous token");

    // Parse PSK token
    let parts: Vec<&str> = psk_token.split('_').collect();
    assert_eq!(parts.len(), 2);
    let psk = Psk::from_hex(parts[0]).expect("Should parse PSK");
    let fp_bytes = hex::decode(parts[1]).expect("Should decode fingerprint hex");
    let mut fp_array = [0u8; 32];
    fp_array.copy_from_slice(&fp_bytes);
    let user_fp_from_token = IdentityFingerprint(fp_array);

    // Connect RemoteClient via PSK
    let remote_client = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_session_store),
        Box::new(remote_proxy),
        remote_notification_tx,
        remote_request_tx,
    )
    .await
    .expect("RemoteClient should connect");

    timeout(
        Duration::from_secs(10),
        remote_client.pair_with_psk(psk, user_fp_from_token),
    )
    .await
    .expect("PSK pairing should not timeout")
    .expect("PSK pairing should succeed");

    // Verify user-side events: HandshakeComplete should fire
    let mut user_handshake_complete = false;
    while let Ok(Some(event)) = timeout(Duration::from_millis(200), notification_rx.recv()).await {
        if matches!(event, UserClientNotification::HandshakeComplete {}) {
            user_handshake_complete = true;
        }
    }
    assert!(
        user_handshake_complete,
        "UserClient should emit HandshakeComplete for PSK connection"
    );

    // Verify remote-side notifications
    let mut remote_handshake_complete = false;
    while let Ok(Some(event)) =
        timeout(Duration::from_millis(200), remote_notification_rx.recv()).await
    {
        if matches!(event, RemoteClientNotification::HandshakeComplete) {
            remote_handshake_complete = true;
        }
    }
    assert!(
        remote_handshake_complete,
        "RemoteClient should emit HandshakeComplete"
    );

    // Cleanup
    drop(remote_client);
    drop(user_client);
}
