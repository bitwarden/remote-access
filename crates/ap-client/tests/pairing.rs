//! Integration tests for ap-client pairing flows
//!
//! These tests verify the PSK and fingerprint-based pairing modes
//! using mock implementations of the identity provider, connection store, and proxy.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use ap_client::{
    ClientError, CredentialRequestReply, FingerprintVerificationReply, IdentityProvider,
    MemoryConnectionStore, MemoryIdentityProvider, ProxyClient, PskToken, RemoteClient,
    RemoteClientFingerprintReply, RemoteClientHandle, RemoteClientNotification,
    RemoteClientRequest, UserClient, UserClientHandle, UserClientNotification, UserClientRequest,
};
use ap_proxy_client::IncomingMessage;
use ap_proxy_protocol::{IdentityFingerprint, IdentityKeyPair, RendezvousCode};
use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use zeroize::Zeroizing;

// ============================================================================
// Mock Implementations
// ============================================================================

// Uses MemoryIdentityProvider from the library instead of a local mock

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
        _identity: IdentityKeyPair,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ap_client::ClientError> {
        self.incoming_rx
            .take()
            .ok_or(ap_client::ClientError::NotInitialized)
    }

    async fn request_rendezvous(&self) -> Result<(), ap_client::ClientError> {
        // Generate a rendezvous code and send it to ourselves
        let code = self
            .rendezvous_code
            .clone()
            .unwrap_or_else(|| RendezvousCode::from_string("TEST12345".to_string()));
        self.incoming_tx
            .send(IncomingMessage::RendezvousInfo(code))
            .map_err(|_| ap_client::ClientError::ChannelClosed)?;
        Ok(())
    }

    async fn request_identity(&self, _code: RendezvousCode) -> Result<(), ap_client::ClientError> {
        // Return the peer's identity
        if let Some(peer_fp) = self.peer_fingerprint {
            // Create a dummy identity for the peer
            let dummy_keypair = IdentityKeyPair::generate();
            self.incoming_tx
                .send(IncomingMessage::IdentityInfo {
                    fingerprint: peer_fp,
                    identity: dummy_keypair.identity(),
                })
                .map_err(|_| ap_client::ClientError::ChannelClosed)?;
        }
        Ok(())
    }

    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), ap_client::ClientError> {
        self.outgoing_tx
            .send((fingerprint, data))
            .map_err(|_| ap_client::ClientError::ChannelClosed)?;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), ap_client::ClientError> {
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
    let user_identity = MemoryIdentityProvider::new();
    let remote_identity = MemoryIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    // Create mock proxy pair
    let (user_proxy, remote_proxy) = create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

    // Create connection stores
    let user_connection_store = MemoryConnectionStore::new();
    let remote_connection_store = MemoryConnectionStore::new();

    // Create and connect UserClient (already listening)
    let UserClientHandle {
        client: user_client,
        notifications: mut notification_rx,
        requests: _request_rx,
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_connection_store),
        Box::new(user_proxy),
        None,
        None,
    )
    .await
    .expect("UserClient should connect");

    // Get PSK token
    let token = user_client
        .get_psk_token(None, false)
        .await
        .expect("Should generate PSK token");

    // Parse token
    let (psk, fingerprint) = PskToken::parse(&token)
        .expect("Should parse PSK token")
        .into_parts();

    // Create and connect RemoteClient
    let RemoteClientHandle {
        client: remote_client,
        notifications: mut remote_notification_rx,
        requests: _remote_request_rx,
    } = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_connection_store),
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

    // Verify connection is cached
    assert!(
        remote_client
            .has_connection(fingerprint)
            .await
            .expect("has_connection should not fail"),
        "Connection should be cached in RemoteClient's connection store"
    );

    // Cleanup
    drop(remote_client);
    drop(user_client);
}

/// Test rendezvous pairing with user-side fingerprint verification (remote side does NOT verify)
#[tokio::test]
async fn test_fingerprint_pairing() {
    // Create identities
    let user_identity = MemoryIdentityProvider::new();
    let remote_identity = MemoryIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    // Create mock proxy pair
    let (mut user_proxy, mut remote_proxy) =
        create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

    // Set up rendezvous code
    let rendezvous_code = RendezvousCode::from_string("ABCDEF123".to_string());
    user_proxy.set_rendezvous_code(rendezvous_code.clone());
    remote_proxy.set_peer_fingerprint(user_fingerprint);

    // Create connection stores
    let user_connection_store = MemoryConnectionStore::new();
    let remote_connection_store = MemoryConnectionStore::new();

    // Create and connect UserClient (already listening)
    let UserClientHandle {
        client: user_client,
        notifications: notification_rx,
        requests: mut request_rx,
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_connection_store),
        Box::new(user_proxy),
        None,
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
    let RemoteClientHandle {
        client: remote_client,
        notifications: mut remote_notification_rx,
        requests: _remote_request_rx,
    } = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_connection_store),
        Box::new(remote_proxy),
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

    // Verify connection is cached
    assert!(
        remote_client
            .has_connection(paired_fingerprint)
            .await
            .expect("has_connection should not fail"),
        "Connection should be cached in RemoteClient's connection store"
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
        _identity: IdentityKeyPair,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ClientError> {
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
            return Err(ClientError::ChannelClosed);
        }

        // Success: create a new channel that stays open
        let (tx, rx) = mpsc::unbounded_channel();
        self.incoming_tx = Some(tx);
        Ok(rx)
    }

    async fn request_rendezvous(&self) -> Result<(), ClientError> {
        Ok(())
    }

    async fn request_identity(&self, _code: RendezvousCode) -> Result<(), ClientError> {
        Ok(())
    }

    async fn send_to(
        &self,
        _fingerprint: IdentityFingerprint,
        _data: Vec<u8>,
    ) -> Result<(), ClientError> {
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), ClientError> {
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

    let identity = MemoryIdentityProvider::new();
    let connection_store = MemoryConnectionStore::new();

    let proxy = ReconnectingMockProxyClient::new(fail_count, Duration::from_millis(10));
    let connect_calls = Arc::clone(&proxy.connect_calls);

    let UserClientHandle {
        client,
        notifications: mut event_rx,
        requests: _request_rx,
    } = UserClient::connect(
        Box::new(identity),
        Box::new(connection_store),
        Box::new(proxy),
        None,
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
    let user_identity = MemoryIdentityProvider::new();
    let remote_identity = MemoryIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    // Create mock proxy pair
    let (mut user_proxy, mut remote_proxy) =
        create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

    // Set up rendezvous code
    let rendezvous_code = RendezvousCode::from_string("XYZW56789".to_string());
    user_proxy.set_rendezvous_code(rendezvous_code.clone());
    remote_proxy.set_peer_fingerprint(user_fingerprint);

    // Create connection stores
    let user_connection_store = MemoryConnectionStore::new();
    let remote_connection_store = MemoryConnectionStore::new();

    // Create and connect UserClient (already listening)
    let UserClientHandle {
        client: user_client,
        notifications: notification_rx,
        requests: mut request_rx,
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_connection_store),
        Box::new(user_proxy),
        None,
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
    let RemoteClientHandle {
        client: remote_client,
        notifications: remote_notification_rx,
        requests: mut remote_request_rx,
    } = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_connection_store),
        Box::new(remote_proxy),
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

    // Verify connection is cached
    assert!(
        remote_client
            .has_connection(paired_fingerprint)
            .await
            .expect("has_connection should not fail"),
        "Connection should be cached in RemoteClient's connection store"
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
    let user_identity = MemoryIdentityProvider::new();
    let remote_identity = MemoryIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    // Create mock proxy pair
    let (mut user_proxy, remote_proxy) =
        create_mock_proxy_pair(user_fingerprint, remote_fingerprint);
    // Set up rendezvous so get_rendezvous_token doesn't hang
    user_proxy.set_rendezvous_code(RendezvousCode::from_string("DUAL12345".to_string()));

    let user_connection_store = MemoryConnectionStore::new();
    let remote_connection_store = MemoryConnectionStore::new();

    // Create UserClient (already listening)
    let UserClientHandle {
        client: user_client,
        notifications: mut notification_rx,
        requests: _request_rx,
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_connection_store),
        Box::new(user_proxy),
        None,
        None,
    )
    .await
    .expect("UserClient should connect");

    // Set up BOTH pairings
    let psk_token = user_client
        .get_psk_token(Some("psk-device".to_string()), false)
        .await
        .expect("Should generate PSK token");

    let _rendezvous_code = user_client
        .get_rendezvous_token(Some("rendezvous-device".to_string()))
        .await
        .expect("Should get rendezvous token");

    // Parse PSK token
    let (psk, user_fp_from_token) = PskToken::parse(&psk_token)
        .expect("Should parse PSK token")
        .into_parts();

    // Connect RemoteClient via PSK
    let RemoteClientHandle {
        client: remote_client,
        notifications: mut remote_notification_rx,
        requests: _remote_request_rx,
    } = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_connection_store),
        Box::new(remote_proxy),
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

// ============================================================================
// Test: Notification channel does not block event loop
// ============================================================================

/// Verifies that a full notification channel does not stall the event loop.
///
/// The `RemoteClient` never drains notifications, yet credential requests
/// still succeed — proving `try_send` drops notifications instead of blocking.
#[tokio::test]
async fn test_notification_channel_not_blocking_event_loop() {
    let user_identity = MemoryIdentityProvider::new();
    let remote_identity = MemoryIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    let (user_proxy, remote_proxy) = create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

    let user_connection_store = MemoryConnectionStore::new();
    let remote_connection_store = MemoryConnectionStore::new();

    // Connect UserClient
    let UserClientHandle {
        client: user_client,
        notifications: _user_notifications, // not drained
        requests: mut request_rx,
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_connection_store),
        Box::new(user_proxy),
        None,
        None,
    )
    .await
    .expect("UserClient should connect");

    // Get PSK token
    let token = user_client
        .get_psk_token(None, false)
        .await
        .expect("Should generate PSK token");

    let (psk, fingerprint) = PskToken::parse(&token)
        .expect("Should parse PSK token")
        .into_parts();

    // Connect RemoteClient — intentionally never drain notifications
    let RemoteClientHandle {
        client: remote_client,
        notifications: _remote_notifications, // deliberately NOT drained
        requests: _remote_request_rx,
    } = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_connection_store),
        Box::new(remote_proxy),
    )
    .await
    .expect("RemoteClient should connect");

    // Pair via PSK (emits several notifications)
    timeout(
        Duration::from_secs(10),
        remote_client.pair_with_psk(psk, fingerprint),
    )
    .await
    .expect("Pairing should not timeout")
    .expect("Pairing should succeed");

    // Spawn a handler that auto-approves credential requests on the user side
    let handler = tokio::spawn(async move {
        while let Some(request) = request_rx.recv().await {
            if let UserClientRequest::CredentialRequest { reply, .. } = request {
                let _ = reply.send(CredentialRequestReply {
                    approved: true,
                    credential: Some(ap_client::CredentialData {
                        username: Some("test_user".into()),
                        password: Some(Zeroizing::new("test_pass".into())),
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

    // Request enough credentials to overflow the notification channel (capacity 32).
    // Each request emits CredentialRequestSent + CredentialReceived = 2 notifications,
    // plus the pairing emitted ~7, so 32 requests should exceed capacity.
    for i in 0..40 {
        let result = timeout(
            Duration::from_secs(10),
            remote_client.request_credential(
                &ap_client::CredentialQuery::Domain("example.com".to_string()),
                None,
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("Request {i} should not timeout — event loop is blocked"))
        .unwrap_or_else(|e| panic!("Request {i} should succeed: {e}"));

        assert_eq!(result.username, Some("test_user".into()));
    }

    handler.abort();
    let _ = handler.await;
    drop(remote_client);
    drop(user_client);
}

// ============================================================================
// Test: Request channel backpressure blocks event loop (by design)
// ============================================================================

/// Verifies that a full request channel blocks the event loop, providing
/// backpressure. When nobody drains `request_rx`, the `UserClient` event loop
/// blocks on `request_tx.send().await`, causing the `RemoteClient`'s
/// `request_credential` to time out.
#[tokio::test]
async fn test_request_channel_backpressure() {
    let user_identity = MemoryIdentityProvider::new();
    let remote_identity = MemoryIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    let (user_proxy, remote_proxy) = create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

    let user_connection_store = MemoryConnectionStore::new();
    let remote_connection_store = MemoryConnectionStore::new();

    // Connect UserClient — intentionally never drain requests
    let UserClientHandle {
        client: user_client,
        notifications: _user_notifications,
        requests: _request_rx, // deliberately NOT drained
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_connection_store),
        Box::new(user_proxy),
        None,
        None,
    )
    .await
    .expect("UserClient should connect");

    // Get PSK token
    let token = user_client
        .get_psk_token(None, false)
        .await
        .expect("Should generate PSK token");

    let (psk, fingerprint) = PskToken::parse(&token)
        .expect("Should parse PSK token")
        .into_parts();

    // Connect RemoteClient
    let RemoteClientHandle {
        client: remote_client,
        notifications: _remote_notifications,
        requests: _remote_request_rx,
    } = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_connection_store),
        Box::new(remote_proxy),
    )
    .await
    .expect("RemoteClient should connect");

    // Pair via PSK
    timeout(
        Duration::from_secs(10),
        remote_client.pair_with_psk(psk, fingerprint),
    )
    .await
    .expect("Pairing should not timeout")
    .expect("Pairing should succeed");

    // Request a credential — since nobody drains request_rx, the UserClient
    // event loop will eventually block on request_tx.send().await, and the
    // RemoteClient's request_credential will time out waiting for a response.
    let result = timeout(
        Duration::from_secs(3),
        remote_client.request_credential(
            &ap_client::CredentialQuery::Domain("example.com".to_string()),
            None,
        ),
    )
    .await;

    assert!(
        result.is_err(),
        "request_credential should time out when request channel is not drained (backpressure)"
    );

    drop(remote_client);
    drop(user_client);
}

// ============================================================================
// Test: Credential request buffered during fingerprint verification
// ============================================================================

/// Verifies that a credential request sent by the RemoteClient *before* the
/// UserClient has approved the fingerprint is buffered and replayed after
/// approval, rather than being silently dropped.
///
/// Timeline:
/// 1. Noise handshake completes on both sides
/// 2. RemoteClient immediately sends a CredentialRequest (before fingerprint approval)
/// 3. UserClient delays fingerprint approval by 100ms, ensuring the credential
///    request arrives while the transport is still in the pending-verification state
/// 4. After approval, the buffered credential request is replayed and handled normally
#[tokio::test]
async fn test_credential_request_buffered_during_fingerprint_verification() {
    // Create identities
    let user_identity = MemoryIdentityProvider::new();
    let remote_identity = MemoryIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    // Create mock proxy pair
    let (mut user_proxy, mut remote_proxy) =
        create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

    // Set up rendezvous code
    let rendezvous_code = RendezvousCode::from_string("BUF123456".to_string());
    user_proxy.set_rendezvous_code(rendezvous_code.clone());
    remote_proxy.set_peer_fingerprint(user_fingerprint);

    // Create connection stores
    let user_connection_store = MemoryConnectionStore::new();
    let remote_connection_store = MemoryConnectionStore::new();

    // Create and connect UserClient
    let UserClientHandle {
        client: user_client,
        notifications: _notification_rx,
        requests: mut request_rx,
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_connection_store),
        Box::new(user_proxy),
        None,
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
    let RemoteClientHandle {
        client: remote_client,
        notifications: _remote_notification_rx,
        requests: _remote_request_rx,
    } = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(remote_connection_store),
        Box::new(remote_proxy),
    )
    .await
    .expect("RemoteClient should connect");

    // Spawn task: pair then immediately request a credential (before fingerprint approval)
    let remote_task = {
        let remote_client = remote_client.clone();
        tokio::spawn(async move {
            // Complete the Noise handshake (returns once handshake finishes, NOT after fingerprint)
            remote_client
                .pair_with_handshake(code, false)
                .await
                .expect("Pairing should succeed");

            // Immediately request a credential — the UserClient hasn't approved yet
            let credential = remote_client
                .request_credential(
                    &ap_client::CredentialQuery::Domain("buffered.example.com".to_string()),
                    None,
                )
                .await
                .expect("Credential request should succeed after fingerprint approval");

            credential
        })
    };

    // Handle UserClient requests sequentially:
    // 1. VerifyFingerprint — delay, then approve (so the credential request arrives while pending)
    // 2. CredentialRequest — the replayed buffered message
    let handler = tokio::spawn(async move {
        // First: fingerprint verification with a delay
        let request = timeout(Duration::from_secs(10), request_rx.recv())
            .await
            .expect("Should receive fingerprint request")
            .expect("Channel should not be closed");

        if let UserClientRequest::VerifyFingerprint { reply, .. } = request {
            // Delay to ensure the RemoteClient's credential request arrives and is buffered
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = reply.send(FingerprintVerificationReply {
                approved: true,
                name: None,
            });
        } else {
            panic!("Expected VerifyFingerprint request, got: {request:?}");
        }

        // Second: credential request (replayed from buffer)
        let request = timeout(Duration::from_secs(10), request_rx.recv())
            .await
            .expect("Should receive credential request (buffered and replayed)")
            .expect("Channel should not be closed");

        if let UserClientRequest::CredentialRequest { reply, .. } = request {
            let _ = reply.send(CredentialRequestReply {
                approved: true,
                credential: Some(ap_client::CredentialData {
                    username: Some("buffered_user".into()),
                    password: Some(Zeroizing::new("buffered_pass".into())),
                    totp: None,
                    uri: None,
                    notes: None,
                    credential_id: None,
                    domain: Some("buffered.example.com".into()),
                }),
                credential_id: None,
            });
        } else {
            panic!("Expected CredentialRequest, got: {request:?}");
        }
    });

    // Wait for the remote task to complete and verify the credential
    let credential = timeout(Duration::from_secs(15), remote_task)
        .await
        .expect("Remote task should not timeout")
        .expect("Remote task should not panic");

    assert_eq!(credential.username, Some("buffered_user".into()));
    assert_eq!(
        credential.password,
        Some(Zeroizing::new("buffered_pass".into()))
    );
    assert_eq!(credential.domain, Some("buffered.example.com".into()));

    handler.await.expect("Handler task should complete");

    // Cleanup
    drop(remote_client);
    drop(user_client);
}

// ============================================================================
// Test: Reusable PSK pairing (multiple remote clients with same PSK)
// ============================================================================

/// Verifies that a reusable PSK allows two different RemoteClients to connect
/// using the same PSK token. The first connection should NOT consume the pairing.
#[tokio::test]
async fn test_reusable_psk_pairing() {
    // Create user identity
    let user_identity = MemoryIdentityProvider::new();
    let user_fingerprint = user_identity.fingerprint().await;

    // Create two remote identities
    let remote_identity1 = MemoryIdentityProvider::new();
    let remote_identity2 = MemoryIdentityProvider::new();
    let remote_fingerprint1 = remote_identity1.fingerprint().await;
    let remote_fingerprint2 = remote_identity2.fingerprint().await;

    // --- First connection: remote1 ---
    let (user_proxy1, remote_proxy1) =
        create_mock_proxy_pair(user_fingerprint, remote_fingerprint1);

    let user_connection_store = MemoryConnectionStore::new();
    let remote_connection_store1 = MemoryConnectionStore::new();
    let psk_store = ap_client::MemoryPskStore::new();

    let UserClientHandle {
        client: user_client,
        notifications: mut notification_rx,
        requests: _request_rx,
    } = UserClient::connect(
        Box::new(user_identity.clone()),
        Box::new(user_connection_store),
        Box::new(user_proxy1),
        None,
        Some(Box::new(psk_store)),
    )
    .await
    .expect("UserClient should connect");

    // Generate a reusable PSK token
    let token = user_client
        .get_psk_token(Some("ci-runner".to_string()), true)
        .await
        .expect("Should generate reusable PSK token");

    // Parse token
    let parsed = PskToken::parse(&token).expect("Should parse PSK token");
    let psk1 = parsed.psk().clone();
    let user_fp = *parsed.fingerprint();

    // Connect remote1 with the PSK
    let RemoteClientHandle {
        client: remote_client1,
        notifications: mut remote_notification_rx1,
        requests: _,
    } = RemoteClient::connect(
        Box::new(remote_identity1),
        Box::new(remote_connection_store1),
        Box::new(remote_proxy1),
    )
    .await
    .expect("RemoteClient 1 should connect");

    timeout(
        Duration::from_secs(10),
        remote_client1.pair_with_psk(psk1, user_fp),
    )
    .await
    .expect("Pairing 1 should not timeout")
    .expect("Pairing 1 should succeed");

    // Verify handshake completed
    let mut handshake_complete1 = false;
    while let Ok(Some(event)) =
        timeout(Duration::from_millis(100), remote_notification_rx1.recv()).await
    {
        if matches!(event, RemoteClientNotification::HandshakeComplete) {
            handshake_complete1 = true;
        }
    }
    assert!(
        handshake_complete1,
        "RemoteClient 1 should emit HandshakeComplete"
    );

    // Drain user notifications
    while let Ok(Some(_)) = timeout(Duration::from_millis(100), notification_rx.recv()).await {}

    // --- Second connection: remote2 ---
    // Drop the first connection and reconnect the user client
    drop(remote_client1);
    drop(user_client);
    drop(notification_rx);

    // Re-create user client with a fresh proxy pair for remote2
    let (user_proxy2, remote_proxy2) =
        create_mock_proxy_pair(user_fingerprint, remote_fingerprint2);

    let user_connection_store2 = MemoryConnectionStore::new();
    let remote_connection_store2 = MemoryConnectionStore::new();

    // Re-create a fresh psk store with the same PSK entry loaded manually
    // (simulating what FilePskStore would do across restarts)
    let mut psk_store2 = ap_client::MemoryPskStore::new();
    let parsed2 = PskToken::parse(&token).expect("Should parse PSK token again");
    let psk_for_store = parsed2.psk().clone();
    ap_client::PskStore::save(
        &mut psk_store2,
        ap_client::PskEntry {
            psk_id: psk_for_store.id(),
            psk: psk_for_store.clone(),
            name: Some("ci-runner".to_string()),
            created_at: 0,
        },
    )
    .await
    .expect("Should save to psk store");

    let UserClientHandle {
        client: user_client2,
        notifications: mut notification_rx2,
        requests: _,
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_connection_store2),
        Box::new(user_proxy2),
        None,
        Some(Box::new(psk_store2)),
    )
    .await
    .expect("UserClient should reconnect");

    // Connect remote2 with the SAME PSK
    let RemoteClientHandle {
        client: remote_client2,
        notifications: mut remote_notification_rx2,
        requests: _,
    } = RemoteClient::connect(
        Box::new(remote_identity2),
        Box::new(remote_connection_store2),
        Box::new(remote_proxy2),
    )
    .await
    .expect("RemoteClient 2 should connect");

    let psk2 = parsed2.psk().clone();
    timeout(
        Duration::from_secs(10),
        remote_client2.pair_with_psk(psk2, user_fp),
    )
    .await
    .expect("Pairing 2 should not timeout")
    .expect("Pairing 2 should succeed with same reusable PSK");

    // Verify handshake completed for remote2
    let mut handshake_complete2 = false;
    while let Ok(Some(event)) =
        timeout(Duration::from_millis(100), remote_notification_rx2.recv()).await
    {
        if matches!(event, RemoteClientNotification::HandshakeComplete) {
            handshake_complete2 = true;
        }
    }
    assert!(
        handshake_complete2,
        "RemoteClient 2 should emit HandshakeComplete with reused PSK"
    );

    // Verify user side completed handshake for remote2
    let mut user_handshake_complete2 = false;
    while let Ok(Some(event)) = timeout(Duration::from_millis(100), notification_rx2.recv()).await {
        if matches!(event, UserClientNotification::HandshakeComplete {}) {
            user_handshake_complete2 = true;
        }
    }
    assert!(
        user_handshake_complete2,
        "UserClient should emit HandshakeComplete for second connection"
    );

    drop(remote_client2);
    drop(user_client2);
}

// ============================================================================
// Test: Reusable PSK works when remote fingerprint is already cached
// ============================================================================

/// Verifies that a reusable PSK handshake succeeds even when the remote device's
/// fingerprint is already in the connection store from a prior connection.
///
/// This is the primary CI/CD scenario: the listener persists connections across
/// restarts, but the remote reconnects with the same PSK token each time.
/// Without the fix, the user client would skip PSK lookup for cached fingerprints
/// and do a null-PSK handshake, causing a mismatch.
#[tokio::test]
async fn test_reusable_psk_with_cached_connection() {
    let user_identity = MemoryIdentityProvider::new();
    let remote_identity = MemoryIdentityProvider::new();

    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    let (user_proxy, remote_proxy) = create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

    // Pre-populate the connection store with the remote's fingerprint
    // (simulates a previous successful connection)
    let mut user_connection_store = MemoryConnectionStore::new();
    ap_client::ConnectionStore::save(
        &mut user_connection_store,
        ap_client::ConnectionInfo {
            fingerprint: remote_fingerprint,
            name: Some("previously-paired".to_string()),
            cached_at: 1000,
            last_connected_at: 1000,
            transport_state: None,
        },
    )
    .await
    .expect("Should save connection");

    let psk_store = ap_client::MemoryPskStore::new();

    let UserClientHandle {
        client: user_client,
        notifications: mut notification_rx,
        requests: _,
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_connection_store),
        Box::new(user_proxy),
        None,
        Some(Box::new(psk_store)),
    )
    .await
    .expect("UserClient should connect");

    // Generate a reusable PSK token
    let token = user_client
        .get_psk_token(None, true)
        .await
        .expect("Should generate reusable PSK token");

    let parsed = PskToken::parse(&token).expect("Should parse PSK token");
    let psk = parsed.psk().clone();
    let user_fp = *parsed.fingerprint();

    // Connect remote (whose fingerprint is ALREADY cached in the user's connection store)
    let RemoteClientHandle {
        client: remote_client,
        notifications: mut remote_notification_rx,
        requests: _,
    } = RemoteClient::connect(
        Box::new(remote_identity),
        Box::new(MemoryConnectionStore::new()),
        Box::new(remote_proxy),
    )
    .await
    .expect("RemoteClient should connect");

    timeout(
        Duration::from_secs(10),
        remote_client.pair_with_psk(psk, user_fp),
    )
    .await
    .expect("Pairing should not timeout")
    .expect("Pairing should succeed even with cached connection");

    // Verify handshake completed on both sides
    let mut remote_ok = false;
    while let Ok(Some(event)) =
        timeout(Duration::from_millis(100), remote_notification_rx.recv()).await
    {
        if matches!(event, RemoteClientNotification::HandshakeComplete) {
            remote_ok = true;
        }
    }
    assert!(remote_ok, "RemoteClient should emit HandshakeComplete");

    // User side should emit SessionRefreshed (not HandshakeComplete for new PSK)
    // because the connection was already cached
    let mut user_ok = false;
    while let Ok(Some(event)) = timeout(Duration::from_millis(100), notification_rx.recv()).await {
        if matches!(
            event,
            UserClientNotification::HandshakeComplete {}
                | UserClientNotification::SessionRefreshed { .. }
        ) {
            user_ok = true;
        }
    }
    assert!(
        user_ok,
        "UserClient should emit HandshakeComplete or SessionRefreshed"
    );

    drop(remote_client);
    drop(user_client);
}

// ============================================================================
// Test: Reusable PSK requires a PskStore
// ============================================================================

/// Verifies that requesting a reusable PSK token without a configured PskStore
/// returns an appropriate error.
#[tokio::test]
async fn test_reusable_psk_no_store_error() {
    let user_identity = MemoryIdentityProvider::new();
    let remote_identity = MemoryIdentityProvider::new();
    let user_fingerprint = user_identity.fingerprint().await;
    let remote_fingerprint = remote_identity.fingerprint().await;

    let (user_proxy, _remote_proxy) = create_mock_proxy_pair(user_fingerprint, remote_fingerprint);

    let UserClientHandle {
        client: user_client,
        notifications: _,
        requests: _,
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(MemoryConnectionStore::new()),
        Box::new(user_proxy),
        None,
        None, // No PskStore
    )
    .await
    .expect("UserClient should connect");

    // Requesting a reusable PSK without a store should fail
    let result = user_client.get_psk_token(None, true).await;
    assert!(
        result.is_err(),
        "get_psk_token(reusable: true) without PskStore should fail"
    );

    drop(user_client);
}
