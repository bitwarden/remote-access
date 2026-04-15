//! Integration tests for ap-uniffi
//!
//! Tests the UniFFI wrapper against a real proxy server, exercising the full
//! protocol stack: proxy connection, PSK pairing, credential exchange.

use std::net::SocketAddr;
use std::sync::Mutex;

use ap_client::{
    CredentialData, CredentialRequestReply, DefaultProxyClient, FingerprintVerificationReply,
    MemoryConnectionStore, MemoryIdentityProvider, UserClient, UserClientHandle, UserClientRequest,
};
use ap_uniffi::{
    ClientError, ConnectionStorage, CredentialProvider, FfiCredentialData, FfiCredentialQuery,
    FfiStoredConnection, IdentityStorage, RemoteClient, UserClient as UniffiUserClient,
    looks_like_psk_token,
};
use tokio::time::Duration;
use zeroize::Zeroizing;

// ============================================================================
// Test Storage Implementations
// ============================================================================

struct MemoryIdentityStorage {
    data: Mutex<Option<Vec<u8>>>,
}

impl MemoryIdentityStorage {
    fn new() -> Self {
        Self {
            data: Mutex::new(None),
        }
    }
}

impl IdentityStorage for MemoryIdentityStorage {
    fn load_identity(&self) -> Option<Vec<u8>> {
        self.data.lock().expect("identity lock").clone()
    }

    fn save_identity(&self, identity_bytes: Vec<u8>) -> Result<(), ClientError> {
        *self.data.lock().expect("identity lock") = Some(identity_bytes);
        Ok(())
    }
}

struct MemoryConnectionStorage {
    data: Mutex<Vec<FfiStoredConnection>>,
}

impl MemoryConnectionStorage {
    fn new() -> Self {
        Self {
            data: Mutex::new(Vec::new()),
        }
    }
}

impl ConnectionStorage for MemoryConnectionStorage {
    fn get(&self, fingerprint_hex: String) -> Option<FfiStoredConnection> {
        self.data
            .lock()
            .expect("connection lock")
            .iter()
            .find(|c| c.fingerprint == fingerprint_hex)
            .cloned()
    }

    fn save(&self, connection: FfiStoredConnection) -> Result<(), ClientError> {
        let mut data = self.data.lock().expect("connection lock");
        if let Some(existing) = data
            .iter_mut()
            .find(|c| c.fingerprint == connection.fingerprint)
        {
            *existing = connection;
        } else {
            data.push(connection);
        }
        Ok(())
    }

    fn update(&self, fingerprint_hex: String, last_connected_at: u64) -> Result<(), ClientError> {
        let mut data = self.data.lock().expect("connection lock");
        if let Some(conn) = data.iter_mut().find(|c| c.fingerprint == fingerprint_hex) {
            conn.last_connected_at = last_connected_at;
        }
        Ok(())
    }

    fn list(&self) -> Vec<FfiStoredConnection> {
        self.data.lock().expect("connection lock").clone()
    }
}

// ============================================================================
// Test Infrastructure
// ============================================================================

async fn start_test_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind to localhost");
    let addr = listener.local_addr().expect("should get local address");
    drop(listener);

    let server = ap_proxy::server::ProxyServer::new(addr);
    tokio::spawn(async move { server.run().await.ok() });
    tokio::time::sleep(Duration::from_millis(100)).await;

    addr
}

fn test_credential() -> CredentialData {
    CredentialData {
        username: Some("testuser".to_string()),
        password: Some(Zeroizing::new("testpassword123".to_string())),
        totp: Some("123456".to_string()),
        uri: Some("https://example.com".to_string()),
        notes: Some("Test credential notes".to_string()),
        credential_id: None,
        domain: None,
    }
}

fn test_ffi_credential() -> FfiCredentialData {
    FfiCredentialData {
        username: Some("testuser".to_string()),
        password: Some("testpassword123".to_string()),
        totp: Some("123456".to_string()),
        uri: Some("https://example.com".to_string()),
        notes: Some("Test credential notes".to_string()),
        credential_id: None,
        domain: None,
    }
}

/// Helper: set up a UserClient (trusted side) with PSK mode using the raw ap-client API.
/// Returns the PSK token string.
async fn setup_user_client_psk(addr: SocketAddr) -> (String, Vec<tokio::task::JoinHandle<()>>) {
    let user_identity = MemoryIdentityProvider::new();
    let user_proxy = Box::new(DefaultProxyClient::from_url(format!("ws://{addr}")));
    let user_session_store = MemoryConnectionStore::new();

    let UserClientHandle {
        client: user_client,
        mut notifications,
        mut requests,
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_session_store),
        user_proxy,
        None,
        None,
    )
    .await
    .expect("UserClient should connect");

    let psk_token = user_client
        .get_psk_token(None, false)
        .await
        .expect("Should get PSK token");

    let notif_task =
        tokio::task::spawn(async move { while let Some(_notif) = notifications.recv().await {} });

    let cred_task = tokio::task::spawn(async move {
        loop {
            match requests.recv().await {
                Some(UserClientRequest::CredentialRequest { reply, .. }) => {
                    reply
                        .send(CredentialRequestReply {
                            approved: true,
                            credential: Some(test_credential()),
                            credential_id: None,
                        })
                        .expect("Should send credential reply");
                    break;
                }
                Some(UserClientRequest::VerifyFingerprint { reply, .. }) => {
                    reply
                        .send(FingerprintVerificationReply {
                            approved: true,
                            name: None,
                        })
                        .expect("Should send fingerprint reply");
                }
                None => break,
            }
        }
    });

    // Keep user_client alive (its event loop shuts down when all handles drop)
    let keepalive = tokio::task::spawn(async move {
        let _client = user_client;
        tokio::time::sleep(Duration::from_secs(300)).await;
    });

    (psk_token, vec![notif_task, cred_task, keepalive])
}

fn make_remote_client(proxy_url: String) -> RemoteClient {
    RemoteClient::new(
        proxy_url,
        Box::new(MemoryIdentityStorage::new()),
        Box::new(MemoryConnectionStorage::new()),
        None,
        None,
    )
    .expect("should create client")
}

// ============================================================================
// RemoteClient Tests
// ============================================================================

#[tokio::test]
async fn connect_to_nonexistent_proxy_fails() {
    let client = make_remote_client("ws://127.0.0.1:1".to_string());
    let result = client.connect().await;
    assert!(result.is_err());
}

/// PSK pairing + credential exchange through the split UniFFI API.
#[tokio::test]
async fn test_psk_pairing_and_credential_request() {
    let addr = start_test_server().await;
    let (psk_token, tasks) = setup_user_client_psk(addr).await;

    let proxy_url = format!("ws://{addr}");
    let client = make_remote_client(proxy_url);

    client.connect().await.expect("connect should succeed");
    client
        .pair_with_psk(psk_token)
        .await
        .expect("pair_with_psk should succeed");

    let cred = client
        .request_credential(
            FfiCredentialQuery::Domain {
                value: "example.com".to_string(),
            },
            None,
        )
        .await
        .expect("credential request should succeed");
    client.close().await;

    assert_eq!(cred.username.as_deref(), Some("testuser"));
    assert_eq!(cred.password.as_deref(), Some("testpassword123"));
    assert_eq!(cred.totp.as_deref(), Some("123456"));

    for t in tasks {
        t.abort();
    }
}

/// Rendezvous pairing through the split UniFFI API.
#[tokio::test]
async fn test_rendezvous_pairing_and_credential_request() {
    let addr = start_test_server().await;

    let user_identity = MemoryIdentityProvider::new();
    let user_proxy = Box::new(DefaultProxyClient::from_url(format!("ws://{addr}")));
    let user_session_store = MemoryConnectionStore::new();

    let UserClientHandle {
        client: user_client,
        mut notifications,
        mut requests,
    } = UserClient::connect(
        Box::new(user_identity),
        Box::new(user_session_store),
        user_proxy,
        None,
        None,
    )
    .await
    .expect("UserClient should connect");

    let code = user_client
        .get_rendezvous_token(None)
        .await
        .expect("Should get rendezvous code");

    let _notif =
        tokio::task::spawn(async move { while let Some(_n) = notifications.recv().await {} });

    let cred_task = tokio::task::spawn(async move {
        loop {
            match requests.recv().await {
                Some(UserClientRequest::VerifyFingerprint { reply, .. }) => {
                    reply
                        .send(FingerprintVerificationReply {
                            approved: true,
                            name: None,
                        })
                        .expect("send fp");
                }
                Some(UserClientRequest::CredentialRequest { reply, .. }) => {
                    reply
                        .send(CredentialRequestReply {
                            approved: true,
                            credential: Some(test_credential()),
                            credential_id: None,
                        })
                        .expect("send cred");
                    break;
                }
                None => break,
            }
        }
    });

    let proxy_url = format!("ws://{addr}");
    let client = make_remote_client(proxy_url);

    client.connect().await.expect("connect should succeed");
    let fp = client
        .pair_with_handshake(code.to_string())
        .await
        .expect("pair_with_handshake should succeed");
    assert!(!fp.is_empty(), "Fingerprint should not be empty");

    let cred = client
        .request_credential(
            FfiCredentialQuery::Domain {
                value: "example.com".to_string(),
            },
            None,
        )
        .await
        .expect("credential request should succeed");
    client.close().await;

    assert_eq!(cred.username.as_deref(), Some("testuser"));

    cred_task.abort();
    drop(user_client);
}

#[tokio::test]
async fn connect_no_token_no_sessions_gives_error() {
    let client = make_remote_client("ws://127.0.0.1:1".to_string());
    let result = client.connect().await;
    assert!(result.is_err());
}

#[test]
fn looks_like_psk_token_works() {
    let psk_hex = "a".repeat(64);
    let fp_hex = "b".repeat(64);
    let token = format!("{psk_hex}_{fp_hex}");
    assert!(looks_like_psk_token(token));
    assert!(!looks_like_psk_token("ABC-DEF-GHI".to_string()));
    assert!(!looks_like_psk_token("too-short".to_string()));
}

// ============================================================================
// UniffiUserClient Tests
// ============================================================================

/// Test UniffiUserClient with CredentialProvider callback.
#[tokio::test]
async fn test_user_access_client_with_credential_provider() {
    /// Simple test credential provider.
    struct TestProvider;

    impl CredentialProvider for TestProvider {
        fn handle_credential_request(
            &self,
            _query: FfiCredentialQuery,
            _remote_fingerprint: String,
        ) -> Option<FfiCredentialData> {
            Some(test_ffi_credential())
        }
    }

    let addr = start_test_server().await;
    let proxy_url = format!("ws://{addr}");

    let user = UniffiUserClient::new(
        proxy_url.clone(),
        Box::new(MemoryIdentityStorage::new()),
        Box::new(MemoryConnectionStorage::new()),
        Box::new(TestProvider),
        None, // fingerprint_verifier
        None, // event_handler
        None, // audit_logger
        None, // psk_storage
    )
    .expect("should create user client");
    user.connect().await.expect("user connect should succeed");
    let psk_token = user
        .get_psk_token(None, false)
        .await
        .expect("should get psk token");

    let client = make_remote_client(proxy_url);

    client.connect().await.expect("connect should succeed");
    client
        .pair_with_psk(psk_token)
        .await
        .expect("pair_with_psk should succeed");

    let result = client
        .request_credential(
            FfiCredentialQuery::Domain {
                value: "example.com".to_string(),
            },
            None,
        )
        .await
        .expect("credential request should succeed");
    client.close().await;

    assert_eq!(result.username.as_deref(), Some("testuser"));
    assert_eq!(result.password.as_deref(), Some("testpassword123"));
    assert_eq!(result.totp.as_deref(), Some("123456"));

    user.close().await;
}
