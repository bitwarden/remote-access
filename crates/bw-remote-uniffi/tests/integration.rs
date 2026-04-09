//! Integration tests for bw-remote-uniffi
//!
//! Tests the UniFFI wrapper against a real proxy server, exercising the full
//! protocol stack: proxy connection, PSK pairing, credential exchange.

use std::net::SocketAddr;

use ap_client::{
    CredentialData, CredentialRequestReply, DefaultProxyClient, FingerprintVerificationReply,
    MemoryConnectionStore, MemoryIdentityProvider, UserClient, UserClientHandle, UserClientRequest,
};
use bw_remote_uniffi::{
    CredentialProvider, FfiCredentialData, RemoteAccessClient, UserAccessClient,
    looks_like_psk_token,
};
use tokio::time::Duration;
use zeroize::Zeroizing;

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
        tokio::task::spawn_local(
            async move { while let Some(_notif) = notifications.recv().await {} },
        );

    let cred_task = tokio::task::spawn_local(async move {
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
    let _keepalive = tokio::task::spawn_local(async move {
        let _client = user_client;
        tokio::time::sleep(Duration::from_secs(300)).await;
    });

    (psk_token, vec![notif_task, cred_task, _keepalive])
}

// ============================================================================
// RemoteAccessClient Tests
// ============================================================================

#[test]
fn connect_to_nonexistent_proxy_fails() {
    let client =
        RemoteAccessClient::new("ws://127.0.0.1:1".to_string(), "test-int".to_string(), None)
            .expect("should create client");

    let result = client.connect();
    assert!(result.is_err());
}

/// PSK pairing + credential exchange through the split UniFFI API.
#[tokio::test(flavor = "current_thread")]
async fn test_psk_pairing_and_credential_request() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let addr = start_test_server().await;
            let (psk_token, tasks) = setup_user_client_psk(addr).await;

            let proxy_url = format!("ws://{addr}");
            let result = tokio::task::spawn_blocking(move || {
                let client = RemoteAccessClient::new(proxy_url, "test-psk".to_string(), None)
                    .expect("should create client");

                client.connect().expect("connect should succeed");
                client
                    .pair_with_psk(psk_token)
                    .expect("pair_with_psk should succeed");

                let cred = client
                    .request_credential("example.com".to_string())
                    .expect("credential request should succeed");
                client.close();
                cred
            })
            .await
            .expect("blocking task should not panic");

            assert_eq!(result.username.as_deref(), Some("testuser"));
            assert_eq!(result.password.as_deref(), Some("testpassword123"));
            assert_eq!(result.totp.as_deref(), Some("123456"));

            for t in tasks {
                t.abort();
            }
        })
        .await;
}

/// Rendezvous pairing through the split UniFFI API.
#[tokio::test(flavor = "current_thread")]
async fn test_rendezvous_pairing_and_credential_request() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
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

            let _notif = tokio::task::spawn_local(async move {
                while let Some(_n) = notifications.recv().await {}
            });

            let cred_task = tokio::task::spawn_local(async move {
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
            let code_str = code.to_string();
            let result = tokio::task::spawn_blocking(move || {
                let client = RemoteAccessClient::new(proxy_url, "test-rdv".to_string(), None)
                    .expect("should create client");

                client.connect().expect("connect should succeed");
                let fp = client
                    .pair_with_handshake(code_str)
                    .expect("pair_with_handshake should succeed");
                assert!(!fp.is_empty(), "Fingerprint should not be empty");

                let cred = client
                    .request_credential("example.com".to_string())
                    .expect("credential request should succeed");
                client.close();
                cred
            })
            .await
            .expect("blocking task should not panic");

            assert_eq!(result.username.as_deref(), Some("testuser"));

            cred_task.abort();
            // Keep user_client alive for the test duration
            drop(user_client);
        })
        .await;
}

#[test]
fn connect_no_token_no_sessions_gives_error() {
    let client = RemoteAccessClient::new(
        "ws://127.0.0.1:1".to_string(),
        "test-nosession".to_string(),
        None,
    )
    .expect("should create client");

    // connect() to a non-existent proxy should fail
    let result = client.connect();
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
// UserAccessClient Tests
// ============================================================================

/// Test UserAccessClient with CredentialProvider callback.
#[tokio::test(flavor = "current_thread")]
async fn test_user_access_client_with_credential_provider() {
    /// Simple test credential provider.
    struct TestProvider;

    impl CredentialProvider for TestProvider {
        fn handle_credential_request(
            &self,
            _query_type: String,
            _query_value: String,
            _remote_fingerprint: String,
        ) -> Option<FfiCredentialData> {
            Some(test_ffi_credential())
        }

        fn verify_fingerprint(&self, _fingerprint: String, _remote_identity: String) -> bool {
            true
        }
    }

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let addr = start_test_server().await;
            let proxy_url = format!("ws://{addr}");

            // Both UserAccessClient and RemoteAccessClient use block_on internally,
            // so they must run on blocking threads (not inside the tokio runtime).
            let proxy_url_clone = proxy_url.clone();
            let psk_token = tokio::task::spawn_blocking(move || {
                let user = UserAccessClient::new(
                    proxy_url_clone,
                    "test-user-cb".to_string(),
                    Box::new(TestProvider),
                    None,
                )
                .expect("should create user client");
                user.connect().expect("user connect should succeed");
                let token = user.get_psk_token(false).expect("should get psk token");
                // Keep user alive on a background thread so its event loop runs
                // for the duration of the test (Drop shuts it down)
                let _keepalive = Box::leak(Box::new(user));
                token
            })
            .await
            .expect("user setup should not panic");

            let result = tokio::task::spawn_blocking(move || {
                let client = RemoteAccessClient::new(proxy_url, "test-remote-cb".to_string(), None)
                    .expect("should create remote client");

                client.connect().expect("connect should succeed");
                client
                    .pair_with_psk(psk_token)
                    .expect("pair_with_psk should succeed");

                let cred = client
                    .request_credential("example.com".to_string())
                    .expect("credential request should succeed");
                client.close();
                cred
            })
            .await
            .expect("blocking task should not panic");

            assert_eq!(result.username.as_deref(), Some("testuser"));
            assert_eq!(result.password.as_deref(), Some("testpassword123"));
            assert_eq!(result.totp.as_deref(), Some("123456"));
        })
        .await;
}
