//! Integration tests for bw-remote-uniffi
//!
//! Tests the UniFFI wrapper against a real proxy server, exercising the full
//! protocol stack: proxy connection, PSK pairing, credential exchange.

use std::net::SocketAddr;

use ap_client::{
    CredentialData, CredentialRequestReply, DefaultProxyClient, FingerprintVerificationReply,
    MemoryConnectionStore, MemoryIdentityProvider, UserClient, UserClientHandle,
    UserClientRequest,
};
use bw_remote_uniffi::RemoteAccessClient;
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
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            // 1. Start real proxy server
            let addr = start_test_server().await;

            // 2. Set up UserClient (the "trusted device" side)
            let user_identity = MemoryIdentityProvider::new();
            let user_proxy =
                Box::new(DefaultProxyClient::from_url(format!("ws://{addr}")));
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

            // 3. Get PSK token
            let psk_token = user_client
                .get_psk_token(None, false)
                .await
                .expect("Should get PSK token");

            // 4. Spawn notification drainer (ignore notifications)
            let _notif_drainer = tokio::task::spawn_local(async move {
                while let Some(_notif) = notifications.recv().await {}
            });

            // 5. Spawn credential response handler
            let credential_handler = tokio::task::spawn_local(async move {
                loop {
                    match requests.recv().await {
                        Some(UserClientRequest::CredentialRequest {
                            query: _,
                            identity: _,
                            reply,
                        }) => {
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
                        None => panic!("Request channel closed unexpectedly"),
                    }
                }
            });

            // 6. Use the UniFFI wrapper to connect and request credential
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
        })
        .await;
}

/// Test full rendezvous pairing + credential exchange through the UniFFI wrapper.
#[tokio::test(flavor = "current_thread")]
async fn test_uniffi_rendezvous_pairing_and_credential_request() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            // 1. Start real proxy server
            let addr = start_test_server().await;

            // 2. Set up UserClient with rendezvous mode
            let user_identity = MemoryIdentityProvider::new();
            let user_proxy =
                Box::new(DefaultProxyClient::from_url(format!("ws://{addr}")));
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

            // 3. Get rendezvous code
            let code = user_client
                .get_rendezvous_token(None)
                .await
                .expect("Should get rendezvous code");

            // 4. Spawn notification drainer
            let _notif_drainer = tokio::task::spawn_local(async move {
                while let Some(_notif) = notifications.recv().await {}
            });

            // 5. Spawn fingerprint auto-approval + credential response handler
            let credential_handler = tokio::task::spawn_local(async move {
                loop {
                    match requests.recv().await {
                        Some(UserClientRequest::VerifyFingerprint { reply, .. }) => {
                            // Auto-approve fingerprint
                            reply
                                .send(FingerprintVerificationReply {
                                    approved: true,
                                    name: None,
                                })
                                .expect("Should send fingerprint approval");
                        }
                        Some(UserClientRequest::CredentialRequest {
                            query: _,
                            identity: _,
                            reply,
                        }) => {
                            reply
                                .send(CredentialRequestReply {
                                    approved: true,
                                    credential: Some(test_credential()),
                                    credential_id: None,
                                })
                                .expect("Should send credential response");
                            break;
                        }
                        None => panic!("Request channel closed unexpectedly"),
                    }
                }
            });

            // 6. Use UniFFI wrapper with rendezvous code
            let proxy_url = format!("ws://{addr}");
            let code_str = code.to_string();
            let result = tokio::task::spawn_blocking(move || {
                let client = RemoteAccessClient::new(proxy_url, "test-uniffi-rdv".to_string())
                    .expect("should create client");

                // Connect with rendezvous code
                let fingerprint = client
                    .connect(Some(code_str), None)
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

            // 7. Verify credential
            assert_eq!(result.username.as_deref(), Some("testuser"));
            assert_eq!(result.password.as_deref(), Some("testpassword123"));
            assert_eq!(result.totp.as_deref(), Some("123456"));

            // Cleanup
            credential_handler.abort();
        })
        .await;
}

/// Test that connect_and_request convenience function works end-to-end.
#[tokio::test(flavor = "current_thread")]
async fn test_uniffi_connect_and_request_convenience() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let addr = start_test_server().await;

            let user_identity = MemoryIdentityProvider::new();
            let user_proxy =
                Box::new(DefaultProxyClient::from_url(format!("ws://{addr}")));
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

            let _notif_drainer = tokio::task::spawn_local(async move {
                while let Some(_notif) = notifications.recv().await {}
            });

            let credential_handler = tokio::task::spawn_local(async move {
                loop {
                    match requests.recv().await {
                        Some(UserClientRequest::CredentialRequest {
                            query: _,
                            identity: _,
                            reply,
                        }) => {
                            reply
                                .send(CredentialRequestReply {
                                    approved: true,
                                    credential: Some(test_credential()),
                                    credential_id: None,
                                })
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
        })
        .await;
}

/// Test that connecting with no token and no cached sessions gives a clear error.
#[test]
fn connect_no_token_no_sessions_gives_error() {
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
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let addr = start_test_server().await;

            // Set up two separate UserClient PSK sessions
            let mut psk_tokens = Vec::new();
            let mut credential_handlers = Vec::new();
            // Keep UserClient handles alive so their event loops don't shut down
            let mut _user_clients = Vec::new();

            for _i in 0..2 {
                let user_identity = MemoryIdentityProvider::new();
                let user_proxy =
                    Box::new(DefaultProxyClient::from_url(format!("ws://{addr}")));
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

                let _notif_drainer = tokio::task::spawn_local(async move {
                    while let Some(_notif) = notifications.recv().await {}
                });

                let credential_handler = tokio::task::spawn_local(async move {
                    loop {
                        match requests.recv().await {
                            Some(UserClientRequest::CredentialRequest {
                                query: _,
                                identity: _,
                                reply,
                            }) => {
                                reply
                                    .send(CredentialRequestReply {
                                        approved: true,
                                        credential: Some(test_credential()),
                                        credential_id: None,
                                    })
                                    .expect("Should send response");
                                break;
                            }
                            Some(_) => continue,
                            None => break,
                        }
                    }
                });

                psk_tokens.push(psk_token);
                credential_handlers.push(credential_handler);
                _user_clients.push(user_client);
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
        })
        .await;
}
