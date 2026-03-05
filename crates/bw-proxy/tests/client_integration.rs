use bw_proxy::server::ProxyServer;
use bw_proxy_client::{IdentityKeyPair, IncomingMessage, ProxyClientConfig, ProxyProtocolClient};
use std::net::SocketAddr;

async fn start_test_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind to localhost");
    let addr = listener.local_addr().expect("should get local address");
    drop(listener);

    let server = ProxyServer::new(addr);
    tokio::spawn(async move { server.run().await.ok() });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    addr
}

#[tokio::test]
async fn test_client_connect_and_authenticate() {
    let addr = start_test_server().await;

    let config = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: None, // Generate new identity
    };

    let mut client = ProxyProtocolClient::new(config);
    let _incoming = client.connect().await.expect("should connect");

    assert!(client.is_authenticated().await);

    // Verify fingerprint is set
    let fingerprint = client.fingerprint();
    assert_ne!(fingerprint.0, [0u8; 32]);

    client.disconnect().await.expect("should disconnect");
}

#[tokio::test]
async fn test_two_clients_messaging() {
    let addr = start_test_server().await;

    // Create two clients
    let config_a = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: None,
    };
    let config_b = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: None,
    };

    let mut client_a = ProxyProtocolClient::new(config_a);
    let mut client_b = ProxyProtocolClient::new(config_b);

    let mut incoming_a = client_a.connect().await.expect("client A should connect");
    let mut incoming_b = client_b.connect().await.expect("client B should connect");

    let fingerprint_a = client_a.fingerprint();
    let fingerprint_b = client_b.fingerprint();

    // A sends to B
    let payload = b"Hello from A".to_vec();
    client_a
        .send_to(fingerprint_b, payload.clone())
        .await
        .expect("client A should send message");

    // B receives message
    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        let msg = incoming_b
            .recv()
            .await
            .expect("client B should receive message");
        match msg {
            IncomingMessage::Send {
                source,
                payload: recv_payload,
                ..
            } => {
                assert_eq!(source, fingerprint_a);
                assert_eq!(recv_payload, payload);
            }
            _ => panic!("Expected Send message"),
        }
    })
    .await
    .expect("receive should not timeout");

    // B sends to A
    let payload_b = b"Hello from B".to_vec();
    client_b
        .send_to(fingerprint_a, payload_b.clone())
        .await
        .expect("client B should send message");

    // A receives message
    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        let msg = incoming_a
            .recv()
            .await
            .expect("client A should receive message");
        match msg {
            IncomingMessage::Send {
                source,
                payload: recv_payload,
                ..
            } => {
                assert_eq!(source, fingerprint_b);
                assert_eq!(recv_payload, payload_b);
            }
            _ => panic!("Expected Send message"),
        }
    })
    .await
    .expect("receive should not timeout");

    client_a
        .disconnect()
        .await
        .expect("client A should disconnect");
    client_b
        .disconnect()
        .await
        .expect("client B should disconnect");
}

#[tokio::test]
async fn test_rendezvous_request() {
    let addr = start_test_server().await;

    let config = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: None,
    };

    let mut client = ProxyProtocolClient::new(config);
    let mut incoming = client.connect().await.expect("should connect");

    // Request rendezvous code
    client.request_rendezvous().await.ok(); // Sends GetRendevouz

    // Receive RendevouzInfo through incoming channel
    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        let msg = incoming
            .recv()
            .await
            .expect("should receive rendezvous info");
        match msg {
            IncomingMessage::RendevouzInfo(code) => {
                assert_eq!(code.as_str().len(), 7); // Format is "ABC-DEF" (7 chars)
            }
            _ => panic!("Expected RendevouzInfo"),
        }
    })
    .await
    .expect("receive should not timeout");

    client.disconnect().await.expect("should disconnect");
}

#[tokio::test]
async fn test_disconnect_cleanup() {
    let addr = start_test_server().await;

    let config = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: None,
    };

    let mut client = ProxyProtocolClient::new(config);
    client.connect().await.expect("should connect");

    assert!(client.is_authenticated().await);

    client.disconnect().await.expect("should disconnect");

    assert!(!client.is_authenticated().await);
}

#[tokio::test]
async fn test_multiple_messages() {
    let addr = start_test_server().await;

    let config_a = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: None,
    };
    let config_b = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: None,
    };

    let mut client_a = ProxyProtocolClient::new(config_a);
    let mut client_b = ProxyProtocolClient::new(config_b);

    let _incoming_a = client_a.connect().await.expect("client A should connect");
    let mut incoming_b = client_b.connect().await.expect("client B should connect");

    let fingerprint_a = client_a.fingerprint();
    let fingerprint_b = client_b.fingerprint();

    // Send multiple messages from A to B
    for i in 0..5 {
        let payload = format!("Message {i}").into_bytes();
        client_a
            .send_to(fingerprint_b, payload.clone())
            .await
            .expect("client A should send message");

        // B receives message
        tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
            let msg = incoming_b
                .recv()
                .await
                .expect("client B should receive message");
            match msg {
                IncomingMessage::Send {
                    source,
                    payload: recv_payload,
                    ..
                } => {
                    assert_eq!(source, fingerprint_a);
                    assert_eq!(recv_payload, payload);
                }
                _ => panic!("Expected Send message"),
            }
        })
        .await
        .expect("receive should not timeout");
    }

    client_a
        .disconnect()
        .await
        .expect("client A should disconnect");
    client_b
        .disconnect()
        .await
        .expect("client B should disconnect");
}

#[tokio::test]
async fn test_multiple_clients_same_identity_can_connect() {
    let addr = start_test_server().await;

    // Create a shared identity keypair
    let shared_keypair = IdentityKeyPair::generate();
    let cose_bytes = shared_keypair.to_cose();

    // Create two clients with the same identity
    let config_a = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: Some(IdentityKeyPair::from_cose(&cose_bytes).unwrap()),
    };
    let config_b = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: Some(IdentityKeyPair::from_cose(&cose_bytes).unwrap()),
    };

    let mut client_a = ProxyProtocolClient::new(config_a);
    let mut client_b = ProxyProtocolClient::new(config_b);

    let _incoming_a = client_a.connect().await.expect("client A should connect");
    let _incoming_b = client_b.connect().await.expect("client B should connect");

    // Both should be authenticated
    assert!(client_a.is_authenticated().await);
    assert!(client_b.is_authenticated().await);

    // Both should have the same fingerprint
    let fingerprint_a = client_a.fingerprint();
    let fingerprint_b = client_b.fingerprint();
    assert_eq!(fingerprint_a, fingerprint_b);

    client_a
        .disconnect()
        .await
        .expect("client A should disconnect");
    client_b
        .disconnect()
        .await
        .expect("client B should disconnect");
}

#[tokio::test]
async fn test_messages_broadcast_to_all_same_identity_connections() {
    let addr = start_test_server().await;

    // Create a shared identity keypair for the user
    let user_keypair = IdentityKeyPair::generate();
    let user_cose = user_keypair.to_cose();

    // Create two user clients with the same identity
    let config_user_a = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: Some(IdentityKeyPair::from_cose(&user_cose).unwrap()),
    };
    let config_user_b = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: Some(IdentityKeyPair::from_cose(&user_cose).unwrap()),
    };

    // Create a sender with different identity
    let config_sender = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: None,
    };

    let mut user_client_a = ProxyProtocolClient::new(config_user_a);
    let mut user_client_b = ProxyProtocolClient::new(config_user_b);
    let mut sender_client = ProxyProtocolClient::new(config_sender);

    let mut incoming_user_a = user_client_a
        .connect()
        .await
        .expect("user A should connect");
    let mut incoming_user_b = user_client_b
        .connect()
        .await
        .expect("user B should connect");
    let _incoming_sender = sender_client
        .connect()
        .await
        .expect("sender should connect");

    let user_fingerprint = user_client_a.fingerprint();

    // Sender sends message to user fingerprint
    let payload = b"Hello to all users".to_vec();
    sender_client
        .send_to(user_fingerprint, payload.clone())
        .await
        .expect("sender should send message");

    // Both user clients should receive the message
    let recv_a = tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        let msg = incoming_user_a
            .recv()
            .await
            .expect("user A should receive message");
        match msg {
            IncomingMessage::Send {
                source,
                payload: recv_payload,
                ..
            } => {
                assert_eq!(source, sender_client.fingerprint());
                assert_eq!(recv_payload, payload);
            }
            _ => panic!("Expected Send message"),
        }
    })
    .await;

    let recv_b = tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        let msg = incoming_user_b
            .recv()
            .await
            .expect("user B should receive message");
        match msg {
            IncomingMessage::Send {
                source,
                payload: recv_payload,
                ..
            } => {
                assert_eq!(source, sender_client.fingerprint());
                assert_eq!(recv_payload, payload);
            }
            _ => panic!("Expected Send message"),
        }
    })
    .await;

    recv_a.expect("user A receive should not timeout");
    recv_b.expect("user B receive should not timeout");

    user_client_a
        .disconnect()
        .await
        .expect("user A should disconnect");
    user_client_b
        .disconnect()
        .await
        .expect("user B should disconnect");
    sender_client
        .disconnect()
        .await
        .expect("sender should disconnect");
}

#[tokio::test]
async fn test_cleanup_when_one_connection_disconnects() {
    let addr = start_test_server().await;

    // Create a shared identity keypair for the user
    let user_keypair = IdentityKeyPair::generate();
    let user_cose = user_keypair.to_cose();

    // Create two user clients with the same identity
    let config_user_a = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: Some(IdentityKeyPair::from_cose(&user_cose).unwrap()),
    };
    let config_user_b = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: Some(IdentityKeyPair::from_cose(&user_cose).unwrap()),
    };

    // Create a sender with different identity
    let config_sender = ProxyClientConfig {
        proxy_url: format!("ws://{addr}"),
        identity_keypair: None,
    };

    let mut user_client_a = ProxyProtocolClient::new(config_user_a);
    let mut user_client_b = ProxyProtocolClient::new(config_user_b);
    let mut sender_client = ProxyProtocolClient::new(config_sender);

    let _incoming_user_a = user_client_a
        .connect()
        .await
        .expect("user A should connect");
    let mut incoming_user_b = user_client_b
        .connect()
        .await
        .expect("user B should connect");
    let _incoming_sender = sender_client
        .connect()
        .await
        .expect("sender should connect");

    let user_fingerprint = user_client_a.fingerprint();

    // Disconnect user A
    user_client_a
        .disconnect()
        .await
        .expect("user A should disconnect");

    // Give the server time to process the disconnection
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Sender sends message to user fingerprint
    let payload = b"Hello remaining user".to_vec();
    sender_client
        .send_to(user_fingerprint, payload.clone())
        .await
        .expect("sender should send message");

    // User B should still receive the message
    tokio::time::timeout(tokio::time::Duration::from_secs(1), async {
        let msg = incoming_user_b
            .recv()
            .await
            .expect("user B should receive message");
        match msg {
            IncomingMessage::Send {
                source,
                payload: recv_payload,
                ..
            } => {
                assert_eq!(source, sender_client.fingerprint());
                assert_eq!(recv_payload, payload);
            }
            _ => panic!("Expected Send message"),
        }
    })
    .await
    .expect("user B receive should not timeout");

    user_client_b
        .disconnect()
        .await
        .expect("user B should disconnect");
    sender_client
        .disconnect()
        .await
        .expect("sender should disconnect");
}
