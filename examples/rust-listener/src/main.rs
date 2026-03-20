//! Minimal UserClient (listener) example.
//!
//! Connects to a proxy, generates a PSK token, and serves hardcoded
//! credentials to any remote client that connects.
//!
//! # Usage
//!
//! ```bash
//! cargo run -p rust-listener-example
//! ```
//!
//! Copy the printed PSK token and pass it to a RemoteClient (e.g. rust-remote-example).
//! Set `PROXY_URL` to override the default proxy address (ws://127.0.0.1:8080).

use ap_client::{
    CredentialData, CredentialRequestReply, DefaultProxyClient, FingerprintVerificationReply,
    MemoryIdentityProvider, MemorySessionStore, UserClient, UserClientRequest,
};

const DEFAULT_PROXY_URL: &str = "ws://127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let proxy_url =
        std::env::var("PROXY_URL").unwrap_or_else(|_| DEFAULT_PROXY_URL.to_string());

    // Ephemeral identity and session store (not persisted)
    let identity = Box::new(MemoryIdentityProvider::new());
    let session_store = Box::new(MemorySessionStore::new());
    let proxy_client = Box::new(DefaultProxyClient::from_url(proxy_url));

    // Connect to the proxy and start listening
    let handle = UserClient::connect(identity, session_store, proxy_client, None).await?;
    let client = handle.client;
    let mut requests = handle.requests;

    // Generate a PSK token for pairing
    let token = client.get_psk_token(None).await?;
    eprintln!("Listening. Share this PSK token with the remote client:");
    println!("{token}");

    // Serve incoming requests
    while let Some(request) = requests.recv().await {
        match request {
            UserClientRequest::VerifyFingerprint { fingerprint, reply, .. } => {
                eprintln!("Fingerprint verification requested: {fingerprint}");
                let _ = reply.send(FingerprintVerificationReply {
                    approved: true,
                    name: None,
                });
            }
            UserClientRequest::CredentialRequest { query, reply, .. } => {
                eprintln!("Credential requested: {query}");

                // Return a hardcoded credential — replace with real lookup logic
                let _ = reply.send(CredentialRequestReply {
                    approved: true,
                    credential: Some(CredentialData {
                        username: Some("user@example.com".to_string()),
                        password: Some("hunter2".to_string()),
                        totp: None,
                        uri: Some(query.search_string().to_string()),
                        notes: None,
                        credential_id: None,
                        domain: Some(query.search_string().to_string()),
                    }),
                    credential_id: None,
                });
                eprintln!("Credential sent");
            }
        }
    }

    Ok(())
}
