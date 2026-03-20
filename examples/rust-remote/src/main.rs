//! Minimal RemoteClient example.
//!
//! Connects to a proxy, pairs using a token (rendezvous code or PSK),
//! requests a credential, and prints it.
//!
//! # Usage
//!
//! ```bash
//! # Rendezvous code (from a listening aac/UserClient):
//! cargo run -p rust-remote-example -- ABC-DEF-GHI example.com
//!
//! # PSK token:
//! cargo run -p rust-remote-example -- <psk_token> example.com
//! ```
//!
//! Set `PROXY_URL` to override the default proxy address (ws://127.0.0.1:8080).

use ap_client::{
    CredentialQuery, DefaultProxyClient, MemoryIdentityProvider, MemorySessionStore, PskToken,
    RemoteClient,
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

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <token> <domain>", args[0]);
        eprintln!("  token  — rendezvous code (e.g. ABC-DEF-GHI) or PSK token");
        eprintln!("  domain — domain to request credentials for (e.g. example.com)");
        std::process::exit(1);
    }
    let token = &args[1];
    let domain = &args[2];

    let proxy_url =
        std::env::var("PROXY_URL").unwrap_or_else(|_| DEFAULT_PROXY_URL.to_string());

    // Ephemeral identity and session store (not persisted)
    let identity = Box::new(MemoryIdentityProvider::new());
    let session_store = Box::new(MemorySessionStore::new());
    let proxy_client = Box::new(DefaultProxyClient::from_url(proxy_url));

    // Connect to the proxy
    let handle = RemoteClient::connect(identity, session_store, proxy_client).await?;
    let client = handle.client;

    // Pair: PSK or rendezvous
    if PskToken::looks_like_psk_token(token) {
        let parsed = PskToken::parse(token)?;
        let (psk, fingerprint) = parsed.into_parts();
        client.pair_with_psk(psk, fingerprint).await?;
        eprintln!("Paired via PSK");
    } else {
        let _fp = client
            .pair_with_handshake(token.clone(), false)
            .await?;
        eprintln!("Paired via rendezvous (no fingerprint verification)");
    }

    // Request credential
    let query = CredentialQuery::Domain(domain.to_string());
    let credential = client.request_credential(&query).await?;

    // Print result
    if let Some(username) = &credential.username {
        println!("username: {username}");
    }
    if let Some(password) = &credential.password {
        println!("password: {password}");
    }
    if let Some(totp) = &credential.totp {
        println!("totp: {totp}");
    }
    if let Some(uri) = &credential.uri {
        println!("uri: {uri}");
    }
    if let Some(notes) = &credential.notes {
        println!("notes: {notes}");
    }
    if let Some(domain) = &credential.domain {
        println!("domain: {domain}");
    }
    if let Some(credential_id) = &credential.credential_id {
        println!("credential_id: {credential_id}");
    }

    Ok(())
}
