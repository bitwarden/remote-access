//! Simple client example demonstrating basic proxy connection and rendezvous code request.
//!
//! This example shows:
//! - Creating a client with a new identity
//! - Connecting and authenticating to the proxy
//! - Handling incoming messages in a background task
//! - Requesting a rendezvous code
//! - Proper cleanup on disconnect
//!
//! # Running the Example
//!
//! First, start the proxy server:
//! ```bash
//! cargo run --bin bw-proxy
//! ```
//!
//! Then run this example:
//! ```bash
//! cargo run --example simple_client
//! ```
//!
//! You should see the client connect, authenticate, and receive a rendezvous code.

use bw_proxy::client::{IncomingMessage, ProxyClientConfig, ProxyProtocolClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging to see tracing output
    tracing_subscriber::fmt::init();

    // Step 1: Create client configuration
    // Setting identity_keypair to None generates a new random identity
    let config = ProxyClientConfig {
        proxy_url: "ws://localhost:8080".to_string(),
        identity_keypair: None, // Will generate new identity
    };

    // Step 2: Create the client
    // The client is created but not yet connected
    let mut client = ProxyProtocolClient::new(config);

    // Step 3: Connect and authenticate
    // This establishes the WebSocket connection and completes challenge-response auth
    // Returns a channel for receiving messages from the server
    let mut incoming = client.connect().await?;

    println!("Connected! Fingerprint: {:?}", client.fingerprint());

    // Step 4: Spawn a background task to handle incoming messages
    // This runs concurrently while we perform other operations
    tokio::spawn(async move {
        while let Some(msg) = incoming.recv().await {
            match msg {
                // Received a message from another client
                IncomingMessage::Send {
                    source, payload, ..
                } => {
                    println!(
                        "Message from {:?}: {}",
                        source,
                        String::from_utf8_lossy(&payload)
                    );
                }
                // Received our rendezvous code from the server
                IncomingMessage::RendevouzInfo(code) => {
                    println!("Rendezvous code: {}", code.as_str());
                    println!("Share this code with peers to let them find you!");
                    println!("Code expires in 5 minutes.");
                }
                // Received identity info after looking up a rendezvous code
                IncomingMessage::IdentityInfo { fingerprint, .. } => {
                    println!("Found peer with fingerprint: {:?}", fingerprint);
                    // You could now send messages to this peer using their fingerprint
                }
            }
        }
    });

    // Step 5: Request a rendezvous code
    // The server will generate a code and send it via IncomingMessage::RendevouzInfo
    client.request_rendezvous().await?;

    // Keep running for a short time to receive the rendezvous code
    println!("Client running... Press Ctrl+C to exit");
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Step 6: Clean disconnect
    // This closes the WebSocket connection and cleans up background tasks
    client.disconnect().await?;

    Ok(())
}
