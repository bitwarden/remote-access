use crate::{
    auth::{Challenge, IdentityFingerprint},
    connection::AuthenticatedConnection,
    error::ProxyError,
    messages::Messages,
    rendevouz::RendevouzCode,
    server::proxy_server::{BufferedMessage, MESSAGE_BUFFER_TTL, ServerState},
};
use futures_util::{SinkExt, StreamExt};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Instant, SystemTime};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

pub struct ConnectionHandler {
    conn_id: u64,
    state: Arc<ServerState>,
    ws_stream: WebSocketStream<TcpStream>,
}

impl ConnectionHandler {
    pub fn new(
        conn_id: u64,
        state: Arc<ServerState>,
        ws_stream: WebSocketStream<TcpStream>,
    ) -> Self {
        Self {
            conn_id,
            state,
            ws_stream,
        }
    }

    pub async fn handle(self) -> Result<(), ProxyError> {
        let conn_id = self.conn_id;
        let state = self.state;

        let (mut ws_write, mut ws_read) = self.ws_stream.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

        let write_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = ws_write.send(msg).await {
                    tracing::error!("Failed to send message: {}", e);
                    break;
                }
            }
        });

        let challenge = Challenge::new();
        let challenge_msg = serde_json::to_string(&Messages::AuthChallenge(challenge.clone()))?;
        if tx.send(Message::Text(challenge_msg)).is_err() {
            return Err(ProxyError::ConnectionClosed);
        }

        tracing::debug!("Connection #{}: Sent auth challenge", conn_id);

        // Wait for auth response
        let auth_response = match ws_read.next().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(_)) => {
                return Err(ProxyError::InvalidMessage(
                    "Expected text message for auth".to_string(),
                ));
            }
            Some(Err(e)) => return Err(e.into()),
            None => return Err(ProxyError::ConnectionClosed),
        };

        let (identity, fingerprint) = match serde_json::from_str::<Messages>(&auth_response)? {
            Messages::AuthResponse(identity, response) => {
                if !response.verify(&challenge, &identity) {
                    return Err(ProxyError::AuthenticationFailed(
                        "Invalid signature".to_string(),
                    ));
                }
                let fingerprint = identity.fingerprint();
                tracing::info!(
                    "Connection #{}: Authenticated as {:?}",
                    conn_id,
                    fingerprint
                );
                (identity, fingerprint)
            }
            _ => {
                return Err(ProxyError::AuthenticationFailed(
                    "Expected AuthResponse".to_string(),
                ));
            }
        };

        let authenticated_conn = Arc::new(AuthenticatedConnection {
            conn_id,
            fingerprint,
            identity,
            tx: tx.clone(),
            connected_at: SystemTime::now(),
        });

        {
            let mut connections = state.connections.write().await;
            connections
                .entry(fingerprint)
                .or_insert_with(Vec::new)
                .push(Arc::clone(&authenticated_conn));
        }

        tracing::info!("Connection #{}: Added to connection map", conn_id);

        // Deliver any buffered messages for this client
        {
            let mut buffer = state.message_buffer.write().await;
            if let Some(queue) = buffer.remove(&fingerprint) {
                let now = Instant::now();
                let mut delivered = 0u64;
                for buffered in queue {
                    if now.duration_since(buffered.buffered_at) < MESSAGE_BUFFER_TTL {
                        let _ = tx.send(Message::Text(buffered.message));
                        delivered += 1;
                    }
                }
                if delivered > 0 {
                    tracing::info!(
                        "Connection #{}: Delivered {} buffered message(s)",
                        conn_id,
                        delivered
                    );
                }
            }
        }

        let result =
            Self::handle_authenticated_messages(&state, &mut ws_read, fingerprint, conn_id).await;

        {
            let mut connections = state.connections.write().await;
            if let Some(conns) = connections.get_mut(&fingerprint) {
                conns.retain(|c| c.conn_id != conn_id);
                if conns.is_empty() {
                    connections.remove(&fingerprint);
                }
            }
        }

        tracing::info!("Connection #{}: Removed from connection map", conn_id);

        drop(tx);
        let _ = write_task.await;

        result
    }

    async fn handle_authenticated_messages(
        state: &Arc<ServerState>,
        ws_read: &mut futures_util::stream::SplitStream<WebSocketStream<TcpStream>>,
        fingerprint: IdentityFingerprint,
        conn_id: u64,
    ) -> Result<(), ProxyError> {
        while let Some(msg_result) = ws_read.next().await {
            let msg = match msg_result {
                Ok(Message::Text(text)) => text,
                Ok(Message::Close(_)) => {
                    tracing::info!("Connection #{}: Client closed connection", conn_id);
                    return Ok(());
                }
                Ok(_) => continue,
                Err(e) => return Err(e.into()),
            };

            let parsed_msg: Messages = match serde_json::from_str(&msg) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Connection #{}: Failed to parse message: {}", conn_id, e);
                    continue;
                }
            };

            match parsed_msg {
                Messages::AuthChallenge(_) | Messages::AuthResponse(_, _) => {
                    tracing::warn!(
                        "Connection #{}: Received auth message after authentication",
                        conn_id
                    );
                }
                Messages::GetRendevouz => {
                    let code = RendevouzCode::new();
                    tracing::info!(
                        "Connection #{}: Generated rendezvous code: {}",
                        conn_id,
                        code.as_str()
                    );

                    // Store mapping in rendezvous_map
                    {
                        use crate::server::proxy_server::RendevouzEntry;
                        let entry = RendevouzEntry {
                            fingerprint,
                            created_at: SystemTime::now(),
                            used: false,
                        };
                        state
                            .rendezvous_map
                            .write()
                            .await
                            .insert(code.as_str().to_string(), entry);
                    }

                    let response = serde_json::to_string(&Messages::RendevouzInfo(code))?;
                    let connections = state.connections.read().await;
                    if let Some(conns) = connections.get(&fingerprint) {
                        for conn in conns.iter() {
                            let _ = conn.tx.send(Message::Text(response.clone()));
                        }
                    }
                }
                Messages::Send {
                    source: _,
                    destination,
                    payload,
                } => {
                    // Use authenticated fingerprint as source (client doesn't provide it)
                    let source = fingerprint;

                    // Route message to all connections with destination fingerprint
                    let dest_conns = {
                        let connections = state.connections.read().await;
                        connections.get(&destination).cloned()
                    };

                    match dest_conns {
                        Some(conns) if !conns.is_empty() => {
                            let forward_msg = serde_json::to_string(&Messages::Send {
                                source: Some(source),
                                destination,
                                payload,
                            })?;
                            for conn in conns.iter() {
                                if conn.tx.send(Message::Text(forward_msg.clone())).is_err() {
                                    tracing::error!(
                                        "Connection #{}: Failed to deliver to conn #{}",
                                        conn_id,
                                        conn.conn_id
                                    );
                                }
                            }
                            tracing::debug!(
                                "Connection #{}: Broadcast message from {:?} to {:?} ({} recipients)",
                                conn_id,
                                source,
                                destination,
                                conns.len()
                            );
                        }
                        _ => {
                            let max = state.config.max_buffered_messages_per_destination;
                            if max == 0 {
                                tracing::warn!(
                                    "Connection #{}: Destination not found (buffering disabled): {:?}",
                                    conn_id,
                                    destination
                                );
                            } else {
                                let forward_msg = serde_json::to_string(&Messages::Send {
                                    source: Some(source),
                                    destination,
                                    payload,
                                })?;
                                let mut buffer = state.message_buffer.write().await;
                                let queue = buffer.entry(destination).or_insert_with(VecDeque::new);
                                queue.push_back(BufferedMessage {
                                    message: forward_msg,
                                    buffered_at: Instant::now(),
                                });
                                if queue.len() > max {
                                    queue.pop_front();
                                }
                                tracing::debug!(
                                    "Connection #{}: Buffered message for offline destination {:?} ({} buffered)",
                                    conn_id,
                                    destination,
                                    queue.len()
                                );
                            }
                        }
                    }
                }
                Messages::RendevouzInfo(_) => {
                    tracing::warn!(
                        "Connection #{}: Received RendevouzInfo (server-only message)",
                        conn_id
                    );
                }
                Messages::IdentityInfo { .. } => {
                    tracing::warn!(
                        "Connection #{}: Received IdentityInfo (server-only message)",
                        conn_id
                    );
                }
                Messages::GetIdentity(code) => {
                    // Lookup and validate rendezvous code
                    let target_fingerprint = {
                        let mut rendezvous_map = state.rendezvous_map.write().await;

                        match rendezvous_map.get_mut(code.as_str()) {
                            Some(entry) => {
                                // Check expiration (5 minutes)
                                let elapsed = SystemTime::now()
                                    .duration_since(entry.created_at)
                                    .unwrap_or_default();

                                if elapsed.as_secs() > 300 {
                                    tracing::warn!(
                                        "Connection #{}: Rendezvous code expired: {}",
                                        conn_id,
                                        code.as_str()
                                    );
                                    rendezvous_map.remove(code.as_str());
                                    None
                                } else if entry.used {
                                    tracing::warn!(
                                        "Connection #{}: Rendezvous code already used: {}",
                                        conn_id,
                                        code.as_str()
                                    );
                                    None
                                } else {
                                    // Mark as used
                                    entry.used = true;
                                    Some(entry.fingerprint)
                                }
                            }
                            None => {
                                tracing::warn!(
                                    "Connection #{}: Unknown rendezvous code: {}",
                                    conn_id,
                                    code.as_str()
                                );
                                None
                            }
                        }
                    };

                    // Lookup target connection and send IdentityInfo
                    if let Some(target_fp) = target_fingerprint {
                        let connections = state.connections.read().await;
                        if let Some(target_conns) = connections.get(&target_fp) {
                            // Use the first connection's identity (all connections with same fingerprint have same identity)
                            if let Some(target_conn) = target_conns.first() {
                                let response_msg = Messages::IdentityInfo {
                                    fingerprint: target_fp,
                                    identity: target_conn.identity.clone(),
                                };
                                let response = serde_json::to_string(&response_msg)?;

                                // Send to all requester connections
                                if let Some(requester_conns) = connections.get(&fingerprint) {
                                    for requester_conn in requester_conns.iter() {
                                        if requester_conn
                                            .tx
                                            .send(Message::Text(response.clone()))
                                            .is_err()
                                        {
                                            tracing::error!(
                                                "Connection #{}: Failed to send IdentityInfo response to conn #{}",
                                                conn_id,
                                                requester_conn.conn_id
                                            );
                                        }
                                    }
                                }
                            }
                        } else {
                            tracing::warn!(
                                "Connection #{}: Target disconnected for rendezvous code: {}",
                                conn_id,
                                code.as_str()
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
