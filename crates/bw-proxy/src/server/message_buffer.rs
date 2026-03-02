use crate::auth::IdentityFingerprint;
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Trait abstraction for offline message buffering.
///
/// Implementations handle their own synchronization — callers store
/// `Arc<dyn MessageBuffer>` without an outer lock.
#[async_trait]
pub trait MessageBuffer: Send + Sync {
    /// Buffer a message for an offline destination.
    /// Returns `true` if accepted, `false` if rejected (disabled, capacity full).
    async fn buffer_message(&self, destination: IdentityFingerprint, message: String) -> bool;

    /// Drain and return all non-expired messages for a destination.
    async fn retrieve_messages(&self, destination: &IdentityFingerprint) -> Vec<String>;

    /// Remove expired entries. Can be a no-op for backends with native TTL.
    async fn cleanup(&self);
}

/// Configuration for [`InMemoryMessageBuffer`].
pub struct InMemoryMessageBufferConfig {
    /// Maximum messages buffered per destination. Set to 0 to disable buffering.
    pub max_messages_per_destination: usize,
    /// Maximum distinct destinations to buffer for.
    pub max_destinations: usize,
    /// Time-to-live for buffered messages.
    pub message_ttl: Duration,
}

impl Default for InMemoryMessageBufferConfig {
    fn default() -> Self {
        Self {
            max_messages_per_destination: 5,
            max_destinations: 1000,
            message_ttl: Duration::from_secs(600),
        }
    }
}

struct BufferedMessage {
    message: String,
    buffered_at: Instant,
}

impl BufferedMessage {
    fn is_expired(&self, ttl: Duration) -> bool {
        self.buffered_at.elapsed() >= ttl
    }
}

/// In-memory implementation of [`MessageBuffer`] backed by a `HashMap` + `VecDeque`.
pub struct InMemoryMessageBuffer {
    buffer: RwLock<HashMap<IdentityFingerprint, VecDeque<BufferedMessage>>>,
    config: InMemoryMessageBufferConfig,
}

impl InMemoryMessageBuffer {
    pub fn new(config: InMemoryMessageBufferConfig) -> Self {
        Self {
            buffer: RwLock::new(HashMap::new()),
            config,
        }
    }
}

#[async_trait]
impl MessageBuffer for InMemoryMessageBuffer {
    async fn buffer_message(&self, destination: IdentityFingerprint, message: String) -> bool {
        if self.config.max_messages_per_destination == 0 {
            return false;
        }

        let mut buffer = self.buffer.write().await;
        let is_new = !buffer.contains_key(&destination);
        if is_new && buffer.len() >= self.config.max_destinations {
            return false;
        }

        let queue = buffer.entry(destination).or_default();
        queue.push_back(BufferedMessage {
            message,
            buffered_at: Instant::now(),
        });
        if queue.len() > self.config.max_messages_per_destination {
            queue.pop_front();
        }
        true
    }

    async fn retrieve_messages(&self, destination: &IdentityFingerprint) -> Vec<String> {
        let mut buffer = self.buffer.write().await;
        let Some(queue) = buffer.remove(destination) else {
            return Vec::new();
        };
        queue
            .into_iter()
            .filter(|msg| !msg.is_expired(self.config.message_ttl))
            .map(|msg| msg.message)
            .collect()
    }

    async fn cleanup(&self) {
        let mut buffer = self.buffer.write().await;
        buffer.retain(|fingerprint, queue| {
            queue.retain(|msg| !msg.is_expired(self.config.message_ttl));
            if queue.is_empty() {
                tracing::debug!("Cleaned up empty message buffer for {:?}", fingerprint);
                false
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fingerprint(byte: u8) -> IdentityFingerprint {
        IdentityFingerprint([byte; 32])
    }

    #[tokio::test]
    async fn test_buffer_and_retrieve() {
        let buf = InMemoryMessageBuffer::new(InMemoryMessageBufferConfig::default());
        let fp = test_fingerprint(1);

        assert!(buf.buffer_message(fp, "msg1".into()).await);
        assert!(buf.buffer_message(fp, "msg2".into()).await);

        let msgs = buf.retrieve_messages(&fp).await;
        assert_eq!(msgs, vec!["msg1", "msg2"]);

        // Second retrieve returns empty (drained)
        let msgs = buf.retrieve_messages(&fp).await;
        assert!(msgs.is_empty());
    }

    #[tokio::test]
    async fn test_eviction_when_over_capacity() {
        let buf = InMemoryMessageBuffer::new(InMemoryMessageBufferConfig {
            max_messages_per_destination: 2,
            ..Default::default()
        });
        let fp = test_fingerprint(1);

        buf.buffer_message(fp, "a".into()).await;
        buf.buffer_message(fp, "b".into()).await;
        buf.buffer_message(fp, "c".into()).await;

        let msgs = buf.retrieve_messages(&fp).await;
        assert_eq!(msgs, vec!["b", "c"]);
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        let buf = InMemoryMessageBuffer::new(InMemoryMessageBufferConfig {
            message_ttl: Duration::from_millis(50),
            ..Default::default()
        });
        let fp = test_fingerprint(1);

        buf.buffer_message(fp, "old".into()).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        buf.buffer_message(fp, "new".into()).await;

        let msgs = buf.retrieve_messages(&fp).await;
        assert_eq!(msgs, vec!["new"]);
    }

    #[tokio::test]
    async fn test_destination_cap() {
        let buf = InMemoryMessageBuffer::new(InMemoryMessageBufferConfig {
            max_destinations: 2,
            ..Default::default()
        });

        assert!(buf.buffer_message(test_fingerprint(1), "a".into()).await);
        assert!(buf.buffer_message(test_fingerprint(2), "b".into()).await);
        // Third distinct destination is rejected
        assert!(!buf.buffer_message(test_fingerprint(3), "c".into()).await);
        // Existing destination still works
        assert!(buf.buffer_message(test_fingerprint(1), "d".into()).await);
    }

    #[tokio::test]
    async fn test_disabled_mode() {
        let buf = InMemoryMessageBuffer::new(InMemoryMessageBufferConfig {
            max_messages_per_destination: 0,
            ..Default::default()
        });
        let fp = test_fingerprint(1);

        assert!(!buf.buffer_message(fp, "msg".into()).await);
        let msgs = buf.retrieve_messages(&fp).await;
        assert!(msgs.is_empty());
    }

    #[tokio::test]
    async fn test_cleanup_removes_expired() {
        let buf = InMemoryMessageBuffer::new(InMemoryMessageBufferConfig {
            message_ttl: Duration::from_millis(50),
            ..Default::default()
        });

        buf.buffer_message(test_fingerprint(1), "old".into()).await;
        tokio::time::sleep(Duration::from_millis(60)).await;

        buf.cleanup().await;

        let msgs = buf.retrieve_messages(&test_fingerprint(1)).await;
        assert!(msgs.is_empty());
    }
}
