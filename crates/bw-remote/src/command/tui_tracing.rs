//! Custom tracing layer that routes log events into the TUI message panel.
//!
//! Instead of writing to stderr (which corrupts the ratatui alternate screen),
//! this layer sends structured log entries through an mpsc channel so they can
//! be rendered inside the TUI.

use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use super::tui::{App, MessageKind};

/// Receiver half of the TUI log channel.
pub type LogReceiver = mpsc::UnboundedReceiver<TuiLogEntry>;

/// A single log entry destined for the TUI message panel.
pub struct TuiLogEntry {
    pub level: Level,
    pub message: String,
    /// Last segment of the tracing target (e.g. `"remote_client"` from
    /// `"bw_rat_client::clients::remote_client"`).
    pub short_target: String,
}

/// A [`tracing_subscriber::Layer`] that forwards log events to a channel.
pub struct TuiLayer {
    tx: mpsc::UnboundedSender<TuiLogEntry>,
}

impl TuiLayer {
    /// Create a new TUI layer and the receiver that the TUI event loop should poll.
    pub fn new() -> (Self, LogReceiver) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }
}

/// Visitor that extracts the `message` field from a tracing event.
struct MessageVisitor {
    message: String,
}

impl MessageVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
        }
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write;
            self.message.clear();
            let _ = write!(self.message, "{value:?}");
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
    }
}

impl<S: Subscriber> Layer<S> for TuiLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::new();
        event.record(&mut visitor);

        let target = event.metadata().target();
        let short_target = target.rsplit("::").next().unwrap_or(target).to_string();

        let entry = TuiLogEntry {
            level: *event.metadata().level(),
            message: visitor.message,
            short_target,
        };

        // Best-effort send — if the receiver is gone, just drop the entry.
        let _ = self.tx.send(entry);
    }
}

/// Push a [`TuiLogEntry`] into the TUI message panel with appropriate styling.
pub fn push_log_entry(app: &mut App, entry: TuiLogEntry) {
    let kind = match entry.level {
        Level::ERROR | Level::WARN => MessageKind::Error,
        _ => MessageKind::Info,
    };
    app.push_msg(kind, format!("[{}] {}", entry.short_target, entry.message));
}
