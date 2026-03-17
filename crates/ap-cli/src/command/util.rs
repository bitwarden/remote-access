//! Shared utilities for CLI commands
//!
//! Contains helper functions used across multiple commands.

use std::time::{SystemTime, UNIX_EPOCH};

use ap_client::{RemoteClientEvent, UserClientEvent};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;

use super::tui::{Message, MessageKind};

/// Highlighted value style (bright cyan, bold) for fingerprints, codes, domains.
fn val_style() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

/// Dimmed label style for secondary text.
fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

/// Normal text style.
fn text() -> Style {
    Style::default().fg(Color::White)
}

/// Format a Unix timestamp as relative time (e.g., "2 hours ago", "3 days ago")
pub fn format_relative_time(timestamp: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let diff = now.saturating_sub(timestamp);

    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        let minutes = diff / 60;
        format!(
            "{} minute{} ago",
            minutes,
            if minutes == 1 { "" } else { "s" }
        )
    } else if diff < 86400 {
        let hours = diff / 3600;
        format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
    } else if diff < 604800 {
        let days = diff / 86400;
        format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
    } else if diff < 2592000 {
        let weeks = diff / 604800;
        format!("{} week{} ago", weeks, if weeks == 1 { "" } else { "s" })
    } else {
        let months = diff / 2592000;
        format!("{} month{} ago", months, if months == 1 { "" } else { "s" })
    }
}

/// Format a RemoteClientEvent as a styled `Message` for the TUI.
///
/// Returns `None` for events that should not produce output.
#[allow(clippy::string_slice)]
pub fn format_connect_event(event: &RemoteClientEvent) -> Option<Message> {
    match event {
        RemoteClientEvent::Connecting { proxy_url } => Some(Message::rich(
            MessageKind::Status,
            vec![
                Span::styled("Connecting to proxy: ", text()),
                Span::styled(proxy_url.clone(), val_style()),
            ],
        )),
        RemoteClientEvent::Connected { fingerprint } => {
            let fp_hex = hex::encode(fingerprint.0);
            Some(Message::rich(
                MessageKind::Success,
                vec![
                    Span::styled("Connected as device: ", text()),
                    Span::styled(
                        format!("{}...", &fp_hex[..16.min(fp_hex.len())]),
                        val_style(),
                    ),
                ],
            ))
        }
        RemoteClientEvent::ReconnectingToSession { fingerprint } => {
            let fp_hex = hex::encode(fingerprint.0);
            Some(Message::rich(
                MessageKind::Status,
                vec![
                    Span::styled("Reconnecting to session: ", text()),
                    Span::styled(fp_hex[..12.min(fp_hex.len())].to_string(), val_style()),
                ],
            ))
        }
        RemoteClientEvent::RendevouzResolving { code } => Some(Message::rich(
            MessageKind::Status,
            vec![
                Span::styled("Resolving rendezvous code: ", text()),
                Span::styled(code.clone(), val_style()),
            ],
        )),
        RemoteClientEvent::RendevouzResolved { fingerprint } => {
            let fp_hex = hex::encode(fingerprint.0);
            Some(Message::rich(
                MessageKind::Success,
                vec![
                    Span::styled("Resolved to fingerprint: ", text()),
                    Span::styled(fp_hex, val_style()),
                ],
            ))
        }
        RemoteClientEvent::PskMode { fingerprint } => {
            let fp_hex = hex::encode(fingerprint.0);
            Some(Message::rich(
                MessageKind::Status,
                vec![
                    Span::styled("Using PSK authentication to: ", text()),
                    Span::styled(fp_hex[..12.min(fp_hex.len())].to_string(), val_style()),
                ],
            ))
        }
        RemoteClientEvent::HandshakeStart => Some(Message::new(
            MessageKind::Status,
            "Starting secure channel handshake...",
        )),
        RemoteClientEvent::HandshakeProgress { message } => Some(Message::rich(
            MessageKind::Status,
            vec![
                Span::styled("Handshake: ", text()),
                Span::styled(message.clone(), dim()),
            ],
        )),
        RemoteClientEvent::HandshakeComplete => Some(Message::new(
            MessageKind::Success,
            "Secure channel established",
        )),
        RemoteClientEvent::Ready { .. } => None,
        RemoteClientEvent::CredentialRequestSent { query } => {
            let label = match query {
                ap_client::CredentialQuery::Domain(d) => d.clone(),
                ap_client::CredentialQuery::Id(id) => format!("id:{id}"),
                ap_client::CredentialQuery::Search(s) => format!("search:{s}"),
            };
            Some(Message::rich(
                MessageKind::Status,
                vec![
                    Span::styled("Requesting credential for: ", text()),
                    Span::styled(label, val_style()),
                    Span::styled("...", dim()),
                ],
            ))
        }
        RemoteClientEvent::CredentialReceived { credential } => Some(Message::rich(
            MessageKind::Success,
            vec![
                Span::styled("Credential received for: ", text()),
                Span::styled(
                    credential
                        .domain
                        .clone()
                        .unwrap_or_else(|| "unknown".into()),
                    val_style(),
                ),
            ],
        )),
        RemoteClientEvent::Error { message, context } => {
            let ctx = context.as_deref().unwrap_or("unknown");
            Some(Message::rich(
                MessageKind::Error,
                vec![
                    Span::styled(format!("Error ({ctx}): "), Style::default().fg(Color::Red)),
                    Span::styled(
                        message.clone(),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                ],
            ))
        }
        RemoteClientEvent::Disconnected { reason } => {
            let reason_str = reason.as_deref().unwrap_or("unknown");
            Some(Message::rich(
                MessageKind::Error,
                vec![
                    Span::styled("Disconnected: ", Style::default().fg(Color::Red)),
                    Span::styled(
                        reason_str.to_string(),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                ],
            ))
        }
        RemoteClientEvent::HandshakeFingerprint { fingerprint } => Some(Message::rich(
            MessageKind::Prompt,
            vec![
                Span::styled(
                    "HANDSHAKE FINGERPRINT: ",
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(fingerprint.clone(), val_style()),
                Span::styled(" — Compare with the trusted device", dim()),
            ],
        )),
        RemoteClientEvent::FingerprintVerified => Some(Message::new(
            MessageKind::Success,
            "Fingerprint verified successfully!",
        )),
        RemoteClientEvent::FingerprintRejected { reason } => Some(Message::rich(
            MessageKind::Error,
            vec![
                Span::styled("Fingerprint rejected: ", Style::default().fg(Color::Red)),
                Span::styled(
                    reason.clone(),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" — Connection aborted", dim()),
            ],
        )),
    }
}

/// Format a UserClientEvent as a styled `Message` for the TUI.
///
/// Returns `None` for events handled structurally by the caller
/// (e.g., `Listening`, `CredentialRequest`, `HandshakeFingerprint`).
#[allow(clippy::string_slice)]
pub fn format_listen_event(event: &UserClientEvent) -> Option<Message> {
    match event {
        UserClientEvent::Listening {} => None,

        UserClientEvent::RendevouzCodeGenerated { code } => Some(Message::rich(
            MessageKind::Prompt,
            vec![
                Span::styled(
                    "RENDEZVOUS CODE: ",
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(code.clone(), val_style()),
                Span::styled(" — Share this code with your remote device", dim()),
            ],
        )),

        UserClientEvent::PskTokenGenerated { token } => Some(Message::rich(
            MessageKind::Prompt,
            vec![
                Span::styled(
                    "PSK TOKEN: ",
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(token.clone(), val_style()),
                Span::styled(" — Share this token securely", dim()),
            ],
        )),

        UserClientEvent::HandshakeStart {} => {
            Some(Message::new(MessageKind::Status, "Noise handshake started"))
        }
        UserClientEvent::HandshakeProgress { message } => Some(Message::rich(
            MessageKind::Status,
            vec![
                Span::styled("Handshake: ", text()),
                Span::styled(message.clone(), dim()),
            ],
        )),
        UserClientEvent::HandshakeComplete {} => Some(Message::new(
            MessageKind::Success,
            "Secure channel established",
        )),

        UserClientEvent::HandshakeFingerprint { fingerprint, .. } => Some(Message::rich(
            MessageKind::Prompt,
            vec![
                Span::styled(
                    "SECURITY VERIFICATION — Fingerprint: ",
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(fingerprint.clone(), val_style()),
                Span::styled(" — Compare with remote device", dim()),
            ],
        )),

        UserClientEvent::FingerprintVerified {} => Some(Message::new(
            MessageKind::Success,
            "Fingerprint verified successfully!",
        )),
        UserClientEvent::FingerprintRejected { reason } => Some(Message::rich(
            MessageKind::Error,
            vec![
                Span::styled("Fingerprint rejected: ", Style::default().fg(Color::Red)),
                Span::styled(
                    reason.clone(),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" — Connection refused", dim()),
            ],
        )),

        UserClientEvent::CredentialRequest { query, .. } => Some(Message::rich(
            MessageKind::Prompt,
            vec![
                Span::styled("Credential request - ", text()),
                Span::styled(query.to_string(), val_style()),
            ],
        )),

        UserClientEvent::CredentialApproved { domain, .. } => Some(Message::rich(
            MessageKind::Success,
            vec![
                Span::styled("Credential approved: ", text()),
                Span::styled(
                    domain.clone().unwrap_or_else(|| "(unknown)".into()),
                    val_style(),
                ),
            ],
        )),
        UserClientEvent::CredentialDenied { domain, .. } => Some(Message::rich(
            MessageKind::Error,
            vec![
                Span::styled("Credential denied: ", Style::default().fg(Color::Red)),
                Span::styled(
                    domain.clone().unwrap_or_else(|| "(unknown)".into()),
                    val_style(),
                ),
            ],
        )),

        UserClientEvent::SessionRefreshed { fingerprint } => {
            let fp_hex = hex::encode(fingerprint.0);
            let short = &fp_hex[..12.min(fp_hex.len())];
            Some(Message::rich(
                MessageKind::Success,
                vec![
                    Span::styled(
                        "Known client re-paired and connected — transport keys refreshed: ",
                        text(),
                    ),
                    Span::styled(short.to_string(), val_style()),
                ],
            ))
        }

        UserClientEvent::ClientDisconnected {} => Some(Message::new(
            MessageKind::Warning,
            "Proxy connection lost — attempting to reconnect...",
        )),

        UserClientEvent::Reconnecting { attempt } => Some(Message::rich(
            MessageKind::Status,
            vec![
                Span::styled("Reconnecting to proxy (attempt ", dim()),
                Span::styled(
                    attempt.to_string(),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(")...", dim()),
            ],
        )),

        UserClientEvent::Reconnected {} => Some(Message::new(
            MessageKind::Success,
            "Reconnected to proxy server",
        )),

        UserClientEvent::Error { message, context } => {
            let ctx = context.as_deref().unwrap_or("unknown");
            Some(Message::rich(
                MessageKind::Error,
                vec![
                    Span::styled(format!("Error ({ctx}): "), Style::default().fg(Color::Red)),
                    Span::styled(
                        message.clone(),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                ],
            ))
        }
    }
}
