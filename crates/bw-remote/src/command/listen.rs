//! Listen command implementation
//!
//! Handles the user-client (trusted device) mode for receiving and
//! approving connection requests from remote clients.

use std::process::Command;

use bw_proxy::{IdentityFingerprint, ProxyClientConfig};
use bw_rat_client::{
    DefaultProxyClient, IdentityProvider, SessionStore, UserClient, UserClientEvent,
    UserClientResponse, UserCredentialData,
};
use clap::Args;
use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures_util::StreamExt;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::info;

use super::tui::{App, AppAction, Message, MessageKind, Mode, init_terminal, restore_terminal};
use super::util::{format_listen_event, format_relative_time};
use crate::storage::{FileIdentityStorage, FileSessionCache};

const DEFAULT_PROXY_URL: &str = "ws://localhost:8080";

/// Arguments for the listen command
#[derive(Args)]
pub struct ListenArgs {
    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL)]
    pub proxy_url: String,

    /// Use PSK (Pre-Shared Key) mode instead of rendezvous code
    #[arg(long)]
    pub psk: bool,
}

impl ListenArgs {
    /// Execute the listen command
    pub async fn run(self) -> Result<()> {
        run_user_client_session(self.proxy_url, self.psk).await
    }
}

/// Current phase of the listen command's interactive loop.
enum Phase {
    /// Waiting for events; showing the idle menu.
    Idle,
    /// Fingerprint verification pending.
    FingerprintConfirm,
    /// Credential approval pending.
    CredentialApproval {
        domain: String,
        request_id: String,
        session_id: String,
        credential: UserCredentialData,
    },
}

/// Whether the event loop exited normally or because `/new` was requested.
enum EventLoopExit {
    Quit,
    NewSession,
}

/// Bitwarden CLI login item structure
#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwUri>>,
}

/// Bitwarden CLI URI structure
#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}

/// Bitwarden CLI item structure
#[derive(Deserialize)]
struct BwItem {
    login: Option<BwLogin>,
}

/// Look up a credential from the Bitwarden CLI
fn lookup_credential(domain: &str) -> Option<UserCredentialData> {
    // Try to find bw on PATH first, then fall back to homebrew location
    let bw_path = which_bw().unwrap_or_else(|| "/opt/homebrew/bin/bw".to_string());

    let output = Command::new(&bw_path)
        .args(["get", "item", domain])
        .output()
        .ok()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("Not found") {
            info!("bw get item failed: {}", stderr);
        }
        return None;
    }

    let item: BwItem = serde_json::from_slice(&output.stdout).ok()?;
    let login = item.login?;

    // Get the first URI if available
    let uri = login
        .uris
        .as_ref()
        .and_then(|uris| uris.first())
        .and_then(|u| u.uri.clone());

    Some(UserCredentialData {
        username: login.username,
        password: login.password,
        totp: login.totp,
        uri,
        notes: None,
    })
}

/// Find bw executable on PATH
fn which_bw() -> Option<String> {
    Command::new("which")
        .arg("bw")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Result of checking the Bitwarden CLI status.
struct BwStatus {
    /// The account email from `bw status`, if available.
    user_email: Option<String>,
    /// Styled spans summarising the vault status (for the header).
    status_spans: Vec<Span<'static>>,
}

/// Check if the Bitwarden CLI is available and unlocked.
///
/// Returns a [`BwStatus`] with styled spans and optional account email.
fn check_bw_status() -> BwStatus {
    let bw_path = match which_bw() {
        Some(p) => p,
        None => {
            return BwStatus {
                user_email: None,
                status_spans: vec![
                    Span::styled("CLI ", Style::default().fg(Color::Red)),
                    Span::styled(
                        "not found",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                ],
            };
        }
    };

    let output = Command::new(&bw_path).args(["status"]).output();

    match output {
        Ok(o) if o.status.success() => {
            let json: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_default();
            let status = json["status"].as_str().unwrap_or("unknown");
            let user_email = json["userEmail"].as_str().map(String::from);

            let status_spans = match status {
                "unlocked" => vec![
                    Span::styled("Vault ", Style::default().fg(Color::Green)),
                    Span::styled(
                        "unlocked",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                ],
                "locked" => vec![
                    Span::styled("Vault ", Style::default().fg(Color::Red)),
                    Span::styled(
                        "locked",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" — run: bw unlock", Style::default().fg(Color::DarkGray)),
                ],
                _ => vec![
                    Span::styled("Vault ", Style::default().fg(Color::Red)),
                    Span::styled(
                        status.to_string(),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" — run: bw login", Style::default().fg(Color::DarkGray)),
                ],
            };

            BwStatus {
                user_email,
                status_spans,
            }
        }
        _ => BwStatus {
            user_email: None,
            status_spans: vec![
                Span::styled("CLI ", Style::default().fg(Color::Red)),
                Span::styled(
                    "error",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ],
        },
    }
}

type SessionInfo = (IdentityFingerprint, Option<String>, u64, u64);

/// Build session info messages for display in the TUI.
fn session_info_messages(sessions: &[SessionInfo], pending_label: Option<&str>) -> Vec<Message> {
    let mut sorted = sessions.to_vec();
    sorted.sort_by(|a, b| b.3.cmp(&a.3));

    let mut msgs = vec![Message::rich(
        MessageKind::Listening,
        vec![Span::styled(
            "Listening for incoming requests from:",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )],
    )];
    for (fingerprint, _, cached_at, last_connected_at) in &sorted {
        let short_hex = hex::encode(fingerprint.0)
            .chars()
            .take(12)
            .collect::<String>();
        let created = format_relative_time(*cached_at);
        let last_used = format_relative_time(*last_connected_at);
        msgs.push(Message::rich(
            MessageKind::Info,
            vec![
                Span::raw("  "),
                Span::styled(
                    short_hex,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  created {created}, last used {last_used}"),
                    Style::default().fg(Color::DarkGray),
                ),
            ],
        ));
    }
    if let Some(label) = pending_label {
        msgs.push(Message::new(MessageKind::Info, format!("  {label}")));
    }
    msgs
}

/// Set up the idle-mode footer for the TUI.
fn idle_footer() -> Line<'static> {
    Line::from(vec![
        Span::styled(" /new", Style::default().fg(Color::Cyan)),
        Span::raw(" create session  "),
        Span::styled("/exit", Style::default().fg(Color::Cyan)),
        Span::raw(" quit  "),
        Span::raw("| PageUp/PageDown to scroll"),
    ])
}

/// Run the interactive event+prompt loop using the ratatui TUI.
///
/// Handles events from `event_rx`, credential lookups, and user input
/// in a single `select!` loop. The `client_handle` is aborted on exit.
///
/// The TUI state (`app`, `term`, `reader`) is owned by the caller so that
/// it survives across `/new` session restarts without flickering.
async fn run_event_loop(
    app: &mut App,
    term: &mut ratatui::DefaultTerminal,
    reader: &mut EventStream,
    mut event_rx: mpsc::Receiver<UserClientEvent>,
    response_tx: mpsc::Sender<UserClientResponse>,
    sessions: &[SessionInfo],
    client_handle: tokio::task::JoinHandle<Result<(), bw_rat_client::RemoteClientError>>,
) -> Result<EventLoopExit> {
    let mut phase = Phase::Idle;

    // Seed session info panel for this iteration
    app.set_mode(Mode::TextInput);
    app.set_session_panel(session_info_messages(sessions, None));
    app.footer = idle_footer();
    app.commands = &["/new", "/exit"];

    let mut tick_interval = tokio::time::interval(std::time::Duration::from_millis(150));

    let exit = loop {
        term.draw(|frame| app.draw(frame))
            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;

        tokio::select! {
            _ = tick_interval.tick() => {
                app.tick();
                continue;
            }
            maybe_event = reader.next() => {
                if let Some(Ok(Event::Key(key))) = maybe_event {
                    if key.kind == KeyEventKind::Press {
                        if let Some(action) = app.handle_key(key) {
                            match (&phase, &action) {
                                // Idle commands
                                (Phase::Idle, AppAction::Submit(s)) if s == "/new" => {
                                    break EventLoopExit::NewSession;
                                }
                                (Phase::Idle, AppAction::Submit(s)) if s == "/exit" => {
                                    break EventLoopExit::Quit;
                                }

                                // Fingerprint confirmation
                                (Phase::FingerprintConfirm, AppAction::Confirmed(approved)) => {
                                    let approved = *approved;
                                    response_tx
                                        .send(UserClientResponse::VerifyFingerprint { approved })
                                        .await
                                        .ok();
                                    if approved {
                                        app.push_msg(MessageKind::Success, "Fingerprint approved");
                                    } else {
                                        app.push_msg(MessageKind::Error, "Fingerprint rejected");
                                    }
                                    phase = Phase::Idle;
                                    app.set_mode(Mode::TextInput);
                                    app.footer = idle_footer();
                                    app.commands = &["/new", "/exit"];
                                }

                                // Credential approval
                                (Phase::CredentialApproval { .. }, AppAction::Confirmed(approved)) => {
                                    let approved = *approved;
                                    let old_phase = std::mem::replace(&mut phase, Phase::Idle);
                                    if let Phase::CredentialApproval { domain, request_id, session_id, credential } = old_phase {
                                        if approved {
                                            response_tx
                                                .send(UserClientResponse::RespondCredential {
                                                    request_id,
                                                    session_id,
                                                    approved: true,
                                                    credential: Some(credential),
                                                })
                                                .await
                                                .ok();
                                            app.push_msg(MessageKind::Success, format!("Credential sent for {domain}"));
                                        } else {
                                            response_tx
                                                .send(UserClientResponse::RespondCredential {
                                                    request_id,
                                                    session_id,
                                                    approved: false,
                                                    credential: None,
                                                })
                                                .await
                                                .ok();
                                            app.push_msg(MessageKind::Error, format!("Credential denied for {domain}"));
                                        }
                                    }
                                    app.set_mode(Mode::TextInput);
                                    app.footer = idle_footer();
                                    app.commands = &["/new", "/exit"];
                                }

                                (_, AppAction::Quit) => break EventLoopExit::Quit,
                                _ => {}
                            }
                        }
                    }
                }
            }

            event = event_rx.recv() => {
                match event {
                    Some(event) => {
                        // Print the formatted event message
                        if let Some(msg) = format_listen_event(&event) {
                            app.push_rich(msg);
                        }

                        // Handle phase transitions
                        match event {
                            UserClientEvent::HandshakeFingerprint { .. } => {
                                phase = Phase::FingerprintConfirm;
                                app.commands = &[];
                                app.set_mode(Mode::Confirm {
                                    title: "Fingerprint Verification".to_string(),
                                    description: Line::from("Do the fingerprints match?"),
                                });
                                app.footer = Line::from(vec![
                                    Span::styled(
                                        " Compare fingerprints with remote device — ",
                                        Style::default().fg(Color::Yellow),
                                    ),
                                    Span::styled(
                                        "[y]",
                                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                                    ),
                                    Span::styled(" approve  ", Style::default().fg(Color::Yellow)),
                                    Span::styled(
                                        "[n]",
                                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                                    ),
                                    Span::styled(" reject", Style::default().fg(Color::Yellow)),
                                ]);
                            }
                            UserClientEvent::CredentialRequest { domain, request_id, session_id } => {
                                match lookup_credential(&domain) {
                                    Some(credential) => {
                                        let found_msg = format!(
                                            "Found: {} ({})",
                                            credential.username.as_deref().unwrap_or("no username"),
                                            credential.uri.as_deref().unwrap_or("no uri")
                                        );
                                        app.push_msg(MessageKind::Info, found_msg);
                                        app.commands = &[];
                                        phase = Phase::CredentialApproval {
                                            domain: domain.clone(),
                                            request_id,
                                            session_id,
                                            credential,
                                        };
                                        app.set_mode(Mode::Confirm {
                                            title: format!("Send credential for {domain}?"),
                                            description: Line::from("Approve sending the credential to the remote device"),
                                        });
                                        app.footer = Line::from(
                                            Span::styled(
                                                " Press [y] to approve or [n] to deny",
                                                Style::default().fg(Color::Yellow),
                                            )
                                        );
                                    }
                                    None => {
                                        app.push_msg(MessageKind::Error, format!("No credential found in vault for {domain}"));
                                        response_tx
                                            .send(UserClientResponse::RespondCredential {
                                                request_id,
                                                session_id,
                                                approved: false,
                                                credential: None,
                                            })
                                            .await
                                            .ok();
                                    }
                                }
                            }
                            UserClientEvent::RendevouzCodeGenerated { .. }
                            | UserClientEvent::PskTokenGenerated { .. } => {
                                // Update session panel with pending label
                                app.set_session_panel(session_info_messages(sessions, Some("New session  (awaiting connection)")));
                            }
                            _ => {}
                        }
                    }
                    None => {
                        app.push_msg(MessageKind::Error, "Connection closed");
                        term.draw(|frame| app.draw(frame))
                            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;
                        break EventLoopExit::Quit;
                    }
                }
            }
        }
    };

    client_handle.abort();
    Ok(exit)
}

/// Run the user client interactive session
async fn run_user_client_session(proxy_url: String, psk_mode: bool) -> Result<()> {
    let local = tokio::task::LocalSet::new();

    local
        .run_until(async move {
            // First iteration: if cached sessions exist, listen on those immediately.
            // On `/new`, we loop back and start a fresh rendezvous/psk session.
            let mut force_new_session = false;

            // Create TUI state once — it survives across `/new` restarts.
            let mut app = App::new();
            app.client_label = "User client";
            let bw_status = check_bw_status();
            app.account_name = bw_status.user_email;
            app.vault_status = Some(bw_status.status_spans);
            let mut term = init_terminal();
            let mut reader = EventStream::new();

            loop {
                let identity_provider =
                    Box::new(FileIdentityStorage::load_or_generate("user_client")?);
                let session_store = Box::new(FileSessionCache::load_or_create("user_client")?);
                let cached_sessions = session_store.list_sessions();

                let has_cached = !cached_sessions.is_empty() && !force_new_session;

                let (event_tx, event_rx) = mpsc::channel(32);
                let (response_tx, response_rx) = mpsc::channel(32);

                let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
                    proxy_url: proxy_url.clone(),
                    identity_keypair: Some(identity_provider.identity().to_owned()),
                }));

                let sessions = session_store.list_sessions();

                let client_handle = tokio::task::spawn_local(async move {
                    let mut client = UserClient::listen(
                        identity_provider as Box<dyn IdentityProvider>,
                        session_store as Box<dyn SessionStore>,
                        proxy_client,
                    )
                    .await?;

                    if has_cached {
                        client.listen_cached_only(event_tx, response_rx).await
                    } else if psk_mode {
                        client.enable_psk(event_tx, response_rx).await
                    } else {
                        client.enable_rendezvous(event_tx, response_rx).await
                    }
                });

                match run_event_loop(
                    &mut app,
                    &mut term,
                    &mut reader,
                    event_rx,
                    response_tx,
                    &sessions,
                    client_handle,
                )
                .await?
                {
                    EventLoopExit::NewSession => {
                        force_new_session = true;
                        continue;
                    }
                    EventLoopExit::Quit => break,
                }
            }

            drop(reader);
            restore_terminal();
            println!("\nUser client session ended.");
            Ok(())
        })
        .await
}
