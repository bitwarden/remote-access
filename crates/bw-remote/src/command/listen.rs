//! Listen command implementation
//!
//! Handles the user-client (trusted device) mode for receiving and
//! approving connection requests from remote clients.

use std::process::Command;

use bw_proxy_client::ProxyClientConfig;
use bw_proxy_protocol::IdentityFingerprint;
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

use super::DEFAULT_PROXY_URL;

/// Slash commands available in idle mode.
const IDLE_COMMANDS: &[&str] = &["/pair [name]", "/bw-unlock", "/bw-session <key>", "/exit"];

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
    /// Prompting user for a friendly device name after fingerprint approval.
    NameInput,
    /// Credential approval pending.
    CredentialApproval {
        domain: String,
        request_id: String,
        session_id: String,
        credential: UserCredentialData,
    },
    /// Waiting for the user to enter their master password for `bw unlock`.
    BwUnlockPassword,
}

/// Whether the event loop exited normally or because `/pair` was requested.
enum EventLoopExit {
    Quit,
    NewSession { name: Option<String> },
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
fn lookup_credential(domain: &str, session: Option<&str>) -> Option<UserCredentialData> {
    let mut cmd = Command::new(bw_path());
    cmd.args(["get", "item", domain]);
    if let Some(key) = session {
        cmd.env("BW_SESSION", key);
    }
    let output = cmd.output().ok()?;

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

/// Fallback path when `bw` is not found on `$PATH` (macOS Homebrew default).
const BW_FALLBACK_PATH: &str = "/opt/homebrew/bin/bw";

/// Find bw executable on PATH.
fn which_bw() -> Option<String> {
    Command::new("which")
        .arg("bw")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Find bw executable on PATH, falling back to a well-known location.
fn bw_path() -> String {
    which_bw().unwrap_or_else(|| BW_FALLBACK_PATH.to_string())
}

/// Run `bw unlock` with the given master password and return the session key.
///
/// The password is passed via the `BW_MASTER_PASSWORD` environment variable on the
/// child process only (not set in the host environment).
fn run_bw_unlock(password: &str) -> Result<String, String> {
    let output = Command::new(bw_path())
        .args(["unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"])
        .env("BW_MASTER_PASSWORD", password)
        .output()
        .map_err(|e| format!("Failed to run bw unlock: {e}"))?;

    if output.status.success() {
        let key = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if key.is_empty() {
            Err("bw unlock returned empty session key".to_string())
        } else {
            Ok(key)
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if stderr.is_empty() {
            "bw unlock failed".to_string()
        } else {
            stderr
        })
    }
}

/// Result of checking the Bitwarden CLI status.
struct BwStatus {
    /// The account email from `bw status`, if available.
    user_email: Option<String>,
    /// Styled spans summarising the vault status (for the header).
    status_spans: Vec<Span<'static>>,
    /// Whether the vault is unlocked and ready for credential lookups.
    is_unlocked: bool,
}

/// Check if the Bitwarden CLI is available and unlocked.
///
/// When a `session` key is provided it is set as the `BW_SESSION` environment
/// variable on the child process so that `bw status` correctly reports the
/// vault as unlocked.
fn check_bw_status(session: Option<&str>) -> BwStatus {
    let path = match which_bw() {
        Some(p) => p,
        None => {
            return BwStatus {
                user_email: None,
                is_unlocked: false,
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

    let mut cmd = Command::new(path);
    cmd.arg("status");
    if let Some(key) = session {
        cmd.env("BW_SESSION", key);
    }
    let output = cmd.output();

    match output {
        Ok(o) if o.status.success() => {
            let json: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_default();
            let status = json["status"].as_str().unwrap_or("unknown");
            let user_email = json["userEmail"].as_str().map(String::from);
            let is_unlocked = status == "unlocked";

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
                    Span::styled(" — type /bw-unlock", Style::default().fg(Color::DarkGray)),
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
                is_unlocked,
                status_spans,
            }
        }
        _ => BwStatus {
            user_email: None,
            is_unlocked: false,
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

/// Apply vault status information to the TUI header.
fn apply_bw_status(app: &mut App, status: BwStatus) {
    app.vault_status = Some(status.status_spans);
    if let Some(email) = status.user_email {
        app.account_name = Some(email);
    }
}

type SessionInfo = (IdentityFingerprint, Option<String>, u64, u64);

/// Reload the session list from disk (the client may have updated it).
fn reload_sessions() -> Vec<SessionInfo> {
    FileSessionCache::load_or_create("user_client")
        .map(|cache| cache.list_sessions())
        .unwrap_or_default()
}

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
    for (fingerprint, name, cached_at, last_connected_at) in &sorted {
        let short_hex = hex::encode(fingerprint.0)
            .chars()
            .take(12)
            .collect::<String>();
        let created = format_relative_time(*cached_at);
        let last_used = format_relative_time(*last_connected_at);
        let mut spans = vec![Span::raw("  ")];
        if let Some(name) = name {
            spans.push(Span::styled(
                name.clone(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(
                format!(" ({short_hex})"),
                Style::default().fg(Color::DarkGray),
            ));
        } else {
            spans.push(Span::styled(
                short_hex,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        spans.push(Span::styled(
            format!("  created {created}, last used {last_used}"),
            Style::default().fg(Color::DarkGray),
        ));
        msgs.push(Message::rich(MessageKind::Info, spans));
    }
    if let Some(label) = pending_label {
        msgs.push(Message::new(MessageKind::Info, format!("  {label}")));
    }
    msgs
}

/// Set up the idle-mode footer for the TUI.
fn idle_footer() -> Line<'static> {
    Line::from(vec![
        Span::styled(" /pair", Style::default().fg(Color::Cyan)),
        Span::styled(" [name]", Style::default().fg(Color::DarkGray)),
        Span::raw(" session  "),
        Span::styled("/bw-unlock", Style::default().fg(Color::Cyan)),
        Span::raw(" vault  "),
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
/// it survives across `/pair` session restarts without flickering.
#[allow(clippy::too_many_arguments)]
async fn run_event_loop(
    app: &mut App,
    term: &mut ratatui::DefaultTerminal,
    reader: &mut EventStream,
    mut event_rx: mpsc::Receiver<UserClientEvent>,
    response_tx: mpsc::Sender<UserClientResponse>,
    sessions: &[SessionInfo],
    pending_session_name: &Option<String>,
    client_handle: tokio::task::JoinHandle<Result<(), bw_rat_client::RemoteClientError>>,
    bw_session: &mut Option<String>,
) -> Result<EventLoopExit> {
    let mut phase = Phase::Idle;

    // Seed session info panel for this iteration
    app.set_session_panel(session_info_messages(sessions, None));
    app.enter_idle(idle_footer(), IDLE_COMMANDS);

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
                                (Phase::Idle, AppAction::Submit(s)) if s.starts_with("/pair") => {
                                    let name = s.strip_prefix("/pair ")
                                        .map(|n| n.trim().to_string())
                                        .filter(|n| !n.is_empty());
                                    break EventLoopExit::NewSession { name };
                                }
                                (Phase::Idle, AppAction::Submit(s)) if s == "/exit" => {
                                    break EventLoopExit::Quit;
                                }
                                (Phase::Idle, AppAction::Submit(s)) if s == "/bw-unlock" => {
                                    phase = Phase::BwUnlockPassword;
                                    app.set_mode(Mode::TextInput);
                                    app.password_mode = true;
                                    app.input_title = " Master Password ";
                                    app.commands = &[];
                                    app.footer = Line::from(Span::styled(
                                        " Type your master password, then press Enter (empty to cancel)",
                                        Style::default().fg(Color::Yellow),
                                    ));
                                }
                                (Phase::Idle, AppAction::Submit(s)) if s.starts_with("/bw-session ") => {
                                    let key = s.strip_prefix("/bw-session ").unwrap_or("").trim().to_string();
                                    if key.is_empty() {
                                        app.push_msg(MessageKind::Error, "Usage: /bw-session <key>");
                                    } else {
                                        let status = check_bw_status(Some(&key));
                                        let unlocked = status.is_unlocked;
                                        apply_bw_status(app, status);
                                        if unlocked {
                                            *bw_session = Some(key);
                                            app.push_msg(MessageKind::Success, "Session key accepted — vault unlocked");
                                        } else {
                                            app.push_msg(MessageKind::Error, "Invalid session key — vault still locked");
                                        }
                                    }
                                }

                                // BwUnlockPassword phase
                                (Phase::BwUnlockPassword, AppAction::Submit(s)) => {
                                    if s.is_empty() {
                                        app.push_msg(MessageKind::Info, "Unlock cancelled");
                                        phase = Phase::Idle;
                                        app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                    } else {
                                        let password = s.clone();
                                        app.push_msg(MessageKind::Status, "Unlocking vault...");
                                        // Force a redraw before the blocking call
                                        term.draw(|frame| app.draw(frame))
                                            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;

                                        let result = tokio::task::spawn_blocking(move || {
                                            run_bw_unlock(&password)
                                        }).await;

                                        phase = Phase::Idle;
                                        app.enter_idle(idle_footer(), IDLE_COMMANDS);

                                        match result {
                                            Ok(Ok(key)) => {
                                                *bw_session = Some(key);
                                                // Successful unlock is proof — set status directly
                                                // to avoid a redundant `bw status` child process.
                                                app.vault_status = Some(vec![
                                                    Span::styled("Vault ", Style::default().fg(Color::Green)),
                                                    Span::styled(
                                                        "unlocked",
                                                        Style::default()
                                                            .fg(Color::Green)
                                                            .add_modifier(Modifier::BOLD),
                                                    ),
                                                ]);
                                                app.push_msg(MessageKind::Success, "Vault unlocked successfully");
                                            }
                                            Ok(Err(e)) => {
                                                app.push_msg(MessageKind::Error, format!("Unlock failed: {e}"));
                                            }
                                            Err(e) => {
                                                app.push_msg(MessageKind::Error, format!("Unlock task failed: {e}"));
                                            }
                                        }
                                    }
                                }

                                // Fingerprint confirmation
                                (Phase::FingerprintConfirm, AppAction::Confirmed(approved)) => {
                                    let approved = *approved;
                                    if !approved {
                                        response_tx
                                            .send(UserClientResponse::VerifyFingerprint { approved: false, name: None })
                                            .await
                                            .ok();
                                        app.push_msg(MessageKind::Error, "Fingerprint rejected");
                                        phase = Phase::Idle;
                                        app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                    } else if let Some(name) = pending_session_name.clone() {
                                        // Name was pre-set via /pair — send immediately
                                        response_tx
                                            .send(UserClientResponse::VerifyFingerprint { approved: true, name: Some(name) })
                                            .await
                                            .ok();
                                        app.push_msg(MessageKind::Success, "Fingerprint approved");
                                        phase = Phase::Idle;
                                        app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                    } else {
                                        // No name pre-set — prompt user for one
                                        app.push_msg(MessageKind::Success, "Fingerprint approved");
                                        phase = Phase::NameInput;
                                        app.input_title = " Name this device (Enter to skip) ";
                                        app.set_mode(Mode::TextInput);
                                        app.commands = &[];
                                        app.footer = Line::from(vec![
                                            Span::styled(
                                                " Type a friendly name for this device, or press Enter to skip",
                                                Style::default().fg(Color::Yellow),
                                            ),
                                        ]);
                                    }
                                }

                                // Name input after fingerprint approval
                                (Phase::NameInput, AppAction::Submit(text)) => {
                                    let name = if text.is_empty() { None } else { Some(text.clone()) };
                                    response_tx
                                        .send(UserClientResponse::VerifyFingerprint { approved: true, name })
                                        .await
                                        .ok();
                                    phase = Phase::Idle;
                                    app.enter_idle(idle_footer(), IDLE_COMMANDS);
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
                                    app.enter_idle(idle_footer(), IDLE_COMMANDS);
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
                                let description = match pending_session_name {
                                    Some(name) => Line::from(vec![
                                        Span::styled("Device: ", Style::default().fg(Color::DarkGray)),
                                        Span::styled(
                                            name.clone(),
                                            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                                        ),
                                        Span::styled(" — Do the fingerprints match?", Style::default()),
                                    ]),
                                    None => Line::from("Do the fingerprints match?"),
                                };
                                app.set_mode(Mode::Confirm {
                                    title: "Fingerprint Verification".to_string(),
                                    description,
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
                                match lookup_credential(&domain, bw_session.as_deref()) {
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
                            UserClientEvent::SessionRefreshed { .. }
                            | UserClientEvent::FingerprintVerified { .. } => {
                                // Session store was updated — reload from disk
                                let fresh = reload_sessions();
                                app.set_session_panel(session_info_messages(&fresh, None));
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
            // On `/pair`, we loop back and start a fresh rendezvous/psk session.
            let mut force_new_session = false;
            let mut pending_session_name: Option<String> = None;

            // Create TUI state once — it survives across `/pair` restarts.
            let mut app = App::new();
            app.client_label = "User client";
            let mut bw_session: Option<String> = None;
            apply_bw_status(&mut app, check_bw_status(None));
            let mut term = init_terminal();
            let mut reader = EventStream::new();

            loop {
                let identity_provider =
                    Box::new(FileIdentityStorage::load_or_generate("user_client")?);
                let session_cache = FileSessionCache::load_or_create("user_client")?;
                let session_store = Box::new(session_cache);
                let cached_sessions = session_store.list_sessions();

                let has_cached = !cached_sessions.is_empty() && !force_new_session;

                let (event_tx, event_rx) = mpsc::channel(32);
                let (response_tx, response_rx) = mpsc::channel(32);

                let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
                    proxy_url: proxy_url.clone(),
                    identity_keypair: Some(identity_provider.identity().to_owned()),
                }));

                let sessions = session_store.list_sessions();

                let client_session_name = pending_session_name.clone();
                let client_handle = tokio::task::spawn_local(async move {
                    let mut client = UserClient::listen(
                        identity_provider as Box<dyn IdentityProvider>,
                        session_store as Box<dyn SessionStore>,
                        proxy_client,
                    )
                    .await?;

                    if let Some(name) = client_session_name {
                        client.set_pending_session_name(name);
                    }

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
                    &pending_session_name,
                    client_handle,
                    &mut bw_session,
                )
                .await?
                {
                    EventLoopExit::NewSession { name } => {
                        force_new_session = true;
                        pending_session_name = name;
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
