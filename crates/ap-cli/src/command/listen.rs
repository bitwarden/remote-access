//! Listen command implementation
//!
//! Handles the user-client (trusted device) mode for receiving and
//! approving connection requests from remote clients.

use ap_client::{
    DefaultProxyClient, IdentityProvider, SessionStore, UserClient, UserClientEvent,
    UserClientResponse, UserCredentialData,
};
use ap_proxy_client::ProxyClientConfig;
use ap_proxy_protocol::IdentityFingerprint;
use clap::Args;
use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures_util::StreamExt;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use tokio::sync::mpsc;

use super::tui::{
    App, AppAction, Message, MessageKind, Mode, init_terminal, restore_terminal, wait_for_keypress,
};
use super::util::{format_listen_event, format_relative_time};
use crate::providers::{CredentialProvider, CredentialQuery, LookupResult, ProviderStatus};
use crate::storage::{FileIdentityStorage, FileSessionCache};

use super::DEFAULT_PROXY_URL;

/// Slash commands available in idle mode.
const IDLE_COMMANDS: &[&str] = &["/pair [name]", "/unlock", "/exit"];

/// Arguments for the listen command
#[derive(Args)]
pub struct ListenArgs {
    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL)]
    pub proxy_url: String,

    /// Use PSK (Pre-Shared Key) mode instead of rendezvous code
    #[arg(long)]
    pub psk: bool,

    /// Credential provider to use
    #[arg(long, default_value = "bitwarden")]
    pub provider: String,
}

impl ListenArgs {
    /// Execute the listen command
    pub async fn run(self, log_rx: Option<super::tui_tracing::LogReceiver>) -> Result<()> {
        let mut provider = crate::providers::create_provider(&self.provider)?;
        run_user_client_session(self.proxy_url, self.psk, &mut *provider, log_rx).await
    }
}

/// Current phase of the listen command's interactive loop.
#[allow(clippy::large_enum_variant)]
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
    /// Waiting for the user to enter unlock input (password or session key).
    UnlockInput,
}

/// Whether the event loop exited normally or because `/pair` was requested.
enum EventLoopExit {
    Quit,
    NewSession { name: Option<String> },
}

/// Map a [`ProviderStatus`] to TUI header spans and apply them.
fn apply_status_spans(app: &mut App, name: &str, status: &ProviderStatus) {
    let (spans, user_info) = match status {
        ProviderStatus::Ready { user_info } => (
            vec![
                Span::styled(format!("{name} "), Style::default().fg(Color::Green)),
                Span::styled(
                    "unlocked",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
            ],
            user_info.clone(),
        ),
        ProviderStatus::Locked { user_info, .. } => (
            vec![
                Span::styled(format!("{name} "), Style::default().fg(Color::Red)),
                Span::styled(
                    "locked",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" — type /unlock", Style::default().fg(Color::DarkGray)),
            ],
            user_info.clone(),
        ),
        ProviderStatus::Unavailable { reason } => (
            vec![
                Span::styled(format!("{name} "), Style::default().fg(Color::Red)),
                Span::styled(
                    reason.clone(),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ],
            None,
        ),
        ProviderStatus::NotInstalled { install_hint } => (
            vec![
                Span::styled(format!("{name} "), Style::default().fg(Color::Red)),
                Span::styled(
                    "not found",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" — {install_hint}"),
                    Style::default().fg(Color::DarkGray),
                ),
            ],
            None,
        ),
    };

    app.vault_status = Some(spans);
    if let Some(info) = user_info {
        app.account_name = Some(info);
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
        Span::styled("/unlock", Style::default().fg(Color::Cyan)),
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
    mut client_handle: Option<tokio::task::JoinHandle<Result<(), ap_client::RemoteClientError>>>,
    provider: &mut dyn CredentialProvider,
    log_rx: &mut Option<super::tui_tracing::LogReceiver>,
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
                                (Phase::Idle, AppAction::Submit(s)) if s == "/unlock" => {
                                    phase = Phase::UnlockInput;
                                    app.set_mode(Mode::TextInput);
                                    app.password_mode = true;
                                    app.input_title = " Unlock ";
                                    app.commands = &[];
                                    app.footer = Line::from(Span::styled(
                                        " Type your master password or session key, then press Enter (empty to cancel)",
                                        Style::default().fg(Color::Yellow),
                                    ));
                                }

                                // Unlock input phase
                                (Phase::UnlockInput, AppAction::Submit(s)) => {
                                    if s.is_empty() {
                                        app.push_msg(MessageKind::Info, "Unlock cancelled");
                                        phase = Phase::Idle;
                                        app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                    } else {
                                        let input = s.clone();
                                        app.push_msg(MessageKind::Status, "Unlocking vault...");
                                        // Force a redraw before the blocking call
                                        term.draw(|frame| app.draw(frame))
                                            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;

                                        match provider.unlock(&input) {
                                            Ok(()) => {
                                                let status = provider.status();
                                                apply_status_spans(app, provider.name(), &status);
                                                app.push_msg(MessageKind::Success, "Vault unlocked successfully");
                                            }
                                            Err(e) => {
                                                app.push_msg(MessageKind::Error, format!("Unlock failed: {e}"));
                                            }
                                        }

                                        phase = Phase::Idle;
                                        app.enter_idle(idle_footer(), IDLE_COMMANDS);
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
                                        app.input_title = " Name this connection (Enter to skip) ";
                                        app.set_mode(Mode::TextInput);
                                        app.commands = &[];
                                        app.footer = Line::from(vec![
                                            Span::styled(
                                                " Type a friendly name for this connection, or press Enter to skip",
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
                                            let cred_id = credential.credential_id.clone();
                                            response_tx
                                                .send(UserClientResponse::RespondCredential {
                                                    request_id,
                                                    session_id,
                                                    domain: domain.clone(),
                                                    approved: true,
                                                    credential: Some(credential),
                                                    credential_id: cred_id,
                                                })
                                                .await
                                                .ok();
                                            app.push_msg(MessageKind::Success, format!("Credential sent for {domain}"));
                                        } else {
                                            response_tx
                                                .send(UserClientResponse::RespondCredential {
                                                    request_id,
                                                    session_id,
                                                    domain: domain.clone(),
                                                    approved: false,
                                                    credential: None,
                                                    credential_id: credential.credential_id,
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
                                match provider.lookup(&CredentialQuery::Domain(&domain)) {
                                    LookupResult::Found(credential) => {
                                        let found_msg = format!(
                                            "Found: {} ({})",
                                            credential.username.as_deref().unwrap_or("no username"),
                                            credential.uri.as_deref().unwrap_or("no uri")
                                        );
                                        app.push_msg(MessageKind::Info, found_msg);
                                        app.commands = &[];
                                        let device_label = sessions.iter()
                                            .find(|(fp, _, _, _)| session_id.contains(&hex::encode(fp.0)))
                                            .map(|(fp, name, _, _)| {
                                                name.clone().unwrap_or_else(|| {
                                                    hex::encode(fp.0).chars().take(12).collect::<String>()
                                                })
                                            })
                                            .unwrap_or_else(|| "unknown device".to_string());
                                        phase = Phase::CredentialApproval {
                                            domain: domain.clone(),
                                            request_id,
                                            session_id,
                                            credential,
                                        };
                                        app.set_mode(Mode::Confirm {
                                            title: format!("Send credential for {domain} to {device_label}?"),
                                            description: Line::from(""),
                                        });
                                        app.footer = Line::from(
                                            Span::styled(
                                                " Press [y] to approve or [n] to deny",
                                                Style::default().fg(Color::Yellow),
                                            )
                                        );
                                    }
                                    result @ (LookupResult::NotReady { .. } | LookupResult::NotFound) => {
                                        match result {
                                            LookupResult::NotReady { message } => {
                                                app.push_msg(MessageKind::Warning, format!("{message} — cannot look up credential for {domain}"));
                                            }
                                            _ => {
                                                app.push_msg(MessageKind::Error, format!("No credential found in vault for {domain}"));
                                            }
                                        }
                                        response_tx
                                            .send(UserClientResponse::RespondCredential {
                                                request_id,
                                                session_id,
                                                domain,
                                                approved: false,
                                                credential: None,
                                                credential_id: None,
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
                        let error_msg = match client_handle.take() {
                            Some(handle) => match handle.await {
                                Ok(Err(e)) => format!("Connection failed: {e}"),
                                Err(e) if e.is_panic() => "Client task panicked".to_string(),
                                _ => "Connection closed".to_string(),
                            },
                            None => "Connection closed".to_string(),
                        };
                        app.push_msg(MessageKind::Error, &error_msg);
                        app.push_msg(MessageKind::Info, "Press any key to exit");
                        term.draw(|frame| app.draw(frame))
                            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;
                        wait_for_keypress(reader).await;
                        break EventLoopExit::Quit;
                    }
                }
            }

            // Handle tracing log entries routed into the TUI
            log_entry = async {
                match log_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(entry) = log_entry {
                    super::tui_tracing::push_log_entry(app, entry);
                }
            }
        }
    };

    if let Some(handle) = client_handle {
        handle.abort();
    }
    Ok(exit)
}

/// Run the user client interactive session
async fn run_user_client_session(
    proxy_url: String,
    psk_mode: bool,
    provider: &mut dyn CredentialProvider,
    mut log_rx: Option<super::tui_tracing::LogReceiver>,
) -> Result<()> {
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

            // Show initial provider status (single status() call)
            let initial_status = provider.status();
            let name = provider.name();
            match &initial_status {
                ProviderStatus::Ready { .. } => {}
                ProviderStatus::Locked { .. } => {
                    app.push_msg(
                        MessageKind::Warning,
                        format!("{name} vault is not unlocked — credential lookups will fail. Use /unlock"),
                    );
                }
                ProviderStatus::Unavailable { reason } => {
                    app.push_msg(MessageKind::Warning, format!("{name}: {reason}"));
                }
                ProviderStatus::NotInstalled { install_hint } => {
                    app.push_msg(
                        MessageKind::Warning,
                        format!("{name} not found. {install_hint}"),
                    );
                }
            }
            apply_status_spans(&mut app, name, &initial_status);
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
                    Some(client_handle),
                    provider,
                    &mut log_rx,
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
