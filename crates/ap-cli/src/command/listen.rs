//! Listen command implementation
//!
//! Handles the user-client (trusted device) mode for receiving and
//! approving connection requests from remote clients.

use ap_client::{
    CredentialData, CredentialRequestReply, DefaultProxyClient, FingerprintVerificationReply,
    IdentityProvider, SessionStore, UserClient, UserClientNotification, UserClientRequest,
};
use ap_proxy_client::ProxyClientConfig;
use ap_proxy_protocol::IdentityFingerprint;
use clap::Args;
use color_eyre::eyre::Result;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures_util::StreamExt;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use tokio::sync::{mpsc, oneshot};

use super::tui::{
    App, AppAction, Message, MessageKind, Mode, init_terminal, restore_terminal, wait_for_keypress,
};
use super::util::{format_listen_notification, format_relative_time, val_style};
use crate::providers::{CredentialProvider, LookupResult, ProviderStatus};
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
    /// Fingerprint verification pending — carries the oneshot reply sender.
    FingerprintConfirm {
        reply: oneshot::Sender<FingerprintVerificationReply>,
    },
    /// Prompting user for a friendly device name after fingerprint approval.
    NameInput {
        reply: oneshot::Sender<FingerprintVerificationReply>,
    },
    /// Credential approval pending — carries the oneshot reply sender.
    CredentialApproval {
        query: ap_client::CredentialQuery,
        credential: CredentialData,
        reply: oneshot::Sender<CredentialRequestReply>,
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
async fn reload_sessions() -> Vec<SessionInfo> {
    match FileSessionCache::load_or_create("user_client") {
        Ok(cache) => cache.list_sessions().await,
        Err(_) => Vec::new(),
    }
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
/// Handles notifications and requests from the `UserClient`, credential lookups,
/// and user input in a single `select!` loop.
///
/// The TUI state (`app`, `term`, `reader`) is owned by the caller so that
/// it survives across `/pair` session restarts without flickering.
#[allow(clippy::too_many_arguments)]
async fn run_event_loop(
    app: &mut App,
    term: &mut ratatui::DefaultTerminal,
    reader: &mut EventStream,
    mut notification_rx: mpsc::Receiver<UserClientNotification>,
    mut request_rx: mpsc::Receiver<UserClientRequest>,
    sessions: &[SessionInfo],
    pending_session_name: &Option<String>,
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
                                (Phase::FingerprintConfirm { .. }, AppAction::Confirmed(approved)) => {
                                    let approved = *approved;
                                    let old_phase = std::mem::replace(&mut phase, Phase::Idle);
                                    if let Phase::FingerprintConfirm { reply } = old_phase {
                                        if !approved {
                                            let _ = reply.send(FingerprintVerificationReply { approved: false, name: None });
                                            app.push_msg(MessageKind::Error, "Fingerprint rejected");
                                            app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                        } else if let Some(name) = pending_session_name.clone() {
                                            // Name was pre-set via /pair — send immediately
                                            let _ = reply.send(FingerprintVerificationReply { approved: true, name: Some(name) });
                                            app.push_msg(MessageKind::Success, "Fingerprint approved");
                                            app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                        } else {
                                            // No name pre-set — prompt user for one
                                            app.push_msg(MessageKind::Success, "Fingerprint approved");
                                            phase = Phase::NameInput { reply };
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
                                }

                                // Name input after fingerprint approval
                                (Phase::NameInput { .. }, AppAction::Submit(text)) => {
                                    let name = if text.is_empty() { None } else { Some(text.clone()) };
                                    let old_phase = std::mem::replace(&mut phase, Phase::Idle);
                                    if let Phase::NameInput { reply } = old_phase {
                                        let _ = reply.send(FingerprintVerificationReply { approved: true, name });
                                    }
                                    app.enter_idle(idle_footer(), IDLE_COMMANDS);
                                }

                                // Credential approval
                                (Phase::CredentialApproval { .. }, AppAction::Confirmed(approved)) => {
                                    let approved = *approved;
                                    let old_phase = std::mem::replace(&mut phase, Phase::Idle);
                                    if let Phase::CredentialApproval { query, credential, reply } = old_phase {
                                        let label = credential.domain.clone().unwrap_or_else(|| query.to_string());
                                        let cred_id = credential.credential_id.clone();
                                        if approved {
                                            let _ = reply.send(CredentialRequestReply {
                                                approved: true,
                                                credential: Some(credential),
                                                credential_id: cred_id,
                                            });
                                            app.push_msg(MessageKind::Success, format!("Credential sent for {label}"));
                                        } else {
                                            let _ = reply.send(CredentialRequestReply {
                                                approved: false,
                                                credential: None,
                                                credential_id: cred_id,
                                            });
                                            app.push_msg(MessageKind::Error, format!("Credential denied for {label}"));
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

            // Handle notifications (fire-and-forget status updates)
            notification = notification_rx.recv() => {
                match notification {
                    Some(notification) => {
                        // Print the formatted notification message
                        if let Some(msg) = format_listen_notification(&notification) {
                            app.push_rich(msg);
                        }

                        // Handle phase transitions for informational events
                        match notification {
                            UserClientNotification::SessionRefreshed { .. }
                            | UserClientNotification::FingerprintVerified { .. } => {
                                // Session store was updated — reload from disk
                                let fresh = reload_sessions().await;
                                app.set_session_panel(session_info_messages(&fresh, None));
                            }
                            _ => {}
                        }
                    }
                    None => {
                        // Notification channel closed — client event loop ended
                        app.push_msg(MessageKind::Error, "Connection closed");
                        app.push_msg(MessageKind::Info, "Press any key to exit");
                        term.draw(|frame| app.draw(frame))
                            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;
                        wait_for_keypress(reader).await;
                        break EventLoopExit::Quit;
                    }
                }
            }

            // Handle requests (require caller action via oneshot reply)
            request = request_rx.recv() => {
                if let Some(request) = request {
                    match request {
                        UserClientRequest::VerifyFingerprint { fingerprint, reply, .. } => {
                            // Display the fingerprint
                            app.push_rich(Message::rich(
                                MessageKind::Prompt,
                                vec![
                                    Span::styled(
                                        "SECURITY VERIFICATION — Fingerprint: ",
                                        Style::default()
                                            .fg(Color::Magenta)
                                            .add_modifier(Modifier::BOLD),
                                    ),
                                    Span::styled(fingerprint, val_style()),
                                    Span::styled(
                                        " — Compare with remote device",
                                        Style::default().fg(Color::DarkGray),
                                    ),
                                ],
                            ));

                            // Enter confirmation phase
                            phase = Phase::FingerprintConfirm { reply };
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
                        UserClientRequest::CredentialRequest { query, identity, reply } => {
                            // Display the request
                            app.push_rich(Message::rich(
                                MessageKind::Prompt,
                                vec![
                                    Span::styled("Credential request - ", Style::default().fg(Color::White)),
                                    Span::styled(query.to_string(), val_style()),
                                ],
                            ));

                            match provider.lookup(&query) {
                                LookupResult::Found(credential) => {
                                    let domain = credential.domain.clone().unwrap_or_else(|| query.to_string());
                                    let found_msg = format!(
                                        "Found: {} ({})",
                                        credential.username.as_deref().unwrap_or("no username"),
                                        credential.uri.as_deref().unwrap_or("no uri")
                                    );
                                    app.push_msg(MessageKind::Info, found_msg);
                                    app.commands = &[];
                                    let device_label = sessions
                                        .iter()
                                        .find(|(fp, _, _, _)| *fp == identity)
                                        .map(|(fp, name, _, _)| {
                                            name.clone().unwrap_or_else(|| {
                                                hex::encode(fp.0)
                                                    .chars()
                                                    .take(12)
                                                    .collect::<String>()
                                            })
                                        })
                                        .unwrap_or_else(|| "unknown device".to_string());
                                    phase = Phase::CredentialApproval {
                                        query,
                                        credential,
                                        reply,
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
                                    let label = query.to_string();
                                    match result {
                                        LookupResult::NotReady { message } => {
                                            app.push_msg(MessageKind::Warning, format!("{message} — cannot look up credential for {label}"));
                                        }
                                        _ => {
                                            app.push_msg(MessageKind::Error, format!("No credential found in vault for {label}"));
                                        }
                                    }
                                    // Auto-deny: reply through the oneshot directly
                                    let _ = reply.send(CredentialRequestReply {
                                        approved: false,
                                        credential: None,
                                        credential_id: None,
                                    });
                                }
                            }
                        }
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

    Ok(exit)
}

/// Run the user client interactive session
async fn run_user_client_session(
    proxy_url: String,
    psk_mode: bool,
    provider: &mut dyn CredentialProvider,
    mut log_rx: Option<super::tui_tracing::LogReceiver>,
) -> Result<()> {
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
        let identity_provider = Box::new(FileIdentityStorage::load_or_generate("user_client")?);
        let session_cache = FileSessionCache::load_or_create("user_client")?;
        let session_store = Box::new(session_cache);
        let cached_sessions = session_store.list_sessions().await;

        let has_cached = !cached_sessions.is_empty() && !force_new_session;

        let (notification_tx, notification_rx) = mpsc::channel(32);
        let (request_tx, request_rx) = mpsc::channel(32);

        let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
            proxy_url: proxy_url.clone(),
            identity_keypair: Some(identity_provider.identity().await),
        }));

        let client = UserClient::connect(
            identity_provider as Box<dyn IdentityProvider>,
            session_store as Box<dyn SessionStore>,
            proxy_client,
            notification_tx,
            request_tx,
            None,
        )
        .await?;

        if !has_cached {
            let client_session_name = pending_session_name.clone();
            if psk_mode {
                let token = client.get_psk_token(client_session_name).await?;
                app.push_rich(Message::rich(
                    MessageKind::Prompt,
                    vec![
                        Span::styled(
                            "PSK TOKEN: ",
                            Style::default()
                                .fg(Color::Magenta)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(token, val_style()),
                        Span::styled(
                            " — Share this token securely",
                            Style::default().fg(Color::DarkGray),
                        ),
                    ],
                ));
            } else {
                let code = client.get_rendezvous_token(client_session_name).await?;
                app.push_rich(Message::rich(
                    MessageKind::Prompt,
                    vec![
                        Span::styled(
                            "RENDEZVOUS CODE: ",
                            Style::default()
                                .fg(Color::Magenta)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(code.as_str().to_string(), val_style()),
                        Span::styled(
                            " — Share this code with your remote device",
                            Style::default().fg(Color::DarkGray),
                        ),
                    ],
                ));
            }
            app.set_session_panel(session_info_messages(
                &cached_sessions,
                Some("New session  (awaiting connection)"),
            ));
        }

        match run_event_loop(
            &mut app,
            &mut term,
            &mut reader,
            notification_rx,
            request_rx,
            &cached_sessions,
            &pending_session_name,
            provider,
            &mut log_rx,
        )
        .await?
        {
            EventLoopExit::NewSession { name } => {
                force_new_session = true;
                pending_session_name = name;
                // Drop the client handle — event loop shuts down when all handles are dropped
                drop(client);
                continue;
            }
            EventLoopExit::Quit => break,
        }
    }

    drop(reader);
    restore_terminal();
    println!("\nUser client session ended.");
    Ok(())
}
