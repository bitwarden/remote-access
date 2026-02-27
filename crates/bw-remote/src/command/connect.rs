//! Connect command implementation
//!
//! Handles the interactive session for connecting to a proxy
//! and requesting credentials over a secure Noise Protocol channel.

use bw_noise_protocol::Psk;
use bw_proxy::ProxyClientConfig;
use bw_rat_client::{
    DefaultProxyClient, IdentityFingerprint, IdentityProvider, RemoteClient, RemoteClientEvent,
    RemoteClientResponse, SessionStore,
};
use clap::Args;
use color_eyre::eyre::{Result, bail};
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures_util::StreamExt;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use tokio::sync::mpsc;

use super::output::{
    OutputFormat, emit_json_error, emit_json_success, emit_text_credential, exit_code_for_error,
    exit_code_name,
};
use super::tui::{App, AppAction, MessageKind, Mode, init_terminal, restore_terminal};
use super::util::{format_connect_event, format_relative_time};
use crate::storage::{FileIdentityStorage, FileSessionCache};

const DEFAULT_PROXY_URL: &str = "ws://localhost:8080";

/// Arguments for the connect command
#[derive(Args)]
pub struct ConnectArgs {
    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL)]
    pub proxy_url: String,

    /// Token (rendezvous code or PSK token)
    #[arg(long)]
    pub token: Option<String>,

    /// Session fingerprint to reconnect to (hex string or unique prefix)
    #[arg(long)]
    pub session: Option<String>,

    /// Disable session caching
    #[arg(long)]
    pub no_cache: bool,

    /// Require fingerprint verification on the connect side
    #[arg(long)]
    pub verify_fingerprint: bool,

    /// Domain to request credentials for (single-shot, non-interactive)
    #[arg(long)]
    pub domain: Option<String>,

    /// Output format for single-shot mode
    #[arg(long, default_value = "text", value_enum)]
    pub output: OutputFormat,
}

impl ConnectArgs {
    /// Execute the connect command
    pub async fn run(self) -> Result<()> {
        if let Some(domain) = self.domain {
            // Single-shot mode: --domain requires --token or --session
            if self.token.is_none() && self.session.is_none() {
                bail!("--domain requires --token or --session");
            }
            run_single_shot(
                self.proxy_url,
                self.token,
                self.session,
                self.no_cache,
                domain,
                self.output,
            )
            .await
        } else {
            run_interactive_session(
                self.proxy_url,
                self.token,
                self.session,
                self.no_cache,
                self.verify_fingerprint,
            )
            .await
        }
    }
}

/// Connection mode for establishing a connection
enum ConnectionMode {
    /// New connection requiring rendezvous code pairing
    New { rendezvous_code: String },
    /// New connection using PSK authentication
    NewPsk {
        psk: Psk,
        remote_fingerprint: IdentityFingerprint,
    },
    /// Existing connection using cached remote fingerprint
    Existing {
        remote_fingerprint: IdentityFingerprint,
    },
}

/// Token type parsed from user input
enum TokenType {
    Rendezvous(String),
    Psk {
        psk: Psk,
        fingerprint: IdentityFingerprint,
    },
}

/// Current phase of the connect command's interactive loop.
enum Phase {
    /// Choosing between new connection or cached session.
    SessionSelect {
        sorted_sessions: Vec<(IdentityFingerprint, Option<String>, u64, u64)>,
    },
    /// Entering a token (rendezvous code or PSK).
    TokenInput,
    /// Handshake/pairing in progress (read-only, no input).
    Connecting,
    /// Fingerprint verification prompt.
    FingerprintConfirm,
    /// Connected — entering domains to request credentials.
    Connected,
}

/// Parse a token (rendezvous code or PSK token)
fn parse_token(token: &str) -> Result<TokenType> {
    if token.contains('_') && token.len() == 129 {
        // PSK token: <64-char-hex>_<64-char-hex>
        let parts: Vec<&str> = token.split('_').collect();
        if parts.len() != 2 || parts[0].len() != 64 || parts[1].len() != 64 {
            bail!("Invalid PSK token format (expected 64-char hex + underscore + 64-char hex)");
        }

        let psk = Psk::from_hex(parts[0])
            .map_err(|e| color_eyre::eyre::eyre!("Invalid PSK in token: {}", e))?;
        let fingerprint = parse_fingerprint_hex(parts[1])?;

        Ok(TokenType::Psk { psk, fingerprint })
    } else {
        // Rendezvous code (6 chars)
        validate_rendezvous_code(token)?;
        Ok(TokenType::Rendezvous(token.to_string()))
    }
}

/// Build pick-list labels for session selection.
#[allow(clippy::string_slice)]
fn session_pick_options(
    sorted_sessions: &[(IdentityFingerprint, Option<String>, u64, u64)],
) -> Vec<String> {
    let mut options = vec!["New connection (enter token)".to_string()];
    for (fingerprint, _, _, last_connected) in sorted_sessions {
        let short_hex = hex::encode(fingerprint.0)
            .chars()
            .take(12)
            .collect::<String>();
        let relative_time = format_relative_time(*last_connected);
        options.push(format!("Session {short_hex}  (last used: {relative_time})"));
    }
    options
}

/// Footer shown during session selection.
fn select_footer() -> Line<'static> {
    Line::from(vec![
        Span::raw(" ↑↓ navigate  "),
        Span::styled("Enter", Style::default().fg(Color::Cyan)),
        Span::raw(" select  "),
        Span::styled("Esc", Style::default().fg(Color::Cyan)),
        Span::raw(" quit"),
    ])
}

/// Footer shown during token input.
fn token_footer() -> Line<'static> {
    Line::from(vec![
        Span::raw(" Enter a rendezvous code or PSK token  "),
        Span::styled("/exit", Style::default().fg(Color::Cyan)),
        Span::raw(" quit  "),
        Span::raw("| PageUp/PageDown to scroll"),
    ])
}

/// Footer shown while connecting.
fn connecting_footer() -> Line<'static> {
    Line::from(vec![Span::styled(
        " Establishing secure connection...",
        Style::default().fg(Color::Yellow),
    )])
}

/// Footer shown during the credential loop.
fn domain_footer() -> Line<'static> {
    Line::from(vec![
        Span::raw(" Enter a domain to request credentials  "),
        Span::styled("/exit", Style::default().fg(Color::Cyan)),
        Span::raw(" quit  "),
        Span::raw("| PageUp/PageDown to scroll"),
    ])
}

/// Run an interactive session for requesting credentials
async fn run_interactive_session(
    proxy_url: String,
    token: Option<String>,
    session_fingerprint: Option<String>,
    no_cache: bool,
    verify_fingerprint: bool,
) -> Result<()> {
    // Create identity provider and session store first
    let identity_provider: Box<dyn IdentityProvider> =
        Box::new(FileIdentityStorage::load_or_generate("remote_client")?);
    let session_store: Box<dyn SessionStore> =
        Box::new(FileSessionCache::load_or_create("remote_client")?);

    // Get cached sessions from session store
    let cached_sessions = session_store.list_sessions();

    // Determine if we can skip straight to connecting based on CLI flags
    let cli_connection_mode = if let Some(session_hex) = session_fingerprint {
        let fingerprint = resolve_session_prefix(&session_hex, &cached_sessions)?;
        Some(ConnectionMode::Existing {
            remote_fingerprint: fingerprint,
        })
    } else if let Some(code_or_token) = token {
        match parse_token(&code_or_token)? {
            TokenType::Rendezvous(code) => Some(ConnectionMode::New {
                rendezvous_code: code,
            }),
            TokenType::Psk { psk, fingerprint } => Some(ConnectionMode::NewPsk {
                psk,
                remote_fingerprint: fingerprint,
            }),
        }
    } else {
        None
    };

    // Initialise the TUI before any user interaction
    let mut app = App::new();
    let mut term = init_terminal();
    let mut reader = EventStream::new();

    // Track deferred resources for interactive connection setup.
    // When CLI flags provide a connection mode these are consumed immediately;
    // otherwise they are consumed when the user picks a session or enters a token.
    let mut deferred_identity: Option<Box<dyn IdentityProvider>> = Some(identity_provider);
    let mut deferred_session_store: Option<Box<dyn SessionStore>> = Some(session_store);
    let deferred_proxy_url = proxy_url;

    let mut event_rx: Option<mpsc::Receiver<RemoteClientEvent>> = None;
    let mut response_tx: Option<mpsc::Sender<RemoteClientResponse>> = None;
    let mut client: Option<RemoteClient> = None;

    // Determine starting phase (and connect immediately for CLI-flag paths)
    let mut phase = if let Some(mode) = cli_connection_mode {
        // CLI flags provided — go straight to connecting
        if no_cache {
            app.push_msg(MessageKind::Info, "Session caching disabled");
        }
        app.push_msg(MessageKind::Status, "Connecting to proxy...");
        app.input_title = " Domain ";
        app.footer = connecting_footer();

        match start_connection(
            deferred_identity.take().expect("identity consumed twice"),
            deferred_session_store
                .take()
                .expect("session store consumed twice"),
            &deferred_proxy_url,
            &mode,
            verify_fingerprint,
        )
        .await
        {
            Ok((erx, rtx, c)) => {
                event_rx = Some(erx);
                response_tx = Some(rtx);
                client = Some(c);
            }
            Err(e) => {
                restore_terminal();
                bail!("Connection failed: {e}");
            }
        }

        Phase::Connecting
    } else if !cached_sessions.is_empty() && !no_cache {
        // Cached sessions available — show pick list
        let mut sorted = cached_sessions.clone();
        sorted.sort_by(|a, b| b.3.cmp(&a.3));
        let options = session_pick_options(&sorted);
        app.set_mode(Mode::Pick {
            title: "Select connection".to_string(),
            options,
            selected: 0,
        });
        app.footer = select_footer();
        Phase::SessionSelect {
            sorted_sessions: sorted,
        }
    } else {
        // No cached sessions — prompt for token
        app.push_msg(
            MessageKind::Prompt,
            "Enter a token (rendezvous code or PSK token):",
        );
        app.input_title = " Token ";
        app.footer = token_footer();
        app.commands = &["/exit"];
        Phase::TokenInput
    };

    loop {
        term.draw(|frame| app.draw(frame))
            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;

        // Build the select! dynamically depending on whether event_rx exists
        tokio::select! {
            maybe_event = reader.next() => {
                if let Some(Ok(Event::Key(key))) = maybe_event {
                    if key.kind == KeyEventKind::Press {
                        if let Some(action) = app.handle_key(key) {
                            match (&phase, action) {
                                // ── Session selection (pick list) ──
                                (Phase::SessionSelect { .. }, AppAction::Picked(idx)) => {
                                    // Extract sorted_sessions before replacing phase
                                    let sorted_sessions = match &phase {
                                        Phase::SessionSelect { sorted_sessions } => sorted_sessions.clone(),
                                        _ => unreachable!(),
                                    };

                                    if idx == 0 {
                                        // New connection — prompt for token
                                        app.push_msg(MessageKind::Prompt, "Enter a token (rendezvous code or PSK token):");
                                        app.set_mode(Mode::TextInput);
                                        app.input_title = " Token ";
                                        app.footer = token_footer();
                                        app.commands = &["/exit"];
                                        phase = Phase::TokenInput;
                                    } else {
                                        let (fingerprint, _, _, _) = &sorted_sessions[idx - 1];
                                        let mode = ConnectionMode::Existing {
                                            remote_fingerprint: *fingerprint,
                                        };

                                        // Start connecting
                                        app.push_msg(MessageKind::Status, "Connecting to proxy...");
                                        app.set_mode(Mode::TextInput);
                                        app.input_title = " Domain ";
                                        app.footer = connecting_footer();

                                        match start_connection(
                                            deferred_identity.take().expect("identity consumed twice"),
                                            deferred_session_store.take().expect("session store consumed twice"),
                                            &deferred_proxy_url,
                                            &mode,
                                            verify_fingerprint,
                                        ).await {
                                            Ok((erx, rtx, c)) => {
                                                event_rx = Some(erx);
                                                response_tx = Some(rtx);
                                                client = Some(c);
                                                app.commands = &[];
                                                phase = Phase::Connecting;
                                            }
                                            Err(e) => {
                                                app.push_msg(MessageKind::Error, format!("Connection failed: {e}"));
                                                break;
                                            }
                                        }
                                    }
                                }

                                // ── Token input ──
                                (Phase::TokenInput, AppAction::Submit(text)) => {
                                    let lower = text.trim().to_lowercase();
                                    if lower == "/exit" {
                                        break;
                                    }

                                    let trimmed = text.trim();
                                    if trimmed.is_empty() {
                                        app.push_msg(MessageKind::Error, "Token is required");
                                        continue;
                                    }

                                    match parse_token(trimmed) {
                                        Ok(token_type) => {
                                            let mode = match token_type {
                                                TokenType::Rendezvous(code) => ConnectionMode::New {
                                                    rendezvous_code: code,
                                                },
                                                TokenType::Psk { psk, fingerprint } => ConnectionMode::NewPsk {
                                                    psk,
                                                    remote_fingerprint: fingerprint,
                                                },
                                            };

                                            app.push_msg(MessageKind::Status, "Connecting to proxy...");
                                            app.input_title = " Domain ";
                                            app.footer = connecting_footer();

                                            match start_connection(
                                                deferred_identity.take().expect("identity consumed twice"),
                                                deferred_session_store.take().expect("session store consumed twice"),
                                                &deferred_proxy_url,
                                                &mode,
                                                verify_fingerprint,
                                            ).await {
                                                Ok((erx, rtx, c)) => {
                                                    event_rx = Some(erx);
                                                    response_tx = Some(rtx);
                                                    client = Some(c);
                                                    app.commands = &[];
                                                    phase = Phase::Connecting;
                                                }
                                                Err(e) => {
                                                    app.push_msg(MessageKind::Error, format!("Connection failed: {e}"));
                                                    break;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            app.push_msg(MessageKind::Error, format!("{e}"));
                                        }
                                    }
                                }

                                // ── Connecting (ignore text input) ──
                                (Phase::Connecting, AppAction::Submit(_)) => {
                                    // Ignore — handshake in progress
                                }

                                // ── Fingerprint confirmation ──
                                (Phase::FingerprintConfirm, AppAction::Confirmed(approved)) => {
                                    if let Some(ref tx) = response_tx {
                                        tx.send(RemoteClientResponse::VerifyFingerprint { approved })
                                            .await
                                            .ok();
                                    }
                                    if approved {
                                        app.push_msg(MessageKind::Success, "Fingerprint approved");
                                    } else {
                                        app.push_msg(MessageKind::Error, "Fingerprint rejected");
                                    }
                                    phase = Phase::Connecting;
                                    app.set_mode(Mode::TextInput);
                                    app.footer = connecting_footer();
                                }

                                // ── Connected — domain requests ──
                                (Phase::Connected, AppAction::Submit(text)) => {
                                    let lower = text.trim().to_lowercase();
                                    if lower == "/exit" {
                                        break;
                                    }
                                    let domain = text.trim().to_string();
                                    if domain.is_empty() {
                                        app.push_msg(MessageKind::Error, "Domain is required");
                                        continue;
                                    }

                                    app.push_msg(MessageKind::User, format!("Requesting: {domain}"));

                                    if let Some(ref mut c) = client {
                                        let mut cred_fut = std::pin::pin!(c.request_credential(&domain));
                                        let mut user_quit = false;
                                        let cred_result = loop {
                                            term.draw(|frame| app.draw(frame))
                                                .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;
                                            tokio::select! {
                                                result = &mut cred_fut => {
                                                    break Some(result);
                                                }
                                                maybe_ev = reader.next() => {
                                                    if let Some(Ok(Event::Key(key))) = maybe_ev {
                                                        if key.kind == KeyEventKind::Press {
                                                            if let Some(AppAction::Quit) = app.handle_key(key) {
                                                                user_quit = true;
                                                                break None;
                                                            }
                                                        }
                                                    }
                                                }
                                                event = async {
                                                    match event_rx.as_mut() {
                                                        Some(rx) => rx.recv().await,
                                                        None => std::future::pending().await,
                                                    }
                                                } => {
                                                    if let Some(event) = event {
                                                        if let Some(msg) = format_connect_event(&event) {
                                                            app.push_rich(msg);
                                                        }
                                                    }
                                                }
                                            }
                                        };

                                        if user_quit {
                                            break;
                                        }

                                        match cred_result {
                                            Some(Ok(credential)) => {
                                                app.push_msg(MessageKind::Success, format!("Credential received for: {domain}"));
                                                if let Some(username) = &credential.username {
                                                    app.push_msg(MessageKind::Info, format!("  Username: {username}"));
                                                }
                                                if let Some(password) = &credential.password {
                                                    app.push_msg(MessageKind::Info, format!("  Password: {password}"));
                                                }
                                                if let Some(totp) = &credential.totp {
                                                    app.push_msg(MessageKind::Info, format!("  TOTP: {totp}"));
                                                }
                                                if let Some(uri) = &credential.uri {
                                                    app.push_msg(MessageKind::Info, format!("  URI: {uri}"));
                                                }
                                            }
                                            Some(Err(e)) => {
                                                app.push_msg(MessageKind::Error, format!("Failed to get credential: {e}"));
                                            }
                                            None => {}
                                        }
                                    }
                                }

                                // ── Global quit ──
                                (_, AppAction::Quit) => break,

                                // ── Catch-all ──
                                _ => {}
                            }
                        }
                    }
                }
            }

            // Handle remote client events (only when connected)
            event = async {
                match event_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match event {
                    Some(event) => {
                        // Handle fingerprint verification
                        if let RemoteClientEvent::HandshakeFingerprint { .. } = &event {
                            if verify_fingerprint {
                                if let Some(msg) = format_connect_event(&event) {
                                    app.push_rich(msg);
                                }
                                phase = Phase::FingerprintConfirm;
                                app.set_mode(Mode::Confirm {
                                    title: "Fingerprint Verification".to_string(),
                                    description: Line::from("Do the fingerprints match?"),
                                });
                                app.footer = Line::from(
                                    Span::styled(
                                        " Compare the fingerprint above with the remote device",
                                        Style::default().fg(Color::Yellow),
                                    )
                                );
                                continue;
                            }
                        }

                        // Transition to Connected on Ready
                        if matches!(event, RemoteClientEvent::Ready { .. }) {
                            app.push_msg(MessageKind::Success, "Connection established");
                            if no_cache {
                                app.push_msg(MessageKind::Info, "Session caching disabled");
                            } else {
                                app.push_msg(MessageKind::Info, "Session caching enabled (use --no-cache to disable)");
                            }
                            app.input_title = " Domain ";
                            app.footer = domain_footer();
                            app.commands = &["/exit"];
                            phase = Phase::Connected;
                        }

                        if let Some(msg) = format_connect_event(&event) {
                            app.push_rich(msg);
                        }
                    }
                    None => {
                        app.push_msg(MessageKind::Error, "Connection closed by remote");
                        term.draw(|frame| app.draw(frame))
                            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;
                        break;
                    }
                }
            }
        }
    }

    restore_terminal();

    if let Some(mut c) = client {
        println!("Closing connection...");
        c.close().await;
    }
    println!("Connection closed. Goodbye!");
    Ok(())
}

/// Run a single-shot credential request — no TUI, stdout/stderr only.
///
/// This is the agent/LLM-friendly code path. It never initializes ratatui,
/// prints structured output to stdout, status to stderr, and exits with a
/// well-defined exit code.
async fn run_single_shot(
    proxy_url: String,
    token: Option<String>,
    session_fingerprint: Option<String>,
    no_cache: bool,
    domain: String,
    output: OutputFormat,
) -> Result<()> {
    use super::output::exit_code;

    let identity_provider: Box<dyn IdentityProvider> =
        Box::new(FileIdentityStorage::load_or_generate("remote_client")?);

    let session_store: Box<dyn SessionStore> = if no_cache {
        // Create a fresh, empty cache that won't be persisted
        Box::new(FileSessionCache::load_or_create("remote_client")?)
    } else {
        Box::new(FileSessionCache::load_or_create("remote_client")?)
    };

    // Determine connection mode from flags (no interactive prompts)
    let cached_sessions = session_store.list_sessions();
    let mode = if let Some(session_hex) = session_fingerprint {
        match resolve_session_prefix(&session_hex, &cached_sessions) {
            Ok(fingerprint) => ConnectionMode::Existing {
                remote_fingerprint: fingerprint,
            },
            Err(e) => {
                let msg = format!("{e}");
                match output {
                    OutputFormat::Json => emit_json_error(&msg, "general_error"),
                    OutputFormat::Text => eprintln!("Error: {msg}"),
                }
                std::process::exit(exit_code::GENERAL_ERROR);
            }
        }
    } else if let Some(code_or_token) = token {
        match parse_token(&code_or_token) {
            Ok(TokenType::Rendezvous(code)) => ConnectionMode::New {
                rendezvous_code: code,
            },
            Ok(TokenType::Psk { psk, fingerprint }) => ConnectionMode::NewPsk {
                psk,
                remote_fingerprint: fingerprint,
            },
            Err(e) => {
                let msg = format!("{e}");
                match output {
                    OutputFormat::Json => emit_json_error(&msg, "general_error"),
                    OutputFormat::Text => eprintln!("Error: {msg}"),
                }
                std::process::exit(exit_code::GENERAL_ERROR);
            }
        }
    } else {
        // Should not happen due to validation in run(), but guard anyway
        let msg = "--domain requires --token or --session";
        match output {
            OutputFormat::Json => emit_json_error(msg, "general_error"),
            OutputFormat::Text => eprintln!("Error: {msg}"),
        }
        std::process::exit(exit_code::GENERAL_ERROR);
    };

    eprintln!("Connecting to proxy...");

    // Connect — never verify fingerprint in single-shot mode (no human present)
    let (mut event_rx, _response_tx, mut client) =
        match start_connection(identity_provider, session_store, &proxy_url, &mode, false).await {
            Ok(result) => result,
            Err(e) => {
                let msg = format!("{e}");
                match output {
                    OutputFormat::Json => {
                        emit_json_error(&msg, exit_code_name(exit_code::CONNECTION_FAILED))
                    }
                    OutputFormat::Text => eprintln!("Error: {msg}"),
                }
                std::process::exit(exit_code::CONNECTION_FAILED);
            }
        };

    // Drain events in background (prevents channel backpressure)
    tokio::spawn(async move {
        while event_rx.recv().await.is_some() {
            // Events are silently consumed — the single-shot path
            // only cares about the credential response.
        }
    });

    // Wait for the connection to be ready by giving the handshake a moment
    // The start_connection call initiates pairing but the Ready event
    // arrives asynchronously. request_credential will fail if the secure
    // channel isn't established yet, so we just call it and let the client
    // handle the internal state.
    eprintln!("Requesting credential for: {domain}");

    match client.request_credential(&domain).await {
        Ok(credential) => {
            match output {
                OutputFormat::Json => emit_json_success(&domain, &credential),
                OutputFormat::Text => emit_text_credential(&domain, &credential),
            }
            client.close().await;
            std::process::exit(exit_code::SUCCESS);
        }
        Err(e) => {
            let code = exit_code_for_error(&e);
            let msg = format!("{e}");
            match output {
                OutputFormat::Json => emit_json_error(&msg, exit_code_name(code)),
                OutputFormat::Text => eprintln!("Error: {msg}"),
            }
            client.close().await;
            std::process::exit(code);
        }
    }
}

/// Create a connection, start pairing, and return the event/response channels + client.
async fn start_connection(
    identity_provider: Box<dyn IdentityProvider>,
    session_store: Box<dyn SessionStore>,
    proxy_url: &str,
    mode: &ConnectionMode,
    verify_fingerprint: bool,
) -> Result<(
    mpsc::Receiver<RemoteClientEvent>,
    mpsc::Sender<RemoteClientResponse>,
    RemoteClient,
)> {
    let (event_tx, event_rx) = mpsc::channel(32);
    let (response_tx, response_rx) = mpsc::channel(32);

    let proxy_client = Box::new(DefaultProxyClient::new(ProxyClientConfig {
        proxy_url: proxy_url.to_string(),
        identity_keypair: Some(identity_provider.identity().to_owned()),
    }));

    let mut client = RemoteClient::new(
        identity_provider,
        session_store,
        event_tx,
        response_rx,
        proxy_client,
    )
    .await
    .map_err(|e| color_eyre::eyre::eyre!("Connection to proxy failed: {}", e))?;

    start_pairing(&mut client, mode, verify_fingerprint).await?;

    Ok((event_rx, response_tx, client))
}

/// Initiate pairing based on the connection mode.
async fn start_pairing(
    client: &mut RemoteClient,
    mode: &ConnectionMode,
    verify_fingerprint: bool,
) -> Result<()> {
    match mode {
        ConnectionMode::New { rendezvous_code } => {
            client
                .pair_with_handshake(rendezvous_code, verify_fingerprint)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("Pairing failed: {}", e))?;
        }
        ConnectionMode::NewPsk {
            psk,
            remote_fingerprint,
        } => {
            client
                .pair_with_psk(psk.clone(), *remote_fingerprint)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("PSK pairing failed: {}", e))?;
        }
        ConnectionMode::Existing { remote_fingerprint } => {
            client
                .load_cached_session(*remote_fingerprint)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("Session reconnection failed: {}", e))?;
        }
    }
    Ok(())
}

/// Validate that a rendezvous code has the correct format
fn validate_rendezvous_code(code: &str) -> Result<()> {
    if code.is_empty() {
        bail!("Rendezvous code is required");
    }

    // Remove optional hyphen for validation
    let code_normalized = code.replace('-', "");

    if code_normalized.len() != 6 {
        bail!("Rendezvous code must be 6 characters (e.g., ABCD12 or ABCD-12)");
    }

    if !code_normalized.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("Rendezvous code must contain only letters and numbers");
    }

    Ok(())
}

/// Resolve a session hex prefix against cached sessions.
///
/// Accepts a full 64-char hex fingerprint or any unique prefix (e.g. "a1b2c3").
/// Returns the matching fingerprint, or an error if the prefix is ambiguous or not found.
fn resolve_session_prefix(
    prefix: &str,
    cached_sessions: &[(IdentityFingerprint, Option<String>, u64, u64)],
) -> Result<IdentityFingerprint> {
    let clean_prefix = prefix.replace(['-', ' ', ':'], "").to_lowercase();

    if clean_prefix.is_empty() {
        bail!("Session prefix must not be empty");
    }

    if !clean_prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("Session prefix must be a hex string");
    }

    let matches: Vec<IdentityFingerprint> = cached_sessions
        .iter()
        .filter(|(fp, _, _, _)| hex::encode(fp.0).starts_with(&clean_prefix))
        .map(|(fp, _, _, _)| *fp)
        .collect();

    match matches.len() {
        0 => bail!("No cached session matches prefix: {prefix}"),
        1 => Ok(matches[0]),
        n => bail!(
            "Ambiguous session prefix '{prefix}' matches {n} sessions — provide more characters"
        ),
    }
}

/// Parse a fingerprint from hex string
#[allow(clippy::string_slice)]
fn parse_fingerprint_hex(hex: &str) -> Result<IdentityFingerprint> {
    // Remove any separators or whitespace
    let clean_hex = hex.replace(['-', ' ', ':'], "");

    if clean_hex.len() != 64 {
        bail!("Fingerprint must be 64 hex characters (32 bytes)");
    }

    // SAFETY: clean_hex is validated to be 64 hex characters (ASCII only),
    // so indexing at i*2 boundaries is safe.
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        let byte_str = &clean_hex[i * 2..i * 2 + 2];
        bytes[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| color_eyre::eyre::eyre!("Invalid hex string"))?;
    }

    Ok(IdentityFingerprint(bytes))
}
