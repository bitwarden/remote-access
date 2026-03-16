//! Connect command implementation
//!
//! Handles the interactive session for connecting to a proxy
//! and requesting credentials over a secure Noise Protocol channel.

use ap_client::{
    ConnectionMode, DefaultProxyClient, IdentityFingerprint, IdentityProvider, RemoteClient,
    RemoteClientEvent, RemoteClientResponse, SessionStore,
};
use ap_noise::Psk;
use ap_proxy_client::ProxyClientConfig;
use clap::Args;
use color_eyre::eyre::{Result, bail};
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures_util::StreamExt;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use tokio::sync::mpsc;

use super::output::{
    OutputFormat, emit_json_error, emit_json_success, emit_text_credential, exit_code_for_error,
};
use super::tui::{
    App, AppAction, MessageKind, Mode, init_terminal, restore_terminal, wait_for_keypress,
};
use super::util::{format_connect_event, format_relative_time};
use crate::storage::{FileIdentityStorage, FileSessionCache, MemorySessionStore};

use super::DEFAULT_PROXY_URL;

/// Arguments for the connect command
#[derive(Args)]
#[command(after_help = "\
AUTOMATION / AGENT / LLM USE:
  For non-interactive (single-shot) credential retrieval:

    1. Request a credential:  aac connect --domain <DOMAIN> --output json

  If only one session is cached, it is used automatically.
  With multiple cached sessions, specify one with --session <HEX>.
  --session accepts a full 64-char hex fingerprint or any unique prefix.
  --output json returns structured JSON to stdout (status to stderr).
  Exit codes: 0=success, 1=error, 2=connection failed, 3=auth failed, 4=not found, 5=fingerprint mismatch")]
pub struct ConnectArgs {
    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL)]
    pub proxy_url: String,

    /// Token (rendezvous code or PSK token)
    #[arg(long, conflicts_with = "session")]
    pub token: Option<String>,

    /// Session fingerprint to reconnect to (hex string or unique prefix)
    #[arg(long, conflicts_with = "token")]
    pub session: Option<String>,

    /// Don't save this connection for future use
    #[arg(long)]
    pub ephemeral_connection: bool,

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
    pub async fn run(self, log_rx: Option<super::tui_tracing::LogReceiver>) -> Result<()> {
        if let Some(domain) = self.domain {
            run_single_shot(
                self.proxy_url,
                self.token,
                self.session,
                self.ephemeral_connection,
                domain,
                self.output,
            )
            .await
        } else {
            run_interactive_session(
                self.proxy_url,
                self.token,
                self.session,
                self.ephemeral_connection,
                self.verify_fingerprint,
                log_rx,
            )
            .await
        }
    }
}

const EPHEMERAL_MSG: &str = "Ephemeral connection (won't be saved)";

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
        // Rendezvous code (9 chars)
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
    ephemeral_connection: bool,
    verify_fingerprint: bool,
    mut log_rx: Option<super::tui_tracing::LogReceiver>,
) -> Result<()> {
    // Create identity provider and session store first
    let identity_provider: Box<dyn IdentityProvider> =
        Box::new(FileIdentityStorage::load_or_generate("remote_client")?);
    let session_store: Box<dyn SessionStore> =
        Box::new(FileSessionCache::load_or_create("remote_client")?);

    // Get cached sessions from session store
    let cached_sessions = session_store.list_sessions();

    // Determine if we can skip straight to connecting based on CLI flags
    let cli_connection_mode = if session_fingerprint.is_some() || token.is_some() {
        Some(resolve_connection_mode(
            token.as_deref(),
            session_fingerprint.as_deref(),
            &cached_sessions,
        )?)
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
        if ephemeral_connection {
            app.push_msg(MessageKind::Info, EPHEMERAL_MSG);
        }
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
    } else if !cached_sessions.is_empty() && !ephemeral_connection {
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
                                                app.push_msg(MessageKind::Info, "Press any key to exit");
                                                term.draw(|frame| app.draw(frame)).ok();
                                                wait_for_keypress(&mut reader).await;
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
                                                    app.push_msg(MessageKind::Info, "Press any key to exit");
                                                    term.draw(|frame| app.draw(frame)).ok();
                                                    wait_for_keypress(&mut reader).await;
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
                            if ephemeral_connection {
                                app.push_msg(MessageKind::Info, EPHEMERAL_MSG);
                            } else {
                                app.push_msg(MessageKind::Info, "Connection will be saved (use --ephemeral-connection to disable)");
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
                        app.push_msg(MessageKind::Info, "Press any key to exit");
                        term.draw(|frame| app.draw(frame))
                            .map_err(|e| color_eyre::eyre::eyre!("TUI draw error: {}", e))?;
                        wait_for_keypress(&mut reader).await;
                        break;
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
                    super::tui_tracing::push_log_entry(&mut app, entry);
                }
            }
        }
    }

    restore_terminal();

    if let Some(mut c) = client {
        println!("Closing connection...");
        c.close().await;
        println!("Connection closed. Goodbye!");
    }
    Ok(())
}

/// Run a single-shot credential request — no TUI, stdout/stderr only.
///
/// This is the agent/LLM-friendly code path. It never initializes ratatui,
/// prints structured output to stdout, status to stderr, and exits with a
/// well-defined exit code.
/// Connect to the proxy, fetch a single credential, and return it.
///
/// Shared by `run_single_shot` and the `run` subcommand. Returns the
/// credential on success, or an error that the caller can format/handle.
pub(super) async fn fetch_credential(
    proxy_url: &str,
    token: Option<&str>,
    session_fingerprint: Option<&str>,
    ephemeral_connection: bool,
    domain: &str,
) -> Result<ap_client::CredentialData> {
    let identity_provider: Box<dyn IdentityProvider> =
        Box::new(FileIdentityStorage::load_or_generate("remote_client")?);

    let session_store: Box<dyn SessionStore> = if ephemeral_connection {
        Box::new(MemorySessionStore::new())
    } else {
        Box::new(FileSessionCache::load_or_create("remote_client")?)
    };

    let cached_sessions = session_store.list_sessions();
    let mode = resolve_connection_mode(token, session_fingerprint, &cached_sessions)?;

    eprintln!("Connecting to proxy...");

    let (mut event_rx, _response_tx, mut client) =
        start_connection(identity_provider, session_store, proxy_url, &mode, false).await?;

    // Drain events in background (prevents channel backpressure)
    tokio::spawn(async move { while event_rx.recv().await.is_some() {} });

    eprintln!("Requesting credential for: {domain}");

    match client.request_credential(domain).await {
        Ok(credential) => {
            client.close().await;
            Ok(credential)
        }
        Err(e) => {
            client.close().await;
            Err(color_eyre::eyre::eyre!(e))
        }
    }
}

async fn run_single_shot(
    proxy_url: String,
    token: Option<String>,
    session_fingerprint: Option<String>,
    ephemeral_connection: bool,
    domain: String,
    output: OutputFormat,
) -> Result<()> {
    use super::output::{exit_code, exit_code_name};

    match fetch_credential(
        &proxy_url,
        token.as_deref(),
        session_fingerprint.as_deref(),
        ephemeral_connection,
        &domain,
    )
    .await
    {
        Ok(credential) => {
            match output {
                OutputFormat::Json => emit_json_success(&domain, &credential),
                OutputFormat::Text => emit_text_credential(&domain, &credential),
            }
            std::process::exit(exit_code::SUCCESS);
        }
        Err(e) => {
            // Try to extract a RemoteClientError for specific exit codes
            let code = e
                .downcast_ref::<ap_client::RemoteClientError>()
                .map(exit_code_for_error)
                .unwrap_or(exit_code::GENERAL_ERROR);
            let msg = format!("{e}");
            match output {
                OutputFormat::Json => emit_json_error(&msg, exit_code_name(code)),
                OutputFormat::Text => eprintln!("Error: {msg}"),
            }
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

    if code_normalized.len() != 9 {
        bail!("Rendezvous code must be 9 characters (e.g., ABCDEF123 or ABC-DEF-123)");
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

    let mut iter = cached_sessions
        .iter()
        .filter(|(fp, _, _, _)| hex::encode(fp.0).starts_with(&clean_prefix))
        .map(|(fp, _, _, _)| *fp);

    match (iter.next(), iter.next()) {
        (None, _) => bail!("No cached session matches prefix: {prefix}"),
        (Some(fp), None) => Ok(fp),
        (Some(_), Some(_)) => {
            bail!("Ambiguous session prefix '{prefix}' — provide more characters")
        }
    }
}

/// Determine the connection mode from CLI flags and cached sessions.
///
/// Pure decision logic — returns `Ok(mode)` or an error message instead of
/// calling `std::process::exit`, making it testable from both the single-shot
/// and interactive code paths.
fn resolve_connection_mode(
    token: Option<&str>,
    session_fingerprint: Option<&str>,
    cached_sessions: &[(IdentityFingerprint, Option<String>, u64, u64)],
) -> Result<ConnectionMode> {
    if session_fingerprint.is_some() && token.is_some() {
        bail!("--session and --token are mutually exclusive")
    } else if let Some(session_hex) = session_fingerprint {
        let fingerprint = resolve_session_prefix(session_hex, cached_sessions)?;
        Ok(ConnectionMode::Existing {
            remote_fingerprint: fingerprint,
        })
    } else if let Some(code_or_token) = token {
        match parse_token(code_or_token)? {
            TokenType::Rendezvous(code) => Ok(ConnectionMode::New {
                rendezvous_code: code,
            }),
            TokenType::Psk { psk, fingerprint } => Ok(ConnectionMode::NewPsk {
                psk,
                remote_fingerprint: fingerprint,
            }),
        }
    } else if cached_sessions.len() == 1 {
        let (fingerprint, _, _, _) = &cached_sessions[0];
        Ok(ConnectionMode::Existing {
            remote_fingerprint: *fingerprint,
        })
    } else if cached_sessions.is_empty() {
        bail!("No cached sessions found — provide --token to start a new connection")
    } else {
        bail!(
            "Multiple cached sessions found — specify one with --session. \
             Use `aac connections list` to see available sessions."
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an IdentityFingerprint from a repeating byte.
    fn fp(byte: u8) -> IdentityFingerprint {
        IdentityFingerprint([byte; 32])
    }

    /// Helper: build a minimal cached-session tuple.
    fn session(byte: u8) -> (IdentityFingerprint, Option<String>, u64, u64) {
        (fp(byte), None, 0, 0)
    }

    // ── resolve_connection_mode ─────────────────────────────────────

    #[test]
    fn resolve_mode_single_cached_session_auto_selects() {
        let sessions = vec![session(0xaa)];
        let mode = resolve_connection_mode(None, None, &sessions).expect("should succeed");
        assert!(matches!(
            mode,
            ConnectionMode::Existing {
                remote_fingerprint
            } if remote_fingerprint == fp(0xaa)
        ));
    }

    #[test]
    fn resolve_mode_no_cached_sessions_errors() {
        let result = resolve_connection_mode(None, None, &[]);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("No cached sessions found"));
    }

    #[test]
    fn resolve_mode_multiple_cached_sessions_errors() {
        let sessions = vec![session(0xaa), session(0xbb)];
        let result = resolve_connection_mode(None, None, &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("Multiple cached sessions found"));
    }

    #[test]
    fn resolve_mode_session_prefix_selects_existing() {
        let sessions = vec![session(0xaa), session(0xbb)];
        let prefix = &hex::encode([0xaa; 32])[..8]; // first 8 chars
        let mode = resolve_connection_mode(None, Some(prefix), &sessions).expect("should succeed");
        assert!(matches!(
            mode,
            ConnectionMode::Existing {
                remote_fingerprint
            } if remote_fingerprint == fp(0xaa)
        ));
    }

    #[test]
    fn resolve_mode_rendezvous_token() {
        let mode = resolve_connection_mode(Some("ABC123DEF"), None, &[]).expect("should succeed");
        assert!(
            matches!(mode, ConnectionMode::New { rendezvous_code } if rendezvous_code == "ABC123DEF")
        );
    }

    #[test]
    fn resolve_mode_psk_token() {
        let psk_hex = "aa".repeat(32);
        let fp_hex = "bb".repeat(32);
        let token = format!("{psk_hex}_{fp_hex}");
        let mode = resolve_connection_mode(Some(&token), None, &[]).expect("should succeed");
        assert!(matches!(
            mode,
            ConnectionMode::NewPsk {
                remote_fingerprint, ..
            } if remote_fingerprint == fp(0xbb)
        ));
    }

    #[test]
    fn resolve_mode_token_takes_priority_over_single_cached() {
        let sessions = vec![session(0xcc)];
        let mode =
            resolve_connection_mode(Some("XYZ789ABC"), None, &sessions).expect("should succeed");
        assert!(
            matches!(mode, ConnectionMode::New { rendezvous_code } if rendezvous_code == "XYZ789ABC")
        );
    }

    #[test]
    fn resolve_mode_session_and_token_both_provided_errors() {
        let sessions = vec![session(0xaa), session(0xbb)];
        let prefix = &hex::encode([0xaa; 32])[..8];
        let result = resolve_connection_mode(Some("ABC123DEF"), Some(prefix), &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("mutually exclusive"));
    }

    // ── resolve_session_prefix ──────────────────────────────────────

    #[test]
    fn prefix_exact_full_hex_match() {
        let sessions = vec![session(0xaa)];
        let full_hex = hex::encode([0xaa; 32]);
        let result = resolve_session_prefix(&full_hex, &sessions).expect("should match");
        assert_eq!(result, fp(0xaa));
    }

    #[test]
    fn prefix_unique_short_match() {
        let sessions = vec![session(0xaa), session(0xbb)];
        let result = resolve_session_prefix("aa", &sessions).expect("should match");
        assert_eq!(result, fp(0xaa));
    }

    #[test]
    fn prefix_ambiguous_errors() {
        // 0xaa and 0xab both start with 'a'
        let sessions = vec![session(0xaa), session(0xab)];
        let result = resolve_session_prefix("a", &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("Ambiguous"));
    }

    #[test]
    fn prefix_no_match_errors() {
        let sessions = vec![session(0xaa)];
        let result = resolve_session_prefix("ff", &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("No cached session"));
    }

    #[test]
    fn prefix_empty_errors() {
        let sessions = vec![session(0xaa)];
        let result = resolve_session_prefix("", &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("must not be empty"));
    }

    #[test]
    fn prefix_non_hex_errors() {
        let sessions = vec![session(0xaa)];
        let result = resolve_session_prefix("zzzz", &sessions);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("hex string"));
    }

    #[test]
    fn prefix_strips_separators() {
        let sessions = vec![session(0xaa)];
        // "aa:aa" should normalize to "aaaa" and match
        let result = resolve_session_prefix("aa:aa", &sessions).expect("should match");
        assert_eq!(result, fp(0xaa));
    }

    // ── parse_token ─────────────────────────────────────────────────

    #[test]
    fn parse_token_rendezvous_code() {
        let result = parse_token("ABC123DEF").expect("should parse");
        assert!(matches!(result, TokenType::Rendezvous(code) if code == "ABC123DEF"));
    }

    #[test]
    fn parse_token_psk_token() {
        let psk_hex = "aa".repeat(32);
        let fp_hex = "bb".repeat(32);
        let token = format!("{psk_hex}_{fp_hex}");
        let result = parse_token(&token).expect("should parse");
        assert!(matches!(result, TokenType::Psk { .. }));
    }

    #[test]
    fn parse_token_invalid_psk_format() {
        // Has underscore but wrong length
        let result = parse_token("abc_def");
        assert!(result.is_err());
    }

    // ── validate_rendezvous_code ────────────────────────────────────

    #[test]
    fn rendezvous_valid_plain() {
        assert!(validate_rendezvous_code("ABCDEF123").is_ok());
    }

    #[test]
    fn rendezvous_valid_with_hyphens() {
        assert!(validate_rendezvous_code("ABC-DEF-123").is_ok());
    }

    #[test]
    fn rendezvous_empty_errors() {
        let result = validate_rendezvous_code("");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("required"));
    }

    #[test]
    fn rendezvous_wrong_length_errors() {
        let result = validate_rendezvous_code("AB");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("9 characters"));
    }

    #[test]
    fn rendezvous_non_alphanumeric_errors() {
        let result = validate_rendezvous_code("ABCDEF!@#");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("letters and numbers"));
    }

    // ── parse_fingerprint_hex ───────────────────────────────────────

    #[test]
    fn fingerprint_valid_64_hex() {
        let hex_str = "aa".repeat(32);
        let result = parse_fingerprint_hex(&hex_str).expect("should parse");
        assert_eq!(result, fp(0xaa));
    }

    #[test]
    fn fingerprint_wrong_length_errors() {
        let result = parse_fingerprint_hex("aabb");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("64 hex characters"));
    }

    #[test]
    fn fingerprint_strips_separators() {
        // 64 hex chars with colons between byte pairs
        let with_colons: String = (0..32).map(|_| "aa").collect::<Vec<_>>().join(":");
        let result = parse_fingerprint_hex(&with_colons).expect("should parse");
        assert_eq!(result, fp(0xaa));
    }
}
