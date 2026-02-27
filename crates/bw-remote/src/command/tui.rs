//! Shared ratatui-based TUI for interactive CLI commands.
//!
//! Provides a message-log + input-panel layout with mode-based input handling.
//! Uses a fullscreen alternate-screen viewport managed entirely through ratatui.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

// ── Message types ──

/// Visual category for a message in the log panel.
#[derive(Clone, Copy)]
pub enum MessageKind {
    /// User-initiated action (e.g. credential request).
    User,
    /// Operational status / progress.
    Status,
    /// Successful completion.
    Success,
    /// Error or failure.
    Error,
    /// Prompt / request for user attention.
    Prompt,
    /// Informational text.
    Info,
    /// Animated listening indicator (dot pulses).
    Listening,
}

/// A styled message in the log panel.
#[derive(Clone)]
pub struct Message {
    pub kind: MessageKind,
    pub text: String,
    /// Optional rich spans that replace the plain text when present.
    pub spans: Option<Vec<Span<'static>>>,
}

impl Message {
    pub fn new(kind: MessageKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
            spans: None,
        }
    }

    /// Create a message with inline-styled spans for richer formatting.
    pub fn rich(kind: MessageKind, spans: Vec<Span<'static>>) -> Self {
        let text = spans.iter().map(|s| s.content.as_ref()).collect::<String>();
        Self {
            kind,
            text,
            spans: Some(spans),
        }
    }

    /// Convert to a styled ratatui `Line` for rendering.
    ///
    /// The `tick` parameter drives the pulse animation for `Listening` messages.
    pub fn to_line(&self, tick: u8) -> Line<'_> {
        let (prefix, prefix_style, text_style) = match self.kind {
            MessageKind::User => (
                "› ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
                Style::default().fg(Color::White),
            ),
            MessageKind::Status => (
                "● ",
                Style::default().fg(Color::Yellow),
                Style::default().fg(Color::White),
            ),
            MessageKind::Success => (
                "✓ ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
                Style::default().fg(Color::Green),
            ),
            MessageKind::Error => (
                "✗ ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            MessageKind::Prompt => (
                "▸ ",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            MessageKind::Info => (
                "  ",
                Style::default().fg(Color::DarkGray),
                Style::default().fg(Color::DarkGray),
            ),
            MessageKind::Listening => (
                "● ",
                Style::default().fg(pulse_color(tick)),
                Style::default().fg(Color::White),
            ),
        };
        let mut parts = vec![Span::styled(prefix, prefix_style)];
        if let Some(spans) = &self.spans {
            parts.extend(spans.iter().cloned());
        } else {
            parts.push(Span::styled(&self.text, text_style));
        }
        Line::from(parts)
    }
}

// ── Mode ──

/// Input mode determines the bottom panel's behaviour and appearance.
pub enum Mode {
    /// Free-form text input with cursor.
    TextInput,
    /// Yes/no confirmation prompt.
    Confirm {
        title: String,
        description: Line<'static>,
    },
    /// Arrow-key pick list.
    Pick {
        title: String,
        options: Vec<String>,
        selected: usize,
    },
}

// ── Actions returned to caller ──

/// Action emitted by `App::handle_key` for the caller to process.
pub enum AppAction {
    /// User pressed Enter with text content (TextInput mode).
    Submit(String),
    /// User answered a confirmation prompt (Confirm mode).
    Confirmed(bool),
    /// User selected an option from a pick list (Pick mode).
    Picked(usize),
    /// User requested quit (Ctrl+C or Esc).
    Quit,
}

// ── Animation ──

/// Brightness lookup table for the listening-dot pulse (20 frames, smooth triangle wave).
const PULSE: [u8; 20] = [
    30, 55, 85, 120, 155, 185, 210, 230, 245, 255, 255, 245, 230, 210, 185, 155, 120, 85, 55, 30,
];

/// Map a tick counter to a pulsing yellow/amber colour.
fn pulse_color(tick: u8) -> Color {
    let brightness = PULSE[(tick as usize) % PULSE.len()];
    Color::Rgb(brightness, brightness / 2, 0)
}

// ── App ──

/// Shared TUI application state.
pub struct App {
    pub messages: Vec<Message>,
    pub input: String,
    pub input_title: &'static str,
    pub mode: Mode,
    pub should_quit: bool,
    pub footer: Line<'static>,
    /// Available slash commands for the current phase (e.g. &["/exit", "/new"]).
    pub commands: &'static [&'static str],
    /// Authenticated account email (from `bw status`).
    pub account_name: Option<String>,
    /// Vault status spans for display in the header.
    pub vault_status: Option<Vec<Span<'static>>>,
    /// Label shown in the header subtitle (e.g. "Remote client" or "User client").
    pub client_label: &'static str,
    /// Persistent session-info panel rendered above the input area.
    pub session_panel: Vec<Message>,
    /// Index of the currently highlighted suggestion (None = no highlight).
    suggestion_idx: Option<usize>,
    scroll_offset: usize,
    tick: u8,
}

impl App {
    pub fn new() -> Self {
        Self {
            messages: vec![],
            input: String::new(),
            input_title: " Commands ",
            mode: Mode::TextInput,
            should_quit: false,
            footer: Line::from(""),
            commands: &[],
            client_label: "Remote client",
            account_name: None,
            vault_status: None,
            session_panel: Vec::new(),
            suggestion_idx: None,
            scroll_offset: 0,
            tick: 0,
        }
    }

    /// Append a message to the log and reset scroll to bottom.
    pub fn push_msg(&mut self, kind: MessageKind, text: impl Into<String>) {
        self.messages.push(Message::new(kind, text));
        self.scroll_offset = 0;
    }

    /// Append a rich (multi-span) message to the log.
    pub fn push_rich(&mut self, msg: Message) {
        self.messages.push(msg);
        self.scroll_offset = 0;
    }

    /// Switch the input mode and clear the input buffer.
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
        self.input.clear();
    }

    /// Replace the persistent session-info panel content.
    pub fn set_session_panel(&mut self, messages: Vec<Message>) {
        self.session_panel = messages;
    }

    /// Advance the animation tick (call periodically from the event loop).
    pub fn tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
    }

    /// Return the commands that match the current input prefix.
    fn filtered_commands(&self) -> Vec<&'static str> {
        if self.input.starts_with('/') {
            self.commands
                .iter()
                .filter(|cmd| cmd.starts_with(self.input.as_str()))
                .copied()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Recalculate `suggestion_idx` after an input change.
    fn update_suggestions(&mut self) {
        let matches = self.filtered_commands();
        if matches.is_empty() {
            self.suggestion_idx = None;
        } else {
            self.suggestion_idx = Some(0);
        }
    }

    /// Process a key event and return an optional action for the caller.
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<AppAction> {
        // Global keys
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                self.should_quit = true;
                return Some(AppAction::Quit);
            }
            (KeyCode::Esc, _) => {
                self.should_quit = true;
                return Some(AppAction::Quit);
            }
            (KeyCode::PageUp, _) => {
                self.scroll_offset = self.scroll_offset.saturating_add(5);
                return None;
            }
            (KeyCode::PageDown, _) => {
                self.scroll_offset = self.scroll_offset.saturating_sub(5);
                return None;
            }
            _ => {}
        }

        match &mut self.mode {
            Mode::TextInput => match key.code {
                KeyCode::Enter => {
                    let text = if let Some(idx) = self.suggestion_idx.take() {
                        let matches = self.filtered_commands();
                        if let Some(&cmd) = matches.get(idx) {
                            self.input.clear();
                            cmd.to_string()
                        } else {
                            std::mem::take(&mut self.input)
                        }
                    } else {
                        std::mem::take(&mut self.input)
                    };
                    if !text.is_empty() {
                        Some(AppAction::Submit(text))
                    } else {
                        None
                    }
                }
                KeyCode::Tab => {
                    if let Some(idx) = self.suggestion_idx {
                        let matches = self.filtered_commands();
                        if let Some(&cmd) = matches.get(idx) {
                            self.input = cmd.to_string();
                            self.suggestion_idx = None;
                        }
                    }
                    None
                }
                KeyCode::Up if self.suggestion_idx.is_some() => {
                    if let Some(idx) = self.suggestion_idx {
                        let count = self.filtered_commands().len();
                        if count > 0 {
                            self.suggestion_idx = Some(if idx == 0 { count - 1 } else { idx - 1 });
                        }
                    }
                    None
                }
                KeyCode::Down if self.suggestion_idx.is_some() => {
                    if let Some(idx) = self.suggestion_idx {
                        let count = self.filtered_commands().len();
                        if count > 0 {
                            self.suggestion_idx = Some((idx + 1) % count);
                        }
                    }
                    None
                }
                KeyCode::Backspace => {
                    self.input.pop();
                    self.update_suggestions();
                    None
                }
                KeyCode::Char(c) => {
                    self.input.push(c);
                    self.update_suggestions();
                    None
                }
                _ => None,
            },
            Mode::Confirm { .. } => match key.code {
                KeyCode::Char('y' | 'Y') => {
                    self.set_mode(Mode::TextInput);
                    Some(AppAction::Confirmed(true))
                }
                KeyCode::Char('n' | 'N') => {
                    self.set_mode(Mode::TextInput);
                    Some(AppAction::Confirmed(false))
                }
                _ => None,
            },
            Mode::Pick {
                options, selected, ..
            } => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    *selected = selected.saturating_sub(1);
                    None
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if *selected + 1 < options.len() {
                        *selected += 1;
                    }
                    None
                }
                KeyCode::Enter => {
                    let idx = *selected;
                    Some(AppAction::Picked(idx))
                }
                _ => None,
            },
        }
    }

    /// Render the full TUI layout into the given frame.
    pub fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();

        // Determine input panel height based on mode
        let input_height = match &self.mode {
            Mode::TextInput => 3,
            Mode::Confirm { .. } => 6,
            Mode::Pick { options, .. } => (options.len() as u16) + 2, // border + items
        };

        let filtered = self.filtered_commands();
        let suggestion_height = if filtered.is_empty() {
            0
        } else {
            filtered.len() as u16 + 2 // border + items
        };

        let session_panel_height = if self.session_panel.is_empty() {
            0
        } else {
            self.session_panel.len() as u16 + 2 // border + items
        };

        let chunks = Layout::vertical([
            Constraint::Length(5),                    // header (shield + title)
            Constraint::Length(1),                    // separator
            Constraint::Fill(1),                      // messages
            Constraint::Length(session_panel_height), // session info panel
            Constraint::Length(suggestion_height),    // suggestions (0 when hidden)
            Constraint::Length(input_height),         // input panel
            Constraint::Length(1),                    // footer
        ])
        .split(area);

        // ── Header ──
        self.draw_header(frame, chunks[0]);

        // ── Separator ──
        let sep_width = chunks[1].width as usize;
        let separator = Paragraph::new(Line::from(Span::styled(
            "─".repeat(sep_width),
            Style::default().fg(Color::Rgb(40, 40, 60)),
        )));
        frame.render_widget(separator, chunks[1]);

        // ── Messages panel ──
        self.draw_messages(frame, chunks[2]);

        // ── Session info panel ──
        if !self.session_panel.is_empty() {
            self.draw_session_panel(frame, chunks[3]);
        }

        // ── Suggestions panel ──
        if !filtered.is_empty() {
            self.draw_suggestions(frame, chunks[4], &filtered);
        }

        // ── Input panel ──
        self.draw_input(frame, chunks[5]);

        // ── Footer ──
        let footer =
            Paragraph::new(self.footer.clone()).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(footer, chunks[6]);
    }

    fn draw_header(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        const SHIELD: [&str; 5] = ["⣿⠛⠛⠛⠛⠛⣿", "⣿⠀⠀⠀⠀⠀⣿", "⢻⠀⠀⠀⠀⢠⡟", "⠀⠻⣤⣤⣤⠟⠀", "⠀⠀⠈⠛⠁⠀⠀"];
        const SHIELD_WIDTH: u16 = 8;

        let hchunks =
            Layout::horizontal([Constraint::Length(SHIELD_WIDTH), Constraint::Fill(1)]).split(area);

        // Shield rendered in Bitwarden blue
        let bw_blue = Color::Rgb(23, 93, 220);
        let shield_lines: Vec<Line<'_>> = SHIELD
            .iter()
            .map(|row| {
                Line::from(Span::styled(
                    *row,
                    Style::default().fg(bw_blue).add_modifier(Modifier::BOLD),
                ))
            })
            .collect();
        frame.render_widget(Paragraph::new(shield_lines), hchunks[0]);

        // Title text (5 lines to match shield height)
        let account_line = match self.account_name {
            Some(ref email) => Line::from(Span::styled(
                email.clone(),
                Style::default().fg(Color::DarkGray),
            )),
            None => Line::from(""),
        };

        let status_line = match self.vault_status {
            Some(ref spans) => Line::from(spans.clone()),
            None => Line::from(""),
        };

        let title_lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "Bitwarden Remote Access",
                    Style::default().fg(bw_blue).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(" v{}", env!("CARGO_PKG_VERSION")),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(Span::styled(
                self.client_label,
                Style::default().fg(Color::DarkGray),
            )),
            account_line,
            status_line,
        ];
        frame.render_widget(Paragraph::new(title_lines), hchunks[1]);
    }

    fn draw_messages(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let tick = self.tick;
        let lines: Vec<Line<'_>> = self.messages.iter().map(|m| m.to_line(tick)).collect();

        let inner_height = area.height as usize;
        let total_lines = lines.len();

        // Clamp scroll offset
        if total_lines > inner_height {
            let max_scroll = total_lines - inner_height;
            if self.scroll_offset > max_scroll {
                self.scroll_offset = max_scroll;
            }
        } else {
            self.scroll_offset = 0;
        }

        // scroll_offset=0 means "show the bottom" (most recent)
        let scroll_from_top = if total_lines > inner_height {
            total_lines - inner_height - self.scroll_offset
        } else {
            0
        };

        let messages = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll_from_top as u16, 0));

        frame.render_widget(messages, area);
    }

    fn draw_session_panel(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let tick = self.tick;
        let lines: Vec<Line<'_>> = self.session_panel.iter().map(|m| m.to_line(tick)).collect();
        let widget = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(40, 40, 60)))
                .title(" Sessions "),
        );
        frame.render_widget(widget, area);
    }

    fn draw_input(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        match &self.mode {
            Mode::TextInput => {
                let input_line = Line::from(vec![
                    Span::styled("> ", Style::default().fg(Color::Cyan)),
                    Span::raw(&self.input),
                    Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
                ]);
                let input_widget = Paragraph::new(input_line).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(self.input_title),
                );
                frame.render_widget(input_widget, area);
            }
            Mode::Confirm { title, description } => {
                let lines = vec![
                    Line::from(Span::styled(
                        title.as_str(),
                        Style::default().add_modifier(Modifier::BOLD),
                    )),
                    description.clone(),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled(
                            "[y]",
                            Style::default()
                                .fg(Color::Green)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(" Yes  "),
                        Span::styled(
                            "[n]",
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(" No"),
                    ]),
                ];
                let confirm_widget = Paragraph::new(lines)
                    .block(Block::default().borders(Borders::ALL).title(" Confirm "));
                frame.render_widget(confirm_widget, area);
            }
            Mode::Pick {
                title,
                options,
                selected,
            } => {
                let lines: Vec<Line<'_>> = options
                    .iter()
                    .enumerate()
                    .map(|(i, label)| {
                        if i == *selected {
                            Line::from(vec![
                                Span::styled(
                                    " ❯ ",
                                    Style::default()
                                        .fg(Color::Cyan)
                                        .add_modifier(Modifier::BOLD),
                                ),
                                Span::styled(
                                    label.as_str(),
                                    Style::default()
                                        .fg(Color::Cyan)
                                        .add_modifier(Modifier::BOLD),
                                ),
                            ])
                        } else {
                            Line::from(vec![
                                Span::raw("   "),
                                Span::styled(label.as_str(), Style::default().fg(Color::White)),
                            ])
                        }
                    })
                    .collect();
                let pick_widget = Paragraph::new(lines).block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" {} ", title)),
                );
                frame.render_widget(pick_widget, area);
            }
        }
    }

    fn draw_suggestions(&self, frame: &mut Frame, area: ratatui::layout::Rect, filtered: &[&str]) {
        let lines: Vec<Line<'_>> = filtered
            .iter()
            .enumerate()
            .map(|(i, cmd)| {
                if self.suggestion_idx == Some(i) {
                    Line::from(vec![
                        Span::styled(
                            " ❯ ",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            *cmd,
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                    ])
                } else {
                    Line::from(vec![
                        Span::raw("   "),
                        Span::styled(*cmd, Style::default().add_modifier(Modifier::DIM)),
                    ])
                }
            })
            .collect();
        let widget = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Suggestions "),
        );
        frame.render_widget(widget, area);
    }
}

// ── Terminal helpers ──

/// Initialise a fullscreen alternate-screen terminal via ratatui.
///
/// Uses `ratatui::init()` which handles raw mode, alternate screen, and
/// backend setup — no direct crossterm terminal calls needed.
pub fn init_terminal() -> DefaultTerminal {
    ratatui::init()
}

/// Restore the terminal to its original state.
pub fn restore_terminal() {
    ratatui::restore();
}
