use std::io::{self, Stdout};
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};

use crate::vault::model::{Vault, VaultEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
    Detail,
}

pub struct App {
    entries: Vec<VaultEntry>,
    filtered_indices: Vec<usize>,
    table_state: TableState,
    search_query: String,
    mode: Mode,
    show_password: bool,
    should_quit: bool,
    status_message: Option<String>,
}

impl App {
    pub fn new(vault: &Vault) -> Self {
        let entries: Vec<VaultEntry> = vault.entries.clone();
        let filtered_indices: Vec<usize> = (0..entries.len()).collect();
        let mut table_state = TableState::default();
        if !filtered_indices.is_empty() {
            table_state.select(Some(0));
        }
        Self {
            entries,
            filtered_indices,
            table_state,
            search_query: String::new(),
            mode: Mode::Normal,
            show_password: false,
            should_quit: false,
            status_message: None,
        }
    }

    pub fn run(&mut self) -> Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let result = self.main_loop(&mut terminal);

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        if let Some(msg) = &self.status_message {
            eprintln!("{}", msg);
        }

        result
    }

    fn main_loop(&mut self, terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
        loop {
            terminal.draw(|f| self.draw(f))?;

            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    // Only handle key press events (not release/repeat)
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    self.handle_key(key.code, key.modifiers);
                }
            }

            if self.should_quit {
                return Ok(());
            }
        }
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) {
        match self.mode {
            Mode::Search => self.handle_search_key(code, modifiers),
            Mode::Normal => self.handle_normal_key(code),
            Mode::Detail => self.handle_detail_key(code),
        }
    }

    fn handle_search_key(&mut self, code: KeyCode, _modifiers: KeyModifiers) {
        match code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
            }
            KeyCode::Enter => {
                self.mode = Mode::Normal;
            }
            KeyCode::Backspace => {
                self.search_query.pop();
                self.apply_filter();
            }
            KeyCode::Char(c) => {
                self.search_query.push(c);
                self.apply_filter();
            }
            _ => {}
        }
    }

    fn handle_normal_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Char('/') => {
                self.mode = Mode::Search;
            }
            KeyCode::Char('a') => {
                self.status_message =
                    Some("Use `prive vault add <name>` to add entries.".to_string());
                self.should_quit = true;
            }
            KeyCode::Char('d') => {
                if let Some(entry) = self.selected_entry() {
                    self.status_message = Some(format!(
                        "Use `prive vault delete {}` to delete this entry.",
                        entry.name
                    ));
                    self.should_quit = true;
                }
            }
            KeyCode::Char('p') => {
                self.show_password = !self.show_password;
            }
            KeyCode::Enter => {
                if let Some(entry) = self.selected_entry() {
                    let pw = entry.password.clone();
                    match copy_to_clipboard(&pw) {
                        Ok(()) => {
                            self.status_message =
                                Some("Password copied to clipboard.".to_string());
                        }
                        Err(e) => {
                            self.status_message =
                                Some(format!("Clipboard error: {}", e));
                        }
                    }
                    self.should_quit = true;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
            }
            KeyCode::Tab => {
                if !self.filtered_indices.is_empty() {
                    self.mode = Mode::Detail;
                    self.show_password = false;
                }
            }
            KeyCode::Esc => {
                if !self.search_query.is_empty() {
                    self.search_query.clear();
                    self.apply_filter();
                }
            }
            _ => {}
        }
    }

    fn handle_detail_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc | KeyCode::Tab => {
                self.mode = Mode::Normal;
                self.show_password = false;
            }
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Char('p') => {
                self.show_password = !self.show_password;
            }
            KeyCode::Enter => {
                if let Some(entry) = self.selected_entry() {
                    let pw = entry.password.clone();
                    match copy_to_clipboard(&pw) {
                        Ok(()) => {
                            self.status_message =
                                Some("Password copied to clipboard.".to_string());
                        }
                        Err(e) => {
                            self.status_message =
                                Some(format!("Clipboard error: {}", e));
                        }
                    }
                    self.should_quit = true;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
            }
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: i32) {
        if self.filtered_indices.is_empty() {
            return;
        }
        let current = self.table_state.selected().unwrap_or(0) as i32;
        let len = self.filtered_indices.len() as i32;
        let next = (current + delta).rem_euclid(len) as usize;
        self.table_state.select(Some(next));
        self.show_password = false;
    }

    fn selected_entry(&self) -> Option<&VaultEntry> {
        let selected = self.table_state.selected()?;
        let &idx = self.filtered_indices.get(selected)?;
        self.entries.get(idx)
    }

    fn apply_filter(&mut self) {
        if self.search_query.is_empty() {
            self.filtered_indices = (0..self.entries.len()).collect();
        } else {
            let matcher = SkimMatcherV2::default();
            let mut scored: Vec<(usize, i64)> = self
                .entries
                .iter()
                .enumerate()
                .filter_map(|(i, entry)| {
                    let haystack = format!(
                        "{} {} {} {}",
                        entry.name,
                        entry.username.as_deref().unwrap_or(""),
                        entry.url.as_deref().unwrap_or(""),
                        entry.tags.join(" "),
                    );
                    matcher
                        .fuzzy_match(&haystack, &self.search_query)
                        .map(|score| (i, score))
                })
                .collect();
            scored.sort_by(|a, b| b.1.cmp(&a.1));
            self.filtered_indices = scored.into_iter().map(|(i, _)| i).collect();
        }

        if self.filtered_indices.is_empty() {
            self.table_state.select(None);
        } else {
            self.table_state.select(Some(0));
        }
    }

    // ── Drawing ──────────────────────────────────────────────────────

    fn draw(&mut self, f: &mut Frame) {
        let size = f.area();

        // Main vertical layout: body + status bar
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(3)])
            .split(size);

        let body_area = outer[0];
        let status_area = outer[1];

        // If in Detail mode and wide enough, split body horizontally
        if self.mode == Mode::Detail && body_area.width > 60 {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(body_area);
            self.draw_table(f, cols[0]);
            self.draw_detail_panel(f, cols[1]);
        } else if self.mode == Mode::Detail {
            // Narrow terminal: overlay detail
            self.draw_table(f, body_area);
            let detail_area = centered_rect(80, 70, body_area);
            f.render_widget(Clear, detail_area);
            self.draw_detail_panel(f, detail_area);
        } else {
            self.draw_table(f, body_area);
        }

        self.draw_status_bar(f, status_area);

        // Search input overlay
        if self.mode == Mode::Search {
            let search_area = Rect {
                x: status_area.x,
                y: status_area.y,
                width: status_area.width,
                height: status_area.height,
            };
            let search_text = format!("/ {}", self.search_query);
            let search_widget = Paragraph::new(search_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Search ")
                    .border_style(Style::default().fg(Color::Yellow)),
            );
            f.render_widget(search_widget, search_area);
        }
    }

    fn draw_table(&mut self, f: &mut Frame, area: Rect) {
        let header_cells = ["Name", "Username", "URL", "Tags"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        let header = Row::new(header_cells).height(1);

        let rows: Vec<Row> = self
            .filtered_indices
            .iter()
            .map(|&i| {
                let entry = &self.entries[i];
                let cells = vec![
                    Cell::from(entry.name.clone()),
                    Cell::from(
                        entry
                            .username
                            .as_deref()
                            .unwrap_or("-")
                            .to_string(),
                    ),
                    Cell::from(
                        entry.url.as_deref().unwrap_or("-").to_string(),
                    ),
                    Cell::from(entry.tags.join(", ")),
                ];
                Row::new(cells)
            })
            .collect();

        let widths = [
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(30),
            Constraint::Percentage(20),
        ];

        let title = if self.search_query.is_empty() {
            " Vault Entries ".to_string()
        } else {
            format!(" Vault Entries (filter: {}) ", self.search_query)
        };

        let table = Table::new(rows, widths)
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title),
            )
            .row_highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");

        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn draw_detail_panel(&self, f: &mut Frame, area: Rect) {
        let entry = match self.selected_entry() {
            Some(e) => e,
            None => {
                let empty = Paragraph::new("No entry selected.").block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Details "),
                );
                f.render_widget(empty, area);
                return;
            }
        };

        let password_display = if self.show_password {
            entry.password.clone()
        } else {
            "********".to_string()
        };

        let lines = vec![
            Line::from(vec![
                Span::styled("Name:     ", Style::default().fg(Color::Yellow)),
                Span::raw(&entry.name),
            ]),
            Line::from(vec![
                Span::styled("Username: ", Style::default().fg(Color::Yellow)),
                Span::raw(entry.username.as_deref().unwrap_or("-")),
            ]),
            Line::from(vec![
                Span::styled("Password: ", Style::default().fg(Color::Yellow)),
                Span::raw(&password_display),
            ]),
            Line::from(vec![
                Span::styled("URL:      ", Style::default().fg(Color::Yellow)),
                Span::raw(entry.url.as_deref().unwrap_or("-")),
            ]),
            Line::from(vec![
                Span::styled("Notes:    ", Style::default().fg(Color::Yellow)),
                Span::raw(entry.notes.as_deref().unwrap_or("-")),
            ]),
            Line::from(vec![
                Span::styled("Tags:     ", Style::default().fg(Color::Yellow)),
                Span::raw(entry.tags.join(", ")),
            ]),
            Line::from(vec![
                Span::styled("TOTP:     ", Style::default().fg(Color::Yellow)),
                Span::raw(if entry.totp_secret.is_some() {
                    "configured"
                } else {
                    "-"
                }),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Created:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    entry.created_at.format("%Y-%m-%d %H:%M").to_string(),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::styled("Modified: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    entry.modified_at.format("%Y-%m-%d %H:%M").to_string(),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
        ];

        let toggle_hint = if self.show_password {
            "p=hide password"
        } else {
            "p=reveal password"
        };
        let title = format!(" Details [{}] ", toggle_hint);

        let detail = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::Cyan)),
        );
        f.render_widget(detail, area);
    }

    fn draw_status_bar(&self, f: &mut Frame, area: Rect) {
        let total = self.entries.len();
        let shown = self.filtered_indices.len();

        let count_info = if self.search_query.is_empty() {
            format!("{} entries", total)
        } else {
            format!("{}/{} entries", shown, total)
        };

        let mode_label = match self.mode {
            Mode::Normal => "NORMAL",
            Mode::Search => "SEARCH",
            Mode::Detail => "DETAIL",
        };

        let keys = match self.mode {
            Mode::Normal => "q=quit /=search Enter=copy j/k=move Tab=detail p=show a=add d=del",
            Mode::Search => "Esc=cancel Enter=confirm",
            Mode::Detail => "Esc/Tab=back q=quit Enter=copy p=toggle j/k=move",
        };

        let status_line = Line::from(vec![
            Span::styled(
                format!(" {} ", mode_label),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(count_info, Style::default().fg(Color::White)),
            Span::raw("  "),
            Span::styled(keys, Style::default().fg(Color::DarkGray)),
        ]);

        let status = Paragraph::new(status_line).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(status, area);
    }
}

/// Helper to create a centered rectangle within `r`.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| format!("Failed to access clipboard: {}", e))?;
    clipboard
        .set_text(text.to_string())
        .map_err(|e| format!("Failed to copy: {}", e))
}
