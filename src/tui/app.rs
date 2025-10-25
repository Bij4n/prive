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
