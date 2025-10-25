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
