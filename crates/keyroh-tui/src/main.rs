use anyhow::{Result, anyhow};
use chrono::Utc;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap},
};
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use keyroh_core::manager::VaultManager;
use keyroh_core::vault::{CustomField, VaultItem};

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppState {
    PasswordPrompt,
    NotInitialized,
    Browse,
    AddForm,
    EditForm,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FormField {
    Name,
    Username,
    Password,
    Url,
    Totp,
    FolderId,
    Favorite,
    Notes,
}

impl FormField {
    fn name(&self) -> &'static str {
        match self {
            FormField::Name => "Item Name *",
            FormField::Username => "Username",
            FormField::Password => "Password",
            FormField::Url => "Login URL",
            FormField::Totp => "TOTP Secret (Base32)",
            FormField::FolderId => "Folder ID",
            FormField::Favorite => "Favorite (y/n)",
            FormField::Notes => "Notes",
        }
    }

    fn next(&self) -> Self {
        match self {
            FormField::Name => FormField::Username,
            FormField::Username => FormField::Password,
            FormField::Password => FormField::Url,
            FormField::Url => FormField::Totp,
            FormField::Totp => FormField::FolderId,
            FormField::FolderId => FormField::Favorite,
            FormField::Favorite => FormField::Notes,
            FormField::Notes => FormField::Name,
        }
    }

    fn prev(&self) -> Self {
        match self {
            FormField::Name => FormField::Notes,
            FormField::Username => FormField::Name,
            FormField::Password => FormField::Username,
            FormField::Url => FormField::Password,
            FormField::Totp => FormField::Url,
            FormField::FolderId => FormField::Totp,
            FormField::Favorite => FormField::FolderId,
            FormField::Notes => FormField::Favorite,
        }
    }
}

struct FormState {
    name: String,
    username: String,
    password: String,
    url: String,
    totp: String,
    folder_id: String,
    favorite: String,
    notes: String,
    active_field: FormField,
}

impl FormState {
    fn new() -> Self {
        Self {
            name: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            totp: String::new(),
            folder_id: String::new(),
            favorite: "n".to_string(),
            notes: String::new(),
            active_field: FormField::Name,
        }
    }

    fn from_item(item: &VaultItem) -> Self {
        let (username, password, url, totp) = if let Some(ref login) = item.login {
            (
                login.username.clone().unwrap_or_default(),
                login.password.clone().unwrap_or_default(),
                login.uris.first().clone().cloned().unwrap_or_default(),
                login.totp.clone().unwrap_or_default(),
            )
        } else {
            (String::new(), String::new(), String::new(), String::new())
        };

        Self {
            name: item.name.clone(),
            username,
            password,
            url,
            totp,
            folder_id: item.folder_id.clone().unwrap_or_default(),
            favorite: if item.favorite {
                "y".into()
            } else {
                "n".into()
            },
            notes: item.notes.clone().unwrap_or_default(),
            active_field: FormField::Name,
        }
    }
}

struct App {
    manager: VaultManager,
    state: AppState,
    password_input: String,
    password_confirm: String,
    auth_error: Option<String>,

    // Browsing list state
    items: Vec<VaultItem>,
    list_state: ListState,
    search_query: String,
    search_focused: bool,
    show_password: bool,

    // Add/Edit state
    form: FormState,
    editing_item_id: Option<String>,

    // Auto-refresh timer
    last_refresh: Instant,
}

fn get_vault_dir() -> PathBuf {
    let mut path = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap());
    path.push(".config");
    path.push("keyroh");
    path
}

impl App {
    fn new() -> Result<Self> {
        let vault_dir = get_vault_dir();
        let manager = VaultManager::open(&vault_dir)?;
        let state = if manager.is_initialized()? {
            AppState::PasswordPrompt
        } else {
            AppState::NotInitialized
        };

        Ok(Self {
            manager,
            state,
            password_input: String::new(),
            password_confirm: String::new(),
            auth_error: None,
            items: Vec::new(),
            list_state: ListState::default(),
            search_query: String::new(),
            search_focused: false,
            show_password: false,
            form: FormState::new(),
            editing_item_id: None,
            last_refresh: Instant::now(),
        })
    }

    fn update_items_list(&mut self) -> Result<()> {
        let mut list = if self.search_query.trim().is_empty() {
            self.manager.list_items()?
        } else {
            self.manager.search_items(&self.search_query)?
        };

        // Sort items: favorites first, then by name
        list.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        self.items = list;

        // Fix index if it goes out of bounds
        let len = self.items.len();
        if len == 0 {
            self.list_state.select(None);
        } else {
            match self.list_state.selected() {
                Some(idx) if idx >= len => self.list_state.select(Some(len - 1)),
                None => self.list_state.select(Some(0)),
                _ => {}
            }
        }
        Ok(())
    }

    fn selected_item(&self) -> Option<&VaultItem> {
        let idx = self.list_state.selected()?;
        self.items.get(idx)
    }

    async fn handle_save_form(&mut self) -> Result<()> {
        if self.form.name.trim().is_empty() {
            return Err(anyhow!("Item Name is required"));
        }

        let name = self.form.name.clone();
        let username = Some(self.form.username.clone()).filter(|s| !s.trim().is_empty());
        let password = Some(self.form.password.clone()).filter(|s| !s.trim().is_empty());
        let totp = Some(self.form.totp.clone()).filter(|s| !s.trim().is_empty());
        let notes = Some(self.form.notes.clone()).filter(|s| !s.trim().is_empty());
        let uris = if self.form.url.trim().is_empty() {
            vec![]
        } else {
            vec![self.form.url.clone()]
        };
        let favorite = self.form.favorite.to_lowercase().starts_with('y');
        let folder_id = Some(self.form.folder_id.clone()).filter(|s| !s.trim().is_empty());

        if let Some(id) = self.editing_item_id.clone() {
            // Edit existing
            self.manager
                .edit_item(
                    id,
                    name,
                    username,
                    password,
                    totp,
                    notes,
                    uris,
                    favorite,
                    vec![], // preserve/clear custom fields for simplicity in TUI form
                    folder_id,
                )
                .await?;
        } else {
            // Add new
            self.manager
                .add_item(
                    name,
                    username,
                    password,
                    totp,
                    notes,
                    uris,
                    favorite,
                    vec![],
                    folder_id,
                )
                .await?;
        }

        self.state = AppState::Browse;
        self.editing_item_id = None;
        self.update_items_list()?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = App::new()?;

    // Main run loop
    let res = run_app(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("\x1b[31mError running TUI: {}\x1b[0m", err);
    }

    Ok(())
}

async fn run_app(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    let tick_rate = Duration::from_millis(250);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui(f, app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == event::KeyEventKind::Press {
                    if handle_key_event(app, key).await? {
                        return Ok(()); // Quit requested
                    }
                }
            }
        }

        // Periodic database refresh & ticks
        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();

            // Auto refresh from disk every 5 seconds if browse screen is open
            if app.state == AppState::Browse && app.last_refresh.elapsed() >= Duration::from_secs(5)
            {
                let _ = app.manager.refresh_items();
                let _ = app.update_items_list();
                app.last_refresh = Instant::now();
            }
        }
    }
}

async fn handle_key_event(app: &mut App, key: KeyEvent) -> Result<bool> {
    match app.state {
        AppState::NotInitialized => {
            // Typing to initialize password
            match key.code {
                KeyCode::Char(c) => {
                    if app.password_input.is_empty() {
                        // Enter master password
                        app.password_input.push(c);
                    } else if app.password_confirm.len() < app.password_input.len()
                        || app.password_confirm.is_empty()
                    {
                        // If we are inputting confirm (state transition by Enter)
                        // Actually let's use a simpler prompt state or split inputs
                        app.password_input.push(c);
                    }
                }
                KeyCode::Backspace => {
                    app.password_input.pop();
                }
                KeyCode::Enter => {
                    if app.password_input.len() < 8 {
                        app.auth_error = Some("Password must be at least 8 characters".into());
                    } else {
                        app.manager.init(&app.password_input)?;
                        app.password_input.clear();
                        app.auth_error = None;
                        app.state = AppState::PasswordPrompt;
                    }
                }
                KeyCode::Esc => return Ok(true), // Quit
                _ => {}
            }
        }
        AppState::PasswordPrompt => {
            // Typing password to unlock
            match key.code {
                KeyCode::Char(c) => {
                    app.password_input.push(c);
                }
                KeyCode::Backspace => {
                    app.password_input.pop();
                }
                KeyCode::Enter => match app.manager.unlock(&app.password_input) {
                    Ok(_) => {
                        app.password_input.clear();
                        app.auth_error = None;
                        app.state = AppState::Browse;
                        app.update_items_list()?;
                    }
                    Err(_) => {
                        app.auth_error = Some("Incorrect master password!".into());
                        app.password_input.clear();
                    }
                },
                KeyCode::Esc => return Ok(true), // Quit
                _ => {}
            }
        }
        AppState::Browse => {
            if app.search_focused {
                match key.code {
                    KeyCode::Char(c) => {
                        app.search_query.push(c);
                        app.update_items_list()?;
                    }
                    KeyCode::Backspace => {
                        app.search_query.pop();
                        app.update_items_list()?;
                    }
                    KeyCode::Esc | KeyCode::Enter => {
                        app.search_focused = false;
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') => return Ok(true),
                    KeyCode::Char('/') => {
                        app.search_focused = true;
                    }
                    KeyCode::Char('p') => {
                        app.show_password = !app.show_password;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = match app.list_state.selected() {
                            Some(i) => {
                                if i >= app.items.len() - 1 {
                                    0
                                } else {
                                    i + 1
                                }
                            }
                            None => 0,
                        };
                        if !app.items.is_empty() {
                            app.list_state.select(Some(i));
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = match app.list_state.selected() {
                            Some(i) => {
                                if i == 0 {
                                    app.items.len() - 1
                                } else {
                                    i - 1
                                }
                            }
                            None => 0,
                        };
                        if !app.items.is_empty() {
                            app.list_state.select(Some(i));
                        }
                    }
                    KeyCode::Char('f') => {
                        // Toggle favorite status
                        let item_to_fav = app.selected_item().cloned();
                        if let Some(item) = item_to_fav {
                            let id = item.id.clone();
                            let name = item.name.clone();
                            let favorite = !item.favorite;
                            let notes = item.notes.clone();
                            let folder_id = item.folder_id.clone();
                            let (username, password, totp, uris) = if let Some(ref l) = item.login {
                                (
                                    l.username.clone(),
                                    l.password.clone(),
                                    l.totp.clone(),
                                    l.uris.clone(),
                                )
                            } else {
                                (None, None, None, vec![])
                            };
                            let fields = item.fields.clone();
                            app.manager
                                .edit_item(
                                    id, name, username, password, totp, notes, uris, favorite,
                                    fields, folder_id,
                                )
                                .await?;
                            app.update_items_list()?;
                        }
                    }
                    KeyCode::Char('a') => {
                        app.form = FormState::new();
                        app.editing_item_id = None;
                        app.state = AppState::AddForm;
                    }
                    KeyCode::Char('e') => {
                        let item_to_edit = app.selected_item().cloned();
                        if let Some(item) = item_to_edit {
                            app.form = FormState::from_item(&item);
                            app.editing_item_id = Some(item.id.clone());
                            app.state = AppState::EditForm;
                        }
                    }
                    KeyCode::Char('d') => {
                        let id_to_delete = app.selected_item().map(|item| item.id.clone());
                        if let Some(id) = id_to_delete {
                            app.manager.delete_item(&id).await?;
                            app.update_items_list()?;
                        }
                    }
                    _ => {}
                }
            }
        }
        AppState::AddForm | AppState::EditForm => {
            match key.code {
                KeyCode::Esc => {
                    app.state = AppState::Browse;
                    app.editing_item_id = None;
                }
                KeyCode::Tab => {
                    app.form.active_field = app.form.active_field.next();
                }
                KeyCode::BackTab => {
                    app.form.active_field = app.form.active_field.prev();
                }
                KeyCode::Enter
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        || app.form.active_field == FormField::Notes =>
                {
                    // Control+Enter or Enter on Notes saves
                    if let Err(err) = app.handle_save_form().await {
                        app.auth_error = Some(err.to_string());
                    } else {
                        app.auth_error = None;
                    }
                }
                KeyCode::Enter if app.form.active_field != FormField::Notes => {
                    // Enter moves to next field
                    app.form.active_field = app.form.active_field.next();
                }
                KeyCode::Backspace => {
                    let field = match app.form.active_field {
                        FormField::Name => &mut app.form.name,
                        FormField::Username => &mut app.form.username,
                        FormField::Password => &mut app.form.password,
                        FormField::Url => &mut app.form.url,
                        FormField::Totp => &mut app.form.totp,
                        FormField::FolderId => &mut app.form.folder_id,
                        FormField::Favorite => &mut app.form.favorite,
                        FormField::Notes => &mut app.form.notes,
                    };
                    field.pop();
                }
                KeyCode::Char(c) => {
                    let field = match app.form.active_field {
                        FormField::Name => &mut app.form.name,
                        FormField::Username => &mut app.form.username,
                        FormField::Password => &mut app.form.password,
                        FormField::Url => &mut app.form.url,
                        FormField::Totp => &mut app.form.totp,
                        FormField::FolderId => &mut app.form.folder_id,
                        FormField::Favorite => &mut app.form.favorite,
                        FormField::Notes => &mut app.form.notes,
                    };
                    field.push(c);
                }
                _ => {}
            }
        }
    }
    Ok(false)
}

fn ui(f: &mut ratatui::Frame, app: &mut App) {
    let size = f.size();

    // Master layout: Header (3 rows), Main Content, Footer (1 row)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(size);

    // Draw Header
    let status_str = match app.state {
        AppState::NotInitialized => "NOT INITIALIZED".to_string(),
        AppState::PasswordPrompt => "LOCKED".to_string(),
        _ => "UNLOCKED".to_string(),
    };

    let header_text = vec![Line::from(vec![
        Span::styled(
            " Keyroh Password Manager ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" [{}]", status_str),
            Style::default().fg(if status_str == "UNLOCKED" {
                Color::Green
            } else {
                Color::Red
            }),
        ),
    ])];
    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(header, chunks[0]);

    // Draw Main Content based on app state
    match app.state {
        AppState::NotInitialized => {
            draw_init_screen(f, chunks[1], app);
        }
        AppState::PasswordPrompt => {
            draw_lock_screen(f, chunks[1], app);
        }
        AppState::Browse => {
            draw_browse_screen(f, chunks[1], app);
        }
        AppState::AddForm | AppState::EditForm => {
            draw_form_screen(f, chunks[1], app);
        }
    }

    // Draw Footer (shortcuts)
    let footer_text = match app.state {
        AppState::NotInitialized | AppState::PasswordPrompt => {
            " [Enter] Confirm / Unlock  |  [Esc] Quit"
        }
        AppState::Browse => {
            " [Esc] Reset  |  [/] Search  |  [j/k] Navigate  |  [a] Add  |  [e] Edit  |  [d] Delete  |  [f] Toggle Favorite  |  [p] Toggle Secret  |  [q] Quit"
        }
        AppState::AddForm | AppState::EditForm => {
            " [Tab/Shift-Tab] Switch Field  |  [Ctrl+Enter] Save  |  [Esc] Cancel"
        }
    };
    let footer = Paragraph::new(Span::styled(
        footer_text,
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(footer, chunks[2]);
}

fn draw_init_screen(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Initialize Vault ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let content_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .split(block.inner(area));

    f.render_widget(block, area);

    let intro = Paragraph::new(
        "Welcome to Keyroh! Please create a master password to initialize your secure vault.\nPassword should be at least 8 characters long.",
    );
    f.render_widget(intro, content_chunks[0]);

    // Password input
    let password_stars: String = "*".repeat(app.password_input.len());
    let password_box = Paragraph::new(password_stars).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Enter Master Password "),
    );
    f.render_widget(password_box, content_chunks[1]);

    if let Some(ref err) = app.auth_error {
        let error_para = Paragraph::new(Span::styled(err, Style::default().fg(Color::Red)));
        f.render_widget(error_para, content_chunks[2]);
    }
}

fn draw_lock_screen(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Unlock Keyroh Vault ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(1),
        ])
        .split(block.inner(area));

    f.render_widget(block, area);

    let prompt = Paragraph::new("Your vault is encrypted. Enter your master password to unlock.");
    f.render_widget(prompt, inner_layout[0]);

    // Password Input Box
    let password_stars: String = "*".repeat(app.password_input.len());
    let password_box = Paragraph::new(password_stars)
        .block(Block::default().borders(Borders::ALL).title(" Password "));
    f.render_widget(password_box, inner_layout[1]);

    if let Some(ref err) = app.auth_error {
        let error_para = Paragraph::new(Span::styled(err, Style::default().fg(Color::Red)));
        f.render_widget(error_para, inner_layout[2]);
    }
}

fn draw_browse_screen(f: &mut ratatui::Frame, area: Rect, app: &mut App) {
    // Layout: Search bar (3 rows), then split content below
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    // Search bar
    let search_title = if app.search_focused {
        " Search (Active) "
    } else {
        " Search [/] "
    };
    let search_style = if app.search_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let search_para = Paragraph::new(app.search_query.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(search_title)
            .border_style(search_style),
    );
    f.render_widget(search_para, chunks[0]);

    // Split list & details
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(33), Constraint::Percentage(67)])
        .split(chunks[1]);

    // Left pane: Items List
    let items_block = Block::default()
        .title(" Vault Items ")
        .borders(Borders::ALL);
    let list_items: Vec<ListItem> = app
        .items
        .iter()
        .map(|item| {
            let star = if item.favorite { "★ " } else { "  " };
            let text = format!("{}{}", star, item.name);
            let style = if item.favorite {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            ListItem::new(Span::styled(text, style))
        })
        .collect();

    let list = List::new(list_items)
        .block(items_block)
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    f.render_stateful_widget(list, body_chunks[0], &mut app.list_state);

    // Right pane: Details
    let details_block = Block::default()
        .title(" Item Details ")
        .borders(Borders::ALL);
    if let Some(item) = app.selected_item() {
        let details_area = details_block.inner(body_chunks[1]);
        f.render_widget(details_block, body_chunks[1]);

        let details_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(7), // Basic credentials
                Constraint::Length(4), // TOTP code if exists
                Constraint::Min(4),    // Custom fields & Notes
            ])
            .split(details_area);

        // 1. Basic details
        let (username, password, url) = if let Some(ref l) = item.login {
            (
                l.username.as_deref().unwrap_or(""),
                l.password.as_deref().unwrap_or(""),
                l.uris.first().map(|u| u.as_str()).unwrap_or(""),
            )
        } else {
            ("", "", "")
        };

        let displayed_password = if app.show_password {
            password
        } else {
            "••••••••"
        };

        let folder = item.folder_id.as_deref().unwrap_or("None");

        let basic_text = vec![
            Line::from(vec![
                Span::styled("Name:       ", Style::default().fg(Color::Cyan)),
                Span::raw(&item.name),
            ]),
            Line::from(vec![
                Span::styled("Username:   ", Style::default().fg(Color::Cyan)),
                Span::raw(username),
            ]),
            Line::from(vec![
                Span::styled("Password:   ", Style::default().fg(Color::Cyan)),
                Span::raw(displayed_password),
            ]),
            Line::from(vec![
                Span::styled("URL:        ", Style::default().fg(Color::Cyan)),
                Span::raw(url),
            ]),
            Line::from(vec![
                Span::styled("Folder ID:  ", Style::default().fg(Color::Cyan)),
                Span::raw(folder),
            ]),
            Line::from(vec![
                Span::styled("Updated:    ", Style::default().fg(Color::Cyan)),
                Span::raw(&item.revision_date),
            ]),
        ];
        f.render_widget(Paragraph::new(basic_text), details_layout[0]);

        // 2. TOTP Code section
        if let Some(ref login) = item.login {
            if login.totp.is_some() {
                let code = login
                    .get_totp_code()
                    .unwrap_or_else(|| "Invalid Secret".to_string());

                // Calculate remaining seconds in current 30 second step
                let epoch = Utc::now().timestamp() as u64;
                let remaining_secs = 30 - (epoch % 30);

                let totp_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(1), Constraint::Length(2)])
                    .split(details_layout[1]);

                let totp_lbl = Paragraph::new(vec![Line::from(vec![
                    Span::styled("TOTP Code:  ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        format!("{} ", code),
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("({}s remaining)", remaining_secs),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])]);
                f.render_widget(totp_lbl, totp_chunks[0]);

                let pct = (remaining_secs as f64 / 30.0 * 100.0) as u16;
                let gauge = Gauge::default()
                    .percent(pct)
                    .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
                    .label("");
                f.render_widget(gauge, totp_chunks[1]);
            }
        }

        // 3. Notes & Fields
        let mut notes_text = vec![];
        if !item.fields.is_empty() {
            notes_text.push(Line::from(Span::styled(
                "-- Custom Fields --",
                Style::default().fg(Color::Cyan),
            )));
            for f in &item.fields {
                match f {
                    CustomField::Text { name, value } => {
                        notes_text.push(Line::from(format!("  {}: {}", name, value)));
                    }
                    CustomField::Hidden { name, value } => {
                        let displayed_val = if app.show_password {
                            value
                        } else {
                            "••••••••"
                        };
                        notes_text.push(Line::from(format!(
                            "  {} (Hidden): {}",
                            name, displayed_val
                        )));
                    }
                    CustomField::Boolean { name, value } => {
                        notes_text.push(Line::from(format!("  {} (Boolean): {}", name, value)));
                    }
                }
            }
        }

        if let Some(ref notes) = item.notes {
            notes_text.push(Line::from(""));
            notes_text.push(Line::from(Span::styled(
                "-- Notes --",
                Style::default().fg(Color::Cyan),
            )));
            for line in notes.lines() {
                notes_text.push(Line::from(line));
            }
        }

        f.render_widget(
            Paragraph::new(notes_text).wrap(Wrap { trim: true }),
            details_layout[2],
        );
    } else {
        let select_prompt =
            Paragraph::new("Select an item from the left to view details.").block(details_block);
        f.render_widget(select_prompt, body_chunks[1]);
    }
}

fn draw_form_screen(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let title = if app.state == AppState::AddForm {
        " Add Vault Entry "
    } else {
        " Edit Vault Entry "
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let inner_area = block.inner(area);
    f.render_widget(block, area);

    // Form layouts: 8 rows of input fields + notes scroll
    let form_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Name
            Constraint::Length(3), // Username
            Constraint::Length(3), // Password
            Constraint::Length(3), // URL
            Constraint::Length(3), // TOTP
            Constraint::Length(3), // Folder ID
            Constraint::Length(3), // Favorite
            Constraint::Min(4),    // Notes
        ])
        .split(inner_area);

    let fields = [
        (FormField::Name, &app.form.name),
        (FormField::Username, &app.form.username),
        (FormField::Password, &app.form.password),
        (FormField::Url, &app.form.url),
        (FormField::Totp, &app.form.totp),
        (FormField::FolderId, &app.form.folder_id),
        (FormField::Favorite, &app.form.favorite),
    ];

    for (i, (field_type, val)) in fields.iter().enumerate() {
        let is_active = app.form.active_field == *field_type;
        let border_style = if is_active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let p = Paragraph::new(val.as_str()).block(
            Block::default()
                .borders(Borders::ALL)
                .title(field_type.name())
                .border_style(border_style),
        );
        f.render_widget(p, form_layout[i]);
    }

    // Notes field
    let is_notes_active = app.form.active_field == FormField::Notes;
    let notes_border_style = if is_notes_active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let notes_p = Paragraph::new(app.form.notes.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(FormField::Notes.name())
                .border_style(notes_border_style),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(notes_p, form_layout[7]);
}
