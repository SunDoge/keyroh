use anyhow::{Result, anyhow};
use chrono::Utc;
use crossterm::{
    event::{self, Event, EventStream, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures::StreamExt;
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
use keyroh_core::vault::{CustomField, UriEntry, VaultItem};
use keyroh_core::{LiveEvent, SyncInfo};

// ── Clipboard helpers ────────────────────────────────────────────────────────
/// Copy text using an already-open Clipboard handle.
/// Keeping the handle alive is essential on Linux: X11/Wayland expect the
/// owner process to serve selection requests until another owner takes over.
fn clipboard_copy(ctx: &mut arboard::Clipboard, text: &str) -> Result<()> {
    ctx.set_text(text.to_owned())
        .map_err(|e| anyhow!("Copy failed: {}", e))
}

/// Paste from an already-open Clipboard handle.
fn clipboard_paste(ctx: &mut arboard::Clipboard) -> Result<String> {
    ctx.get_text().map_err(|e| anyhow!("Paste failed: {}", e))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppState {
    Welcome, // Landing: choose create or sync
    PasswordPrompt,
    NotInitialized,       // Create new vault – enter password
    NotInitializedImport, // Sync existing – enter ticket + password
    Browse,
    AddForm,
    EditForm,
    ShowKeys,
    BitwardenImport, // Import from Bitwarden JSON export
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BwFocus {
    Path,
    Email,
    Password,
    Iterations,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WelcomeChoice {
    Create,
    Sync,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InitFocus {
    Ticket,
    Password,
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
        let (username, password, url, totp) = if let Some(login) = item.login() {
            (
                login.username.clone().unwrap_or_default(),
                login.password.clone().unwrap_or_default(),
                login
                    .uris
                    .first()
                    .map(|u| u.uri.clone())
                    .unwrap_or_default(),
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
    #[allow(dead_code)]
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

    // Timer for live sync/network info refresh (on ShowKeys page)
    last_sync_refresh: Instant,

    // Sync ticket cache
    sync_ticket: Option<String>,

    // Cached live sync/network info (refreshed periodically on ShowKeys)
    sync_info: SyncInfo,

    // TUI Sync Ticket import
    ticket_input: String,
    init_focus: InitFocus,

    // Welcome screen cursor
    welcome_choice: WelcomeChoice,

    // Bitwarden JSON import form
    bw_path: String,
    bw_email: String,
    bw_password: String,
    bw_iterations: String,
    bw_focus: BwFocus,

    // Transient clipboard feedback: (message, shown_at)
    clipboard_msg: Option<(String, Instant)>,

    // Persistent clipboard handle — must NOT be dropped while the app runs;
    // on Linux the process must keep serving X11 selection requests.
    clipboard: Option<arboard::Clipboard>,
}

fn get_vault_dir() -> PathBuf {
    if let Ok(d) = std::env::var("KEYROH_DATA_DIR") {
        PathBuf::from(d)
    } else {
        let mut path = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap());
        path.push(".config");
        path.push("keyroh");
        path
    }
}

impl App {
    pub async fn new() -> Result<Self> {
        let vault_dir = get_vault_dir();
        let manager = VaultManager::open(&vault_dir).await?;
        // If not yet initialized, show the Welcome landing menu first
        let state = if manager.is_initialized()? {
            AppState::PasswordPrompt
        } else {
            AppState::Welcome
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
            last_sync_refresh: Instant::now(),
            sync_ticket: None,
            sync_info: SyncInfo::default(),
            ticket_input: String::new(),
            init_focus: InitFocus::Ticket,
            welcome_choice: WelcomeChoice::Create,
            bw_path: String::new(),
            bw_email: String::new(),
            bw_password: String::new(),
            bw_iterations: "600000".to_string(),
            bw_focus: BwFocus::Path,
            clipboard_msg: None,
            // Open the clipboard once and keep it alive for the full app lifetime.
            // On Linux (X11 / Wayland) the clipboard owner must stay alive to
            // serve selection requests from other processes.
            clipboard: arboard::Clipboard::new().ok(),
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
            vec![UriEntry::new(self.form.url.clone())]
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
    let mut app = App::new().await?;

    // Main run loop
    let res = run_app(&mut terminal, &mut app).await;

    // Restore terminal before shutdown so any error messages are visible
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(ref err) = res {
        eprintln!("\x1b[31mError running TUI: {}\x1b[0m", err);
    }

    // Graceful shutdown: flush iroh docs/blobs, zero master key in memory.
    // shutdown() consumes VaultManager by value; extract it from App first.
    if let Err(e) = app.manager.shutdown().await {
        eprintln!("\x1b[33mWarning: shutdown error: {}\x1b[0m", e);
    }

    res
}

async fn run_app(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    let tick_rate = Duration::from_millis(250);
    let mut crossterm_events = EventStream::new();

    // Channel that receives LiveEvents forwarded from a background task.
    // Capacity 64 is more than enough for bursts of sync events.
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<LiveEvent>(64);
    let mut subscribed = false;

    loop {
        terminal.draw(|f| ui(f, app))?;

        // Subscribe to vault events the first time we land on Browse.
        // The spawned task owns the stream and forwards events through the channel.
        if app.state == AppState::Browse && !subscribed {
            if let Ok(mut stream) = app.manager.subscribe_events().await {
                let tx = ev_tx.clone();
                tokio::spawn(async move {
                    while let Some(Ok(ev)) = stream.next().await {
                        if tx.send(ev).await.is_err() {
                            break; // TUI exited — drop the task
                        }
                    }
                });
                subscribed = true;
            }
        }

        tokio::select! {
            // ── Terminal keyboard events ─────────────────────────────────────
            maybe_event = crossterm_events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) if key.kind == event::KeyEventKind::Press => {
                        if handle_key_event(app, key).await? {
                            return Ok(());
                        }
                    }
                    Some(Err(e)) => return Err(e.into()),
                    _ => {}
                }
            }

            // ── iroh-docs vault events ────────────────────────────────────────
            Some(ev) = ev_rx.recv() => {
                match ev {
                    // Any insert or blob-ready event → refresh the item list immediately
                    LiveEvent::InsertLocal { .. }
                    | LiveEvent::InsertRemote { .. }
                    | LiveEvent::ContentReady { .. }
                    | LiveEvent::PendingContentReady => {
                        let _ = app.manager.refresh_items().await;
                        let _ = app.update_items_list();
                    }
                    // Peer/sync events → update sync info panel if it's visible
                    LiveEvent::NeighborUp(_)
                    | LiveEvent::NeighborDown(_)
                    | LiveEvent::SyncFinished(_) => {
                        if app.state == AppState::ShowKeys {
                            app.sync_info = app.manager.get_sync_info().await;
                            app.last_sync_refresh = Instant::now();
                        }
                    }
                }
            }

            // ── 250 ms tick: timers ──────────────────────────────────────────
            _ = tokio::time::sleep(tick_rate) => {
                // Refresh live network info every 2 s on the sync page
                if app.state == AppState::ShowKeys
                    && app.last_sync_refresh.elapsed() >= Duration::from_secs(2)
                {
                    app.sync_info = app.manager.get_sync_info().await;
                    app.last_sync_refresh = Instant::now();
                }

                // Expire transient clipboard feedback
                if let Some((_, shown_at)) = &app.clipboard_msg {
                    if shown_at.elapsed() > Duration::from_secs(3) {
                        app.clipboard_msg = None;
                    }
                }
            }
        }
    }
}

async fn handle_key_event(app: &mut App, key: KeyEvent) -> Result<bool> {
    match app.state {
        // ── Welcome landing menu ────────────────────────────────────────────
        AppState::Welcome => match key.code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                app.welcome_choice = WelcomeChoice::Create;
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                app.welcome_choice = WelcomeChoice::Sync;
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                app.welcome_choice = WelcomeChoice::Create;
                app.auth_error = None;
                app.password_input.clear();
                app.state = AppState::NotInitialized;
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                app.welcome_choice = WelcomeChoice::Sync;
                app.auth_error = None;
                app.password_input.clear();
                app.ticket_input.clear();
                app.init_focus = InitFocus::Ticket;
                app.state = AppState::NotInitializedImport;
            }
            KeyCode::Enter => match app.welcome_choice {
                WelcomeChoice::Create => {
                    app.auth_error = None;
                    app.password_input.clear();
                    app.state = AppState::NotInitialized;
                }
                WelcomeChoice::Sync => {
                    app.auth_error = None;
                    app.password_input.clear();
                    app.ticket_input.clear();
                    app.init_focus = InitFocus::Ticket;
                    app.state = AppState::NotInitializedImport;
                }
            },
            KeyCode::Esc | KeyCode::Char('q') => return Ok(true),
            _ => {}
        },
        // ── Create new vault: enter master password ─────────────────────────
        AppState::NotInitialized => {
            match key.code {
                KeyCode::Char(c) => {
                    app.password_input.push(c);
                }
                KeyCode::Backspace => {
                    app.password_input.pop();
                }
                KeyCode::Enter => {
                    if app.password_input.len() < 8 {
                        app.auth_error = Some("Password must be at least 8 characters".into());
                    } else {
                        app.manager.init(&app.password_input).await?;
                        app.password_input.clear();
                        app.auth_error = None;
                        app.state = AppState::PasswordPrompt;
                    }
                }
                KeyCode::Esc => {
                    // Go back to Welcome menu
                    app.password_input.clear();
                    app.auth_error = None;
                    app.state = AppState::Welcome;
                }
                _ => {}
            }
        }
        // ── Sync existing vault: enter ticket + password ────────────────────
        AppState::NotInitializedImport => {
            match key.code {
                KeyCode::Tab => {
                    app.init_focus = match app.init_focus {
                        InitFocus::Ticket => InitFocus::Password,
                        InitFocus::Password => InitFocus::Ticket,
                    };
                }
                KeyCode::BackTab => {
                    app.init_focus = match app.init_focus {
                        InitFocus::Ticket => InitFocus::Password,
                        InitFocus::Password => InitFocus::Ticket,
                    };
                }
                // Ctrl+V must come before the general Char(c) arm
                KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    // Ctrl+V: paste clipboard into focused field
                    let result = app
                        .clipboard
                        .as_mut()
                        .map(clipboard_paste)
                        .unwrap_or_else(|| Err(anyhow!("Clipboard unavailable")));
                    match result {
                        Ok(text) => {
                            let clean: String = text.chars().filter(|c| !c.is_control()).collect();
                            match app.init_focus {
                                InitFocus::Ticket => app.ticket_input.push_str(&clean),
                                InitFocus::Password => app.password_input.push_str(&clean),
                            }
                        }
                        Err(e) => {
                            app.auth_error = Some(format!("Paste failed: {}", e));
                        }
                    }
                }
                KeyCode::Char(c) => match app.init_focus {
                    InitFocus::Ticket => app.ticket_input.push(c),
                    InitFocus::Password => app.password_input.push(c),
                },
                KeyCode::Backspace => match app.init_focus {
                    InitFocus::Ticket => {
                        app.ticket_input.pop();
                    }
                    InitFocus::Password => {
                        app.password_input.pop();
                    }
                },
                KeyCode::Enter => {
                    if app.ticket_input.is_empty() {
                        app.auth_error = Some("Sync ticket cannot be empty".into());
                    } else if app.password_input.len() < 8 {
                        app.auth_error = Some("Password must be at least 8 characters".into());
                    } else {
                        match app
                            .manager
                            .import_and_init(&app.password_input, &app.ticket_input)
                            .await
                        {
                            Ok(_) => {
                                app.password_input.clear();
                                app.ticket_input.clear();
                                app.auth_error = None;
                                app.state = AppState::PasswordPrompt;
                            }
                            Err(e) => {
                                app.auth_error = Some(format!("Import failed: {}", e));
                            }
                        }
                    }
                }
                KeyCode::Esc => {
                    // Go back to Welcome menu
                    app.password_input.clear();
                    app.ticket_input.clear();
                    app.auth_error = None;
                    app.state = AppState::Welcome;
                }
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
                KeyCode::Enter => match app.manager.unlock(&app.password_input).await {
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
                    KeyCode::Char('r') => {
                        let _ = app.manager.refresh_items().await;
                        let _ = app.update_items_list();
                    }
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
                            let (username, password, totp, uris) = if let Some(l) = item.login() {
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
                    KeyCode::Char('I') => {
                        // Capital I: open Bitwarden JSON import screen
                        app.bw_path.clear();
                        app.bw_email.clear();
                        app.bw_password.clear();
                        app.bw_iterations = "600000".to_string();
                        app.bw_focus = BwFocus::Path;
                        app.auth_error = None;
                        app.state = AppState::BitwardenImport;
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
                    KeyCode::Char('s') => {
                        app.sync_ticket = app.manager.export_sync_ticket().await.ok();
                        app.sync_info = app.manager.get_sync_info().await;
                        app.last_sync_refresh = Instant::now();
                        app.state = AppState::ShowKeys;
                    }
                    // [y] Copy password of selected item to clipboard
                    KeyCode::Char('y') => {
                        let pwd = app
                            .selected_item()
                            .and_then(|item| item.login().and_then(|l| l.password.clone()));
                        if let Some(pw) = pwd {
                            let result = app
                                .clipboard
                                .as_mut()
                                .map(|ctx| clipboard_copy(ctx, &pw))
                                .unwrap_or_else(|| Err(anyhow!("Clipboard unavailable")));
                            match result {
                                Ok(_) => {
                                    app.clipboard_msg = Some((
                                        "Password copied to clipboard!".into(),
                                        Instant::now(),
                                    ));
                                }
                                Err(e) => {
                                    app.clipboard_msg =
                                        Some((format!("Copy failed: {}", e), Instant::now()));
                                }
                            }
                        } else {
                            app.clipboard_msg =
                                Some(("No password to copy.".into(), Instant::now()));
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
        AppState::ShowKeys => {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('s') => {
                    app.state = AppState::Browse;
                }
                // [y] Copy the sync ticket to clipboard
                KeyCode::Char('y') => {
                    if let Some(ticket) = app.sync_ticket.clone() {
                        let result = app
                            .clipboard
                            .as_mut()
                            .map(|ctx| clipboard_copy(ctx, &ticket))
                            .unwrap_or_else(|| Err(anyhow!("Clipboard unavailable")));
                        match result {
                            Ok(_) => {
                                app.clipboard_msg = Some((
                                    "Sync ticket copied to clipboard!".into(),
                                    Instant::now(),
                                ));
                            }
                            Err(e) => {
                                app.clipboard_msg =
                                    Some((format!("Copy failed: {}", e), Instant::now()));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        AppState::BitwardenImport => {
            match key.code {
                KeyCode::Esc => {
                    app.auth_error = None;
                    app.state = AppState::Browse;
                }
                KeyCode::Tab => {
                    app.bw_focus = match app.bw_focus {
                        BwFocus::Path => BwFocus::Email,
                        BwFocus::Email => BwFocus::Password,
                        BwFocus::Password => BwFocus::Iterations,
                        BwFocus::Iterations => BwFocus::Path,
                    };
                }
                KeyCode::BackTab => {
                    app.bw_focus = match app.bw_focus {
                        BwFocus::Path => BwFocus::Iterations,
                        BwFocus::Email => BwFocus::Path,
                        BwFocus::Password => BwFocus::Email,
                        BwFocus::Iterations => BwFocus::Password,
                    };
                }
                KeyCode::Char(c) => {
                    let field = match app.bw_focus {
                        BwFocus::Path => &mut app.bw_path,
                        BwFocus::Email => &mut app.bw_email,
                        BwFocus::Password => &mut app.bw_password,
                        BwFocus::Iterations => &mut app.bw_iterations,
                    };
                    field.push(c);
                }
                KeyCode::Backspace => {
                    let field = match app.bw_focus {
                        BwFocus::Path => &mut app.bw_path,
                        BwFocus::Email => &mut app.bw_email,
                        BwFocus::Password => &mut app.bw_password,
                        BwFocus::Iterations => &mut app.bw_iterations,
                    };
                    field.pop();
                }
                KeyCode::Enter if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    // Ctrl+Enter: run the import
                    if app.bw_path.trim().is_empty() {
                        app.auth_error = Some("File path is required".into());
                    } else {
                        let path = app.bw_path.trim().to_string();
                        let email = app.bw_email.trim().to_string();
                        let password = app.bw_password.clone();
                        let iterations = app.bw_iterations.trim().parse::<u32>().unwrap_or(600_000);

                        let pw_opt = if password.is_empty() {
                            None
                        } else {
                            Some(password.as_str())
                        };
                        match app
                            .manager
                            .import_bitwarden_json(&path, pw_opt, &email, iterations)
                            .await
                        {
                            Ok(n) => {
                                app.auth_error = None;
                                app.bw_password.clear();
                                app.update_items_list()?;
                                app.state = AppState::Browse;
                                app.clipboard_msg = Some((
                                    format!("Imported {} items from Bitwarden", n),
                                    Instant::now(),
                                ));
                            }
                            Err(e) => {
                                app.auth_error = Some(format!("Import failed: {}", e));
                            }
                        }
                    }
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
        AppState::Welcome | AppState::NotInitialized | AppState::NotInitializedImport => {
            "NOT INITIALIZED".to_string()
        }
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
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(header, chunks[0]);

    // Draw Main Content based on app state
    match app.state {
        AppState::Welcome => {
            draw_welcome_screen(f, chunks[1], app);
        }
        AppState::NotInitialized => {
            draw_init_screen(f, chunks[1], app);
        }
        AppState::NotInitializedImport => {
            draw_init_import_screen(f, chunks[1], app);
        }
        AppState::PasswordPrompt => {
            draw_lock_screen(f, chunks[1], app);
        }
        AppState::Browse => {
            draw_browse_screen(f, chunks[1], app);
        }
        AppState::ShowKeys => {
            draw_keys_screen(f, chunks[1], app);
        }
        AppState::AddForm | AppState::EditForm => {
            draw_form_screen(f, chunks[1], app);
        }
        AppState::BitwardenImport => {
            draw_bitwarden_import_screen(f, chunks[1], app);
        }
    }

    // Draw Footer (shortcuts)
    let footer_text = match app.state {
        AppState::Welcome => {
            " [↑/↓] Navigate  |  [Enter] Select  |  [N] New Vault  |  [S] Sync  |  [Esc] Quit"
        }
        AppState::NotInitialized => " [Enter] Create Vault  |  [Esc] Back",
        AppState::NotInitializedImport => {
            " [Tab] Switch Field  |  [Enter] Import & Sync  |  [Esc] Back"
        }
        AppState::PasswordPrompt => " [Enter] Unlock  |  [Esc] Quit",
        AppState::Browse => {
            " [/] Search  |  [j/k] Nav  |  [a] Add  |  [e] Edit  |  [d] Del  |  [I] Bitwarden  |  [f] Fav  |  [p] Secret  |  [y] Pwd  |  [r] Refresh  |  [s] Sync  |  [q] Quit"
        }
        AppState::ShowKeys => " [y] Copy Sync Ticket  |  [Esc/s/q] Back  |  (refreshes every 2s)",
        AppState::AddForm | AppState::EditForm => {
            " [Tab/Shift-Tab] Switch Field  |  [Ctrl+Enter] Save  |  [Esc] Cancel"
        }
        AppState::BitwardenImport => " [Tab] Next Field  |  [Ctrl+Enter] Import  |  [Esc] Cancel",
    };
    let footer = Paragraph::new(Span::styled(
        footer_text,
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(footer, chunks[2]);
}

fn draw_welcome_screen(f: &mut ratatui::Frame, area: Rect, app: &App) {
    use ratatui::widgets::BorderType;

    let block = Block::default()
        .title(" Welcome to Keyroh ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // tagline
            Constraint::Length(1), // spacer
            Constraint::Length(3), // option 1
            Constraint::Length(3), // option 2
            Constraint::Min(1),
        ])
        .split(inner);

    let tagline = Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  Keyroh",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " — End-to-end encrypted, P2P-synced password vault.",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![Span::styled(
            "  Choose how to get started:",
            Style::default().fg(Color::DarkGray),
        )]),
    ]);
    f.render_widget(tagline, layout[0]);

    let is_create = app.welcome_choice == WelcomeChoice::Create;
    let is_sync = app.welcome_choice == WelcomeChoice::Sync;

    let create_style = if is_create {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Cyan)
    };
    let sync_style = if is_sync {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Yellow)
    };

    let create_prefix = if is_create { "▶ " } else { "  " };
    let sync_prefix = if is_sync { "▶ " } else { "  " };

    let opt_create = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            format!("  {}[N]  New Vault", create_prefix),
            create_style,
        )]),
        Line::from(vec![Span::styled(
            "       Create a brand-new encrypted vault on this device.",
            Style::default().fg(Color::DarkGray),
        )]),
    ]);
    f.render_widget(opt_create, layout[2]);

    let opt_sync = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            format!("  {}[S]  Sync Existing Vault", sync_prefix),
            sync_style,
        )]),
        Line::from(vec![Span::styled(
            "       Import a Sync Ticket to replicate a vault from another device.",
            Style::default().fg(Color::DarkGray),
        )]),
    ]);
    f.render_widget(opt_sync, layout[3]);
}

fn draw_init_screen(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Create New Vault ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

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
        "Create a master password for your new vault.\nPassword must be at least 8 characters long.",
    );
    f.render_widget(intro, content_chunks[0]);

    // Password input
    let password_stars: String = "*".repeat(app.password_input.len());
    let password_box = Paragraph::new(password_stars).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Master Password "),
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
                Constraint::Length(8), // Basic credentials
                Constraint::Length(4), // TOTP code if exists
                Constraint::Min(4),    // Custom fields & Notes
            ])
            .split(details_area);

        // 1. Basic details
        let (username, password, url) = if let Some(l) = item.login() {
            (
                l.username.as_deref().unwrap_or(""),
                l.password.as_deref().unwrap_or(""),
                l.uris.first().map(|u| u.uri.as_str()).unwrap_or(""),
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

        let cb_hint = if let Some((ref msg, _)) = app.clipboard_msg {
            Line::from(vec![Span::styled(
                format!("  ✓ {}", msg),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )])
        } else {
            Line::from(vec![Span::styled(
                "  [y] Copy password  [p] Toggle reveal",
                Style::default().fg(Color::DarkGray),
            )])
        };

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
            cb_hint,
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
        if let Some(login) = item.login() {
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

        // Mask the password field so it is never shown in plaintext on screen.
        let masked;
        let display: &str = if *field_type == FormField::Password {
            masked = "•".repeat(val.len());
            &masked
        } else {
            val.as_str()
        };

        let p = Paragraph::new(display).block(
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

fn draw_keys_screen(f: &mut ratatui::Frame, area: Rect, app: &App) {
    use ratatui::widgets::BorderType;

    let outer_block = Block::default()
        .title(" Sync Status ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = outer_block.inner(area);
    f.render_widget(outer_block, area);

    // Three vertical sections: Network | Document | Ticket
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // Network status
            Constraint::Length(6), // Document / vault status
            Constraint::Min(5),    // Sync ticket
        ])
        .split(inner);

    // ── Section 1: Network Status ─────────────────────────────────────────────
    let info = &app.sync_info;

    let relay_str = info.relay_url.as_deref().unwrap_or("not connected");
    let relay_color = if info.relay_url.is_some() {
        Color::Green
    } else {
        Color::DarkGray
    };

    let sockets_str = if info.bound_sockets.is_empty() {
        "none".to_string()
    } else {
        info.bound_sockets.join(", ")
    };

    let mut net_lines = vec![
        Line::from(vec![Span::styled(
            " Network",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("  Node ID:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(&info.node_id, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Relay:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(relay_str, Style::default().fg(relay_color)),
        ]),
        Line::from(vec![
            Span::styled("  Sockets:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(&sockets_str, Style::default().fg(Color::White)),
        ]),
    ];

    let peers_header = Line::from(vec![
        Span::styled("  Peers:     ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} known", info.sync_peers.len()),
            Style::default().fg(if info.sync_peers.is_empty() {
                Color::DarkGray
            } else {
                Color::Green
            }),
        ),
    ]);
    net_lines.push(peers_header);

    // Show up to 2 peer IDs inline (truncated to 16 chars for readability)
    for peer in info.sync_peers.iter().take(2) {
        let short = if peer.len() > 20 {
            format!("    {}…", &peer[..20])
        } else {
            format!("    {}", peer)
        };
        net_lines.push(Line::from(vec![Span::styled(
            short,
            Style::default().fg(Color::Yellow),
        )]));
    }
    if info.sync_peers.len() > 2 {
        net_lines.push(Line::from(vec![Span::styled(
            format!("    … and {} more", info.sync_peers.len() - 2),
            Style::default().fg(Color::DarkGray),
        )]));
    }

    f.render_widget(
        Paragraph::new(net_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        sections[0],
    );

    // ── Section 2: Document / Vault Status ───────────────────────────────────
    let vault_status = if info.is_unlocked {
        Span::styled("unlocked ✓", Style::default().fg(Color::Green))
    } else if info.is_initialized {
        Span::styled("locked", Style::default().fg(Color::Yellow))
    } else {
        Span::styled("not initialized", Style::default().fg(Color::Red))
    };

    let doc_lines = vec![
        Line::from(vec![Span::styled(
            " Vault",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("  Status:    ", Style::default().fg(Color::DarkGray)),
            vault_status,
        ]),
        Line::from(vec![
            Span::styled("  Namespace: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&info.namespace_id, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Author:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(&info.author_id, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Items:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                info.item_count.to_string(),
                Style::default().fg(Color::White),
            ),
        ]),
    ];

    f.render_widget(
        Paragraph::new(doc_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        sections[1],
    );

    // ── Section 3: Sync Ticket ────────────────────────────────────────────────
    let ticket = app
        .sync_ticket
        .as_deref()
        .unwrap_or("N/A — unlock vault and press [s] again");

    let cb_line = if let Some((ref msg, _)) = app.clipboard_msg {
        Line::from(vec![Span::styled(
            format!("  ✓ {}", msg),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )])
    } else {
        Line::from(vec![Span::styled(
            "  [y] copy ticket  [!] keep secure — grants full vault access",
            Style::default().fg(Color::DarkGray),
        )])
    };

    let ticket_lines = vec![
        Line::from(vec![Span::styled(
            " Sync Ticket (share with another device)",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(
            ticket,
            Style::default().fg(Color::Yellow),
        )]),
        Line::from(""),
        cb_line,
    ];

    f.render_widget(
        Paragraph::new(ticket_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .wrap(Wrap { trim: false }),
        sections[2],
    );
}

fn draw_init_import_screen(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Import Sync Ticket ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let content_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Intro text
            Constraint::Length(4), // Ticket Input
            Constraint::Length(3), // Password Input
            Constraint::Length(2), // Error message
            Constraint::Min(1),
        ])
        .split(block.inner(area));

    f.render_widget(block, area);

    let intro = Paragraph::new(
        "Paste a Sync Ticket from another device. The master key is fetched over P2P.\nEnsure the source device is reachable, then enter the vault master password.",
    );
    f.render_widget(intro, content_chunks[0]);

    // Ticket Input Box
    let is_ticket_focused = app.init_focus == InitFocus::Ticket;
    let ticket_border = if is_ticket_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let ticket_box = Paragraph::new(app.ticket_input.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(ticket_border)
                .title(" Enter Sync Ticket "),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(ticket_box, content_chunks[1]);

    // Password Input Box
    let is_password_focused = app.init_focus == InitFocus::Password;
    let password_border = if is_password_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let password_stars = "*".repeat(app.password_input.len());
    let password_box = Paragraph::new(password_stars).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(password_border)
            .title(" Enter Master Password "),
    );
    f.render_widget(password_box, content_chunks[2]);

    // Error display
    if let Some(ref err) = app.auth_error {
        let error_para = Paragraph::new(Span::styled(err, Style::default().fg(Color::Red)));
        f.render_widget(error_para, content_chunks[3]);
    }
}

fn draw_bitwarden_import_screen(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Import from Bitwarden ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // intro
            Constraint::Length(3), // file path
            Constraint::Length(3), // email
            Constraint::Length(3), // password
            Constraint::Length(3), // iterations
            Constraint::Length(2), // error
            Constraint::Min(1),
        ])
        .split(block.inner(area));

    f.render_widget(block, area);

    let intro = Paragraph::new(
        "Encrypted export: fill all fields. Unencrypted export: only file path needed.",
    );
    f.render_widget(intro, chunks[0]);

    let focused_style = Style::default().fg(Color::Magenta);
    let unfocused_style = Style::default().fg(Color::DarkGray);

    let fields: &[(&str, &str, BwFocus, bool)] = &[
        ("File Path", app.bw_path.as_str(), BwFocus::Path, false),
        (
            "Bitwarden Email",
            app.bw_email.as_str(),
            BwFocus::Email,
            false,
        ),
        (
            "Master Password",
            app.bw_password.as_str(),
            BwFocus::Password,
            true,
        ),
        (
            "PBKDF2 Iterations",
            app.bw_iterations.as_str(),
            BwFocus::Iterations,
            false,
        ),
    ];

    for (i, (label, value, focus, is_pw)) in fields.iter().enumerate() {
        let is_active = app.bw_focus == *focus;
        let border_style = if is_active {
            focused_style
        } else {
            unfocused_style
        };
        let display = if *is_pw {
            "*".repeat(value.len())
        } else {
            value.to_string()
        };
        let p = Paragraph::new(display.as_str()).block(
            Block::default()
                .borders(Borders::ALL)
                .title(*label)
                .border_style(border_style),
        );
        f.render_widget(p, chunks[i + 1]);
    }

    if let Some(ref err) = app.auth_error {
        let error_para =
            Paragraph::new(Span::styled(err.as_str(), Style::default().fg(Color::Red)));
        f.render_widget(error_para, chunks[5]);
    }
}
