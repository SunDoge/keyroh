use std::path::{Path, PathBuf};
use std::io::{self, Write};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use keyroh_core::manager::VaultManager;
use keyroh_core::vault::VaultItem;

#[derive(Parser)]
#[command(name = "keyroh", author, version, about = "Keyroh: A decentralized collaborative password manager built on iroh-docs & SQLite")]
struct Cli {
    #[arg(long, help = "Custom data directory")]
    dir: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Clone)]
enum Commands {
    #[command(about = "Initialize the vault with a master password")]
    Init,

    #[command(about = "Unlock the vault and generate a session token")]
    Unlock,

    #[command(about = "Lock the vault (instructions to clear the session key)")]
    Lock,

    #[command(about = "Show initialization and unlocked status")]
    Status,

    #[command(about = "Add a new login/password entry")]
    Add {
        #[arg(long, short)]
        name: Option<String>,
        #[arg(long, short)]
        username: Option<String>,
        #[arg(long, short)]
        password: Option<String>,
        #[arg(long, short)]
        notes: Option<String>,
        #[arg(long, short)]
        uri: Option<String>,
        #[arg(long, short)]
        favorite: bool,
    },

    #[command(about = "List all login entries in the vault")]
    List,

    #[command(about = "Show decrypted details of a login entry by ID")]
    Show {
        id: String,
    },

    #[command(about = "Search login entries by query string")]
    Search {
        query: String,
    },

    #[command(about = "Edit an existing entry")]
    Edit {
        id: String,
        #[arg(long, short)]
        name: Option<String>,
        #[arg(long, short)]
        username: Option<String>,
        #[arg(long, short)]
        password: Option<String>,
        #[arg(long, short)]
        notes: Option<String>,
        #[arg(long, short)]
        uri: Option<String>,
        #[arg(long, short)]
        favorite: Option<bool>,
    },

    #[command(about = "Delete a login entry by ID")]
    Delete {
        id: String,
    },

    #[command(about = "Export replica sync keys")]
    ExportKeys,

    #[command(about = "Import replica sync keys and initialize local password")]
    ImportKeys {
        #[arg(long, help = "Namespace secret key (hex)")]
        ns_secret: String,
        #[arg(long, help = "Author key (hex)")]
        author: String,
    },
}

fn get_vault_dir(custom_dir: Option<String>) -> PathBuf {
    if let Some(d) = custom_dir {
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

async fn get_unlocked_manager(dir: &Path) -> Result<VaultManager> {
    let mut manager = VaultManager::open(dir)?;
    if !manager.is_initialized()? {
        return Err(anyhow!("Vault is not initialized. Run 'keyroh init' first."));
    }
    
    // Check if session environment variable is set
    if let Ok(session_key) = std::env::var("KEYROH_SESSION") {
        manager.unlock_with_session(&session_key)?;
    } else {
        // If not set, prompt for master password
        let password = rpassword::prompt_password("\x1b[36mEnter master password to unlock vault:\x1b[0m ")?;
        manager.unlock(&password)?;
    }
    
    Ok(manager)
}

fn prompt_string(prompt: &str, default: Option<&str>) -> String {
    let display_prompt = if let Some(def) = default {
        format!("{} [{}]: ", prompt, def)
    } else {
        format!("{}: ", prompt)
    };
    print!("{}", display_prompt);
    let _ = io::stdout().flush();
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.unwrap_or("").to_string()
    } else {
        trimmed.to_string()
    }
}

fn prompt_string_opt(prompt: &str, default: Option<&str>) -> Option<String> {
    let s = prompt_string(prompt, default);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn print_success(msg: &str) {
    println!("\x1b[32m✔ {}\x1b[0m", msg);
}

fn print_error(msg: &str) {
    eprintln!("\x1b[31m✘ Error: {}\x1b[0m", msg);
}

fn print_info(msg: &str) {
    println!("\x1b[34mℹ {}\x1b[0m", msg);
}

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
    for row in rows {
        for (i, val) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(val.len());
            }
        }
    }
    
    // Print header in bold cyan
    print!("\x1b[1;36m");
    for (i, h) in headers.iter().enumerate() {
        print!("{:<width$}  ", h, width = widths[i]);
    }
    println!("\x1b[0m");
    
    // Print separator
    for w in &widths {
        print!("{:-<width$}  ", "", width = w);
    }
    println!();
    
    // Print rows
    for row in rows {
        for (i, val) in row.iter().enumerate() {
            if i < widths.len() {
                // If it is the first column (ID), make it grey, others normal
                if i == 0 {
                    print!("\x1b[90m{:<width$}\x1b[0m  ", val, width = widths[i]);
                } else if i == 1 {
                    print!("\x1b[1m{:<width$}\x1b[0m  ", val, width = widths[i]); // Bold names
                } else {
                    print!("{:<width$}  ", val, width = widths[i]);
                }
            }
        }
        println!();
    }
}

fn print_item_details(item: &VaultItem) {
    println!("\x1b[1;35mVault Item Details\x1b[0m");
    println!("\x1b[90m==================================================\x1b[0m");
    println!("\x1b[1mID:\x1b[0m             {}", item.id);
    println!("\x1b[1mName:\x1b[0m           {}", item.name);
    println!("\x1b[1mFavorite:\x1b[0m       {}", if item.favorite { "Yes ★" } else { "No" });
    println!("\x1b[1mRevision Date:\x1b[0m  {}", item.revision_date);
    
    if let Some(ref login) = item.login {
        println!("\x1b[1;34m-- Login details --\x1b[0m");
        println!("  \x1b[1mUsername:\x1b[0m     {}", login.username.as_deref().unwrap_or(""));
        println!("  \x1b[1mPassword:\x1b[0m     {}", login.password.as_deref().unwrap_or(""));
        println!("  \x1b[1mURIs:\x1b[0m         {:?}", login.uris);
    }
    
    if let Some(ref notes) = item.notes {
        println!("\x1b[1;34m-- Notes --\x1b[0m");
        println!("{}", notes);
    }
    println!("\x1b[90m==================================================\x1b[0m");
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let vault_dir = get_vault_dir(cli.dir);
    
    match execute_command(cli.command, &vault_dir).await {
        Ok(_) => {}
        Err(err) => {
            print_error(&format!("{:#}", err));
            std::process::exit(1);
        }
    }
}

async fn execute_command(command: Commands, vault_dir: &Path) -> Result<()> {
    match command {
        Commands::Init => {
            let mut manager = VaultManager::open(vault_dir)?;
            if manager.is_initialized()? {
                return Err(anyhow!("Vault is already initialized at {:?}", vault_dir));
            }
            
            println!("\x1b[1;36mInitializing a new Keyroh Vault at {:?}\x1b[0m", vault_dir);
            let password = rpassword::prompt_password("Choose a master password: ")?;
            if password.len() < 8 {
                return Err(anyhow!("Master password should be at least 8 characters long"));
            }
            
            let confirm = rpassword::prompt_password("Confirm master password: ")?;
            if password != confirm {
                return Err(anyhow!("Passwords do not match"));
            }
            
            manager.init(&password)?;
            print_success("Vault successfully initialized!");
            print_info("Use 'keyroh unlock' to start a session.");
        }
        
        Commands::Unlock => {
            let mut manager = VaultManager::open(vault_dir)?;
            if !manager.is_initialized()? {
                return Err(anyhow!("Vault is not initialized. Run 'keyroh init' first."));
            }
            
            let password = rpassword::prompt_password("Enter master password to unlock: ")?;
            match manager.unlock(&password) {
                Ok(session_key) => {
                    print_success("Vault unlocked successfully!");
                    println!("\nTo set your session key, run the following command in your terminal:");
                    println!("\x1b[1;32mexport KEYROH_SESSION={}\x1b[0m\n", session_key);
                    print_info("Copy the command above. Subsequent commands in this terminal session will read the session key directly.");
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }
        
        Commands::Lock => {
            print_info("To lock your vault session, run:");
            println!("\x1b[1;31munset KEYROH_SESSION\x1b[0m");
        }
        
        Commands::Status => {
            let manager = VaultManager::open(vault_dir)?;
            let status = manager.get_status()?;
            
            println!("\x1b[1;36mKeyroh Vault Status\x1b[0m");
            println!("\x1b[90m==================================================\x1b[0m");
            println!("Storage Directory:   {:?}", vault_dir);
            println!("Initialized:         {}", status["initialized"]);
            println!("Session Status:      {}", if status["unlocked"].as_bool().unwrap_or(false) { "\x1b[32mUnlocked ✔\x1b[0m" } else { "\x1b[31mLocked 🔒\x1b[0m" });
            println!("Namespace Sync ID:   {}", status["namespace_id"].as_str().unwrap_or(""));
            println!("Author Sync ID:      {}", status["author_id"].as_str().unwrap_or(""));
            if status["unlocked"].as_bool().unwrap_or(false) {
                println!("Cached Vault Items:  {}", status["item_count"]);
            }
            println!("\x1b[90m==================================================\x1b[0m");
        }
        
        Commands::Add { name, username, password, notes, uri, favorite } => {
            let mut manager = get_unlocked_manager(vault_dir).await?;
            
            // Interactive prompts if values are not provided as arguments
            let item_name = name.unwrap_or_else(|| prompt_string("Item Name", None));
            if item_name.is_empty() {
                return Err(anyhow!("Item Name is required"));
            }
            
            let item_username = username.or_else(|| prompt_string_opt("Username", None));
            let item_password = password.or_else(|| {
                rpassword::prompt_password("Password: ").ok().filter(|s| !s.is_empty())
            });
            let item_uri = uri.or_else(|| prompt_string_opt("Login URI/URL", None));
            let item_notes = notes.or_else(|| prompt_string_opt("Notes", None));
            
            let uris = item_uri.map(|u| vec![u]).unwrap_or_default();
            
            print_info("Saving item to iroh-docs and indexing with SQLite...");
            let item = manager.add_item(
                item_name,
                item_username,
                item_password,
                item_notes,
                uris,
                favorite
            ).await?;
            
            print_success("Vault item added successfully!");
            println!("ID: {}", item.id);
        }
        
        Commands::List => {
            let manager = get_unlocked_manager(vault_dir).await?;
            let items = manager.list_items()?;
            
            if items.is_empty() {
                print_info("Vault is empty.");
                return Ok(());
            }
            
            let headers = vec!["ID", "NAME", "USERNAME", "URI", "FAVORITE"];
            let rows = items.into_iter().map(|item| {
                let username = item.login.as_ref().and_then(|l| l.username.clone()).unwrap_or_default();
                let uri = item.login.as_ref().and_then(|l| l.uris.first().cloned()).unwrap_or_default();
                vec![
                    item.id[..8].to_string() + "...",
                    item.name,
                    username,
                    uri,
                    if item.favorite { "★" } else { "" }.to_string(),
                ]
            }).collect::<Vec<_>>();
            
            print_table(&headers, &rows);
        }
        
        Commands::Show { id } => {
            let manager = get_unlocked_manager(vault_dir).await?;
            let items = manager.list_items()?;
            
            // Find item by ID or prefix
            let item = items.into_iter().find(|i| i.id == id || i.id.starts_with(&id))
                .ok_or_else(|| anyhow!("Vault item not found: {}", id))?;
                
            print_item_details(&item);
        }
        
        Commands::Search { query } => {
            let manager = get_unlocked_manager(vault_dir).await?;
            let items = manager.search_items(&query)?;
            
            if items.is_empty() {
                print_info("No items match your query.");
                return Ok(());
            }
            
            let headers = vec!["ID", "NAME", "USERNAME", "URI", "FAVORITE"];
            let rows = items.into_iter().map(|item| {
                let username = item.login.as_ref().and_then(|l| l.username.clone()).unwrap_or_default();
                let uri = item.login.as_ref().and_then(|l| l.uris.first().cloned()).unwrap_or_default();
                vec![
                    item.id[..8].to_string() + "...",
                    item.name,
                    username,
                    uri,
                    if item.favorite { "★" } else { "" }.to_string(),
                ]
            }).collect::<Vec<_>>();
            
            print_table(&headers, &rows);
        }
        
        Commands::Edit { id, name, username, password, notes, uri, favorite } => {
            let mut manager = get_unlocked_manager(vault_dir).await?;
            
            // Retrieve existing first
            let items = manager.list_items()?;
            let existing = items.into_iter().find(|i| i.id == id || i.id.starts_with(&id))
                .ok_or_else(|| anyhow!("Vault item not found: {}", id))?;
            
            let ex_login = existing.login.as_ref();
            let ex_username = ex_login.and_then(|l| l.username.clone());
            let ex_password = ex_login.and_then(|l| l.password.clone());
            let ex_uri = ex_login.and_then(|l| l.uris.first().cloned());
            
            // Interactive prompts/arguments merging
            let new_name = name.unwrap_or_else(|| prompt_string("Item Name", Some(&existing.name)));
            let new_username = username.or_else(|| prompt_string_opt("Username", ex_username.as_deref()));
            let new_password = password.or_else(|| {
                rpassword::prompt_password(&format!("Password (press Enter to keep existing): ")).ok()
                    .filter(|s| !s.is_empty())
                    .or(ex_password)
            });
            let new_uri = uri.or_else(|| prompt_string_opt("Login URI/URL", ex_uri.as_deref()));
            let new_notes = notes.or_else(|| prompt_string_opt("Notes", existing.notes.as_deref()));
            let new_favorite = favorite.unwrap_or_else(|| {
                prompt_string("Favorite (y/n)", Some(if existing.favorite { "y" } else { "n" })).to_lowercase().starts_with('y')
            });
            
            let uris = new_uri.map(|u| vec![u]).unwrap_or_default();
            
            print_info("Updating entry in iroh-docs and SQLite...");
            let updated = manager.edit_item(
                existing.id,
                new_name,
                new_username,
                new_password,
                new_notes,
                uris,
                new_favorite
            ).await?;
            
            print_success("Vault item updated successfully!");
            print_item_details(&updated);
        }
        
        Commands::Delete { id } => {
            let mut manager = get_unlocked_manager(vault_dir).await?;
            
            let items = manager.list_items()?;
            let existing = items.into_iter().find(|i| i.id == id || i.id.starts_with(&id))
                .ok_or_else(|| anyhow!("Vault item not found: {}", id))?;
            
            print_info(&format!("Deleting item '{}' ({})...", existing.name, existing.id));
            manager.delete_item(&existing.id).await?;
            
            print_success("Vault item deleted successfully!");
        }
        
        Commands::ExportKeys => {
            let manager = get_unlocked_manager(vault_dir).await?;
            let (ns_secret, author) = manager.export_replica_keys()?;
            
            println!("\n\x1b[1;35mKeyroh Sync Keys (KEEP THESE SECRET!)\x1b[0m");
            println!("\x1b[90m==================================================\x1b[0m");
            println!("\x1b[1mNamespace Secret (Replica Key):\x1b[0m");
            println!("\x1b[32m{}\x1b[0m", ns_secret);
            println!("\n\x1b[1mAuthor Secret Key:\x1b[0m");
            println!("\x1b[32m{}\x1b[0m", author);
            println!("\x1b[90m==================================================\x1b[0m");
            print_info("Use these keys with 'keyroh import-keys' on another device to replicate this vault.");
        }
        
        Commands::ImportKeys { ns_secret, author } => {
            let mut manager = VaultManager::open(vault_dir)?;
            if manager.is_initialized()? {
                return Err(anyhow!("Cannot import keys into an already initialized vault. Clear the storage directory {:?} first.", vault_dir));
            }
            
            println!("\x1b[1;36mImporting Replica Sync Keys and Initializing Local Vault\x1b[0m");
            let password = rpassword::prompt_password("Choose a master password for THIS device: ")?;
            if password.len() < 8 {
                return Err(anyhow!("Master password should be at least 8 characters long"));
            }
            
            let confirm = rpassword::prompt_password("Confirm master password: ")?;
            if password != confirm {
                return Err(anyhow!("Passwords do not match"));
            }
            
            manager.import_and_init(&password, &ns_secret, &author)?;
            print_success("Keys successfully imported and local vault initialized!");
            print_info("Subsequent sync reconciliations can now take place. Run 'keyroh list' to view cache.");
        }
    }
    
    Ok(())
}
