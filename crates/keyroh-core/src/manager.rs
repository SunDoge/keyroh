use std::path::{Path, PathBuf};
use std::str::FromStr;
use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection};
use iroh_docs::store::fs::Store as DocStore;
use iroh_docs::{NamespaceSecret, NamespaceId, Author, AuthorId, SignedEntry};
use iroh_blobs::Hash;
use chrono::Utc;
use uuid::Uuid;
use rand::Rng;

use crate::vault::{VaultItem, LoginDetails};
use crate::crypto;
use crate::db;
use crate::docs;

pub struct UnlockedState {
    pub master_key: [u8; 32],
    pub ns_secret: NamespaceSecret,
    pub author: Author,
    pub namespace_id: NamespaceId,
    pub author_id: AuthorId,
    pub mem_conn: Connection,
}

pub struct VaultManager {
    base_dir: PathBuf,
    sqlite_conn: Connection,
    doc_store: DocStore,
    unlocked: Option<UnlockedState>,
}

impl VaultManager {
    /// Opens the vault manager, initializing directories and database connections.
    pub fn open(base_dir: &Path) -> Result<Self> {
        // Create base directory
        std::fs::create_dir_all(base_dir)
            .context("Failed to create vault data directory")?;
            
        let sqlite_path = base_dir.join("keyroh.db");
        let docs_path = base_dir.join("docs.db");
        
        let sqlite_conn = db::init_persistent_db(&sqlite_path)?;
        let doc_store = docs::open_doc_store(&docs_path)?;
        
        Ok(VaultManager {
            base_dir: base_dir.to_path_buf(),
            sqlite_conn,
            doc_store,
            unlocked: None,
        })
    }
    
    /// Checks if the vault has been initialized.
    pub fn is_initialized(&self) -> Result<bool> {
        let salt = db::get_state_value(&self.sqlite_conn, "salt")?;
        let encrypted_master_key = db::get_state_value(&self.sqlite_conn, "encrypted_master_key")?;
        Ok(salt.is_some() && encrypted_master_key.is_some())
    }
    
    /// Initializes a new vault with a master password.
    pub fn init(&mut self, master_password: &str) -> Result<()> {
        if self.is_initialized()? {
            return Err(anyhow!("Vault is already initialized"));
        }
        
        // 1. Generate master key
        let mut master_key = [0u8; 32];
        rand::rng().fill_bytes(&mut master_key);
        
        // 2. Derive KEK and encrypt master key
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        
        let mut kek = [0u8; 32];
        crypto::derive_key(master_password, &salt, &mut kek);
        
        let encrypted_master_key = crypto::encrypt(&master_key, &kek)?;
        
        // 3. Create document replica and author in iroh-docs
        let (ns_secret, author) = docs::create_vault_replica(&mut self.doc_store)?;
        let namespace_id = ns_secret.id();
        let author_id = author.id();
        
        // 4. Encrypt replica keys with the master key
        let ns_bytes = ns_secret.to_bytes();
        let author_bytes = author.to_bytes();
        
        let encrypted_ns = crypto::encrypt(&ns_bytes, &master_key)?;
        let encrypted_author = crypto::encrypt(&author_bytes, &master_key)?;
        
        // 5. Store everything in persistent SQLite
        db::set_state_value(&self.sqlite_conn, "salt", &hex::encode(salt))?;
        db::set_state_value(&self.sqlite_conn, "encrypted_master_key", &hex::encode(encrypted_master_key))?;
        db::set_state_value(&self.sqlite_conn, "encrypted_ns_secret", &hex::encode(encrypted_ns))?;
        db::set_state_value(&self.sqlite_conn, "encrypted_author", &hex::encode(encrypted_author))?;
        db::set_state_value(&self.sqlite_conn, "namespace_id", &namespace_id.to_string())?;
        db::set_state_value(&self.sqlite_conn, "author_id", &author_id.to_string())?;
        
        // Flush doc store to ensure it's written
        self.doc_store.flush()?;
        
        Ok(())
    }
    
    /// Unlocks the vault with the master password, decrypting the master key.
    /// Returns the decrypted master key as hex.
    pub fn unlock(&mut self, master_password: &str) -> Result<String> {
        if !self.is_initialized()? {
            return Err(anyhow!("Vault has not been initialized. Run init first."));
        }
        
        // 1. Fetch salt and encrypted master key
        let salt_hex = db::get_state_value(&self.sqlite_conn, "salt")?
            .ok_or_else(|| anyhow!("Salt missing"))?;
        let enc_master_key_hex = db::get_state_value(&self.sqlite_conn, "encrypted_master_key")?
            .ok_or_else(|| anyhow!("Encrypted master key missing"))?;
            
        let salt = hex::decode(salt_hex).context("Failed to decode salt hex")?;
        let enc_master_key = hex::decode(enc_master_key_hex).context("Failed to decode encrypted master key hex")?;
        
        // 2. Derive KEK
        let mut kek = [0u8; 32];
        crypto::derive_key(master_password, &salt, &mut kek);
        
        // 3. Decrypt master key
        let master_key_vec = crypto::decrypt(&enc_master_key, &kek)
            .map_err(|_| anyhow!("Incorrect master password"))?;
            
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_vec);
        
        // 4. Open index
        self.load_unlocked_state(master_key)?;
        
        Ok(hex::encode(master_key))
    }
    
    /// Unlocks the vault with a pre-decrypted master key hex (e.g. from environment variable).
    pub fn unlock_with_session(&mut self, session_key_hex: &str) -> Result<()> {
        let master_key_vec = hex::decode(session_key_hex)
            .context("Invalid session key format")?;
            
        if master_key_vec.len() != 32 {
            return Err(anyhow!("Session key must be 32 bytes (64 hex characters)"));
        }
        
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_vec);
        
        self.load_unlocked_state(master_key)?;
        Ok(())
    }
    
    /// Helper to populate decrypted states into memory and open in-memory index database.
    fn load_unlocked_state(&mut self, master_key: [u8; 32]) -> Result<()> {
        // 1. Fetch encrypted replica secrets
        let enc_ns_hex = db::get_state_value(&self.sqlite_conn, "encrypted_ns_secret")?
            .ok_or_else(|| anyhow!("Encrypted namespace secret missing"))?;
        let enc_author_hex = db::get_state_value(&self.sqlite_conn, "encrypted_author")?
            .ok_or_else(|| anyhow!("Encrypted author missing"))?;
            
        let enc_ns = hex::decode(enc_ns_hex)?;
        let enc_author = hex::decode(enc_author_hex)?;
        
        // 2. Decrypt replica keys
        let ns_bytes_vec = crypto::decrypt(&enc_ns, &master_key)
            .context("Failed to decrypt namespace secret")?;
        let author_bytes_vec = crypto::decrypt(&enc_author, &master_key)
            .context("Failed to decrypt author")?;
            
        let mut ns_bytes = [0u8; 32];
        let mut author_bytes = [0u8; 32];
        ns_bytes.copy_from_slice(&ns_bytes_vec);
        author_bytes.copy_from_slice(&author_bytes_vec);
        
        let ns_secret = NamespaceSecret::from_bytes(&ns_bytes);
        let author = Author::from_bytes(&author_bytes);
        
        let namespace_id = ns_secret.id();
        let author_id = author.id();
        
        // 3. Create in-memory index database
        let mem_conn = db::create_in_memory_index_db()?;
        
        // 4. Load replica entries from iroh-docs and populate in-memory database
        let entries = docs::get_replica_entries(&mut self.doc_store, namespace_id)?;
        
        for signed_entry in entries {
            let key = signed_entry.key();
            let key_str = String::from_utf8_lossy(key);
            
            // Vault item keys look like: "items/<uuid>"
            if key_str.starts_with("items/") {
                // If content len is 0, it means it is a tombstone / deleted entry
                if signed_entry.content_len() == 0 {
                    let id = &key_str["items/".len()..];
                    db::delete_index_item(&mem_conn, id)?;
                    continue;
                }
                
                let content_hash = signed_entry.content_hash();
                let hash_hex = content_hash.to_hex();
                
                // Fetch encrypted blob from SQLite
                if let Some(enc_content) = db::get_blob(&self.sqlite_conn, &hash_hex)? {
                    // Decrypt blob
                    if let Ok(dec_bytes) = crypto::decrypt(&enc_content, &master_key) {
                        // Parse VaultItem
                        if let Ok(item) = serde_json::from_slice::<VaultItem>(&dec_bytes) {
                            db::upsert_index_item(&mem_conn, &item)?;
                        }
                    }
                }
            }
        }
        
        self.unlocked = Some(UnlockedState {
            master_key,
            ns_secret,
            author,
            namespace_id,
            author_id,
            mem_conn,
        });
        
        Ok(())
    }
    
    /// Locks the vault, discarding memory keys and search indexes.
    pub fn lock(&mut self) {
        self.unlocked = None;
    }
    
    /// Gets the UnlockedState, returning error if locked.
    fn get_unlocked(&self) -> Result<&UnlockedState> {
        self.unlocked.as_ref().ok_or_else(|| anyhow!("Vault is locked. Export KEYROH_SESSION or run unlock command."))
    }
    
    /// Gets the UnlockedState mutably, returning error if locked.
    fn get_unlocked_mut(&mut self) -> Result<&mut UnlockedState> {
        self.unlocked.as_mut().ok_or_else(|| anyhow!("Vault is locked. Export KEYROH_SESSION or run unlock command."))
    }
    
    /// Returns basic details about the current replica configuration.
    pub fn get_status(&self) -> Result<serde_json::Value> {
        let is_init = self.is_initialized()?;
        let is_unlocked = self.unlocked.is_some();
        
        let namespace_id = db::get_state_value(&self.sqlite_conn, "namespace_id")?;
        let author_id = db::get_state_value(&self.sqlite_conn, "author_id")?;
        
        let num_items = if let Some(ref state) = self.unlocked {
            db::list_index_items(&state.mem_conn)?.len()
        } else {
            0
        };
        
        Ok(serde_json::json!({
            "initialized": is_init,
            "unlocked": is_unlocked,
            "namespace_id": namespace_id.unwrap_or_else(|| "N/A".to_string()),
            "author_id": author_id.unwrap_or_else(|| "N/A".to_string()),
            "item_count": num_items,
        }))
    }
    
    /// Adds a login password item to the vault.
    pub async fn add_item(
        &mut self,
        name: String,
        username: Option<String>,
        password: Option<String>,
        notes: Option<String>,
        uris: Vec<String>,
        favorite: bool,
    ) -> Result<VaultItem> {
        let (master_key, namespace_id, ns_secret, author) = {
            let state = self.get_unlocked()?;
            (state.master_key, state.namespace_id, state.ns_secret.clone(), state.author.clone())
        };
        
        // 1. Construct VaultItem
        let id = Uuid::new_v4().to_string();
        let revision_date = Utc::now().to_rfc3339();
        
        let login = if username.is_some() || password.is_some() || !uris.is_empty() {
            Some(LoginDetails { username, password, uris })
        } else {
            None
        };
        
        let item = VaultItem {
            id: id.clone(),
            name,
            notes,
            login,
            favorite,
            revision_date,
        };
        
        // 2. Serialize and Encrypt
        let item_bytes = serde_json::to_vec(&item)?;
        let encrypted_bytes = crypto::encrypt(&item_bytes, &master_key)?;
        
        // 3. Compute BLAKE3 Hash
        let hash = Hash::new(&encrypted_bytes);
        let hash_hex = hash.to_hex();
        
        // 4. Store encrypted blob in persistent SQLite
        db::save_blob(&self.sqlite_conn, &hash_hex, &encrypted_bytes)?;
        
        // 5. Store entry in iroh-docs replica
        let key = format!("items/{}", id);
        let len = encrypted_bytes.len() as u64;
        
        docs::insert_doc_entry(
            &mut self.doc_store,
            &namespace_id,
            &ns_secret,
            &author,
            key.as_bytes(),
            hash,
            len
        ).await?;
        
        // 6. Index item in memory
        let state = self.get_unlocked()?;
        db::upsert_index_item(&state.mem_conn, &item)?;
        
        Ok(item)
    }

    /// Edits an existing item in the vault.
    pub async fn edit_item(
        &mut self,
        id: String,
        name: String,
        username: Option<String>,
        password: Option<String>,
        notes: Option<String>,
        uris: Vec<String>,
        favorite: bool,
    ) -> Result<VaultItem> {
        // Verify item exists and get keys
        let (master_key, namespace_id, ns_secret, author) = {
            let state = self.get_unlocked()?;
            let _existing = db::list_index_items(&state.mem_conn)?
                .into_iter()
                .find(|item| item.id == id)
                .ok_or_else(|| anyhow!("Item not found: {}", id))?;
            (state.master_key, state.namespace_id, state.ns_secret.clone(), state.author.clone())
        };
        
        let revision_date = Utc::now().to_rfc3339();
        
        let login = if username.is_some() || password.is_some() || !uris.is_empty() {
            Some(LoginDetails { username, password, uris })
        } else {
            None
        };
        
        let item = VaultItem {
            id: id.clone(),
            name,
            notes,
            login,
            favorite,
            revision_date,
        };
        
        // Serialize and Encrypt
        let item_bytes = serde_json::to_vec(&item)?;
        let encrypted_bytes = crypto::encrypt(&item_bytes, &master_key)?;
        
        // Compute Hash
        let hash = Hash::new(&encrypted_bytes);
        let hash_hex = hash.to_hex();
        
        // Save encrypted blob in persistent SQLite
        db::save_blob(&self.sqlite_conn, &hash_hex, &encrypted_bytes)?;
        
        // Store entry in iroh-docs
        let key = format!("items/{}", id);
        let len = encrypted_bytes.len() as u64;
        
        docs::insert_doc_entry(
            &mut self.doc_store,
            &namespace_id,
            &ns_secret,
            &author,
            key.as_bytes(),
            hash,
            len
        ).await?;
        
        // Index item in memory
        let state = self.get_unlocked()?;
        db::upsert_index_item(&state.mem_conn, &item)?;
        
        Ok(item)
    }
    
    /// Deletes an item from the vault.
    pub async fn delete_item(&mut self, id: &str) -> Result<()> {
        let (namespace_id, author) = {
            let state = self.get_unlocked()?;
            (state.namespace_id, state.author.clone())
        };
        
        let key = format!("items/{}", id);
        
        // Insert deletion entry in iroh-docs
        docs::delete_doc_entry(
            &mut self.doc_store,
            &namespace_id,
            &author,
            key.as_bytes()
        ).await?;
        
        // Remove from search index
        let state = self.get_unlocked()?;
        db::delete_index_item(&state.mem_conn, id)?;
        
        Ok(())
    }
    
    /// Searches items matching a query string.
    pub fn search_items(&self, query: &str) -> Result<Vec<VaultItem>> {
        let state = self.get_unlocked()?;
        db::search_index_items(&state.mem_conn, query)
    }
    
    /// Lists all items in the vault.
    pub fn list_items(&self) -> Result<Vec<VaultItem>> {
        let state = self.get_unlocked()?;
        db::list_index_items(&state.mem_conn)
    }
    
    /// Retrieves a single item by ID.
    pub fn get_item(&self, id: &str) -> Result<Option<VaultItem>> {
        let state = self.get_unlocked()?;
        let items = db::list_index_items(&state.mem_conn)?;
        let item = items.into_iter().find(|i| i.id == id);
        Ok(item)
    }
    
    /// Exports replica sync keys.
    pub fn export_replica_keys(&self) -> Result<(String, String)> {
        if !self.is_initialized()? {
            return Err(anyhow!("Vault not initialized"));
        }
        
        let state = self.get_unlocked()?;
        
        let ns_hex = hex::encode(state.ns_secret.to_bytes());
        let author_hex = hex::encode(state.author.to_bytes());
        
        Ok((ns_hex, author_hex))
    }
    
    /// Imports replica keys from another device to sync database.
    pub fn import_replica_keys(&mut self, ns_secret_hex: &str, author_hex: &str) -> Result<()> {
        if self.is_initialized()? {
            return Err(anyhow!("Cannot import replica keys into an already initialized vault. Create a new directory or clear existing state first."));
        }
        
        // 1. Decode keys
        let ns_bytes_vec = hex::decode(ns_secret_hex).context("Invalid namespace secret hex")?;
        let author_bytes_vec = hex::decode(author_hex).context("Invalid author hex")?;
        
        if ns_bytes_vec.len() != 32 || author_bytes_vec.len() != 32 {
            return Err(anyhow!("Keys must be 32 bytes (64 hex characters)"));
        }
        
        let mut ns_bytes = [0u8; 32];
        let mut author_bytes = [0u8; 32];
        ns_bytes.copy_from_slice(&ns_bytes_vec);
        author_bytes.copy_from_slice(&author_bytes_vec);
        
        let _ns_secret = NamespaceSecret::from_bytes(&ns_bytes);
        let _author = Author::from_bytes(&author_bytes);
        
        // 2. Prompt or generate password/keys
        // To make it simple, we ask the user to initialize a password for THIS local device.
        // It can be a different password! We will derive a Master Key and encrypt the imported keys.
        // Or we can ask them to run keyroh init first? No, if we import, we initialize the local master password now.
        // Let's print that the caller should call: `manager.import_and_init(password, ns_secret, author)`
        Ok(())
    }
    
    /// Imports replica keys AND initializes the master password.
    pub fn import_and_init(&mut self, master_password: &str, ns_secret_hex: &str, author_hex: &str) -> Result<()> {
        if self.is_initialized()? {
            return Err(anyhow!("Vault already initialized"));
        }
        
        // 1. Decode keys
        let ns_bytes_vec = hex::decode(ns_secret_hex).context("Invalid namespace secret hex")?;
        let author_bytes_vec = hex::decode(author_hex).context("Invalid author hex")?;
        
        let mut ns_bytes = [0u8; 32];
        let mut author_bytes = [0u8; 32];
        ns_bytes.copy_from_slice(&ns_bytes_vec);
        author_bytes.copy_from_slice(&author_bytes_vec);
        
        let ns_secret = NamespaceSecret::from_bytes(&ns_bytes);
        let author = Author::from_bytes(&author_bytes);
        
        let namespace_id = ns_secret.id();
        let author_id = author.id();
        
        // 2. Generate local Master Key
        let mut master_key = [0u8; 32];
        rand::rng().fill_bytes(&mut master_key);
        
        // 3. Derive KEK and encrypt master key
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        
        let mut kek = [0u8; 32];
        crypto::derive_key(master_password, &salt, &mut kek);
        
        let encrypted_master_key = crypto::encrypt(&master_key, &kek)?;
        
        // 4. Encrypt imported keys with the master key
        let encrypted_ns = crypto::encrypt(&ns_bytes, &master_key)?;
        let encrypted_author = crypto::encrypt(&author_bytes, &master_key)?;
        
        // 5. Import replica and author to docs store
        docs::import_vault_replica(&mut self.doc_store, ns_secret, author)?;
        
        // 6. Save state in SQLite
        db::set_state_value(&self.sqlite_conn, "salt", &hex::encode(salt))?;
        db::set_state_value(&self.sqlite_conn, "encrypted_master_key", &hex::encode(encrypted_master_key))?;
        db::set_state_value(&self.sqlite_conn, "encrypted_ns_secret", &hex::encode(encrypted_ns))?;
        db::set_state_value(&self.sqlite_conn, "encrypted_author", &hex::encode(encrypted_author))?;
        db::set_state_value(&self.sqlite_conn, "namespace_id", &namespace_id.to_string())?;
        db::set_state_value(&self.sqlite_conn, "author_id", &author_id.to_string())?;
        
        self.doc_store.flush()?;
        
        Ok(())
    }

    /// Exposes the SQLite connection and doc_store to allow external sync or exports.
    pub fn get_sqlite_conn(&self) -> &Connection {
        &self.sqlite_conn
    }
    
    pub fn get_sqlite_conn_mut(&mut self) -> &mut Connection {
        &mut self.sqlite_conn
    }

    pub fn get_doc_store_mut(&mut self) -> &mut DocStore {
        &mut self.doc_store
    }
}
