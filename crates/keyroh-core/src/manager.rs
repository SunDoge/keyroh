use std::path::{Path, PathBuf};
use anyhow::{anyhow, Context, Result};
use iroh_docs::store::fs::Store as DocStore;
use iroh_docs::{NamespaceSecret, NamespaceId, Author, AuthorId};
use iroh_blobs::Hash;
use chrono::Utc;
use uuid::Uuid;
use rand::Rng;
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

use crate::vault::{VaultItem, LoginDetails, CustomField};
use crate::crypto;
use crate::docs;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct LocalState {
    pub salt: String,
    pub encrypted_master_key: String,
    pub encrypted_ns_secret: String,
    pub encrypted_author: String,
    pub namespace_id: String,
    pub author_id: String,
}

pub struct UnlockedState {
    pub master_key: [u8; 32],
    pub ns_secret: NamespaceSecret,
    pub author: Author,
    pub namespace_id: NamespaceId,
    pub author_id: AuthorId,
    pub items: Vec<VaultItem>,
}

impl Drop for UnlockedState {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

pub struct VaultManager {
    base_dir: PathBuf,
    doc_store: DocStore,
    unlocked: Option<UnlockedState>,
}

impl VaultManager {
    /// Opens the vault manager, initializing directories.
    pub fn open(base_dir: &Path) -> Result<Self> {
        // Create base directory and blobs directory
        std::fs::create_dir_all(base_dir)
            .context("Failed to create vault data directory")?;
        std::fs::create_dir_all(base_dir.join("blobs"))
            .context("Failed to create vault blobs directory")?;
            
        let docs_path = base_dir.join("docs.db");
        let doc_store = docs::open_doc_store(&docs_path)?;
        
        Ok(VaultManager {
            base_dir: base_dir.to_path_buf(),
            doc_store,
            unlocked: None,
        })
    }
    
    /// Checks if the vault has been initialized.
    pub fn is_initialized(&self) -> Result<bool> {
        let state_path = self.base_dir.join("state.json");
        if !state_path.exists() {
            return Ok(false);
        }
        let state_str = std::fs::read_to_string(&state_path)?;
        let state: LocalState = serde_json::from_str(&state_str)?;
        Ok(!state.salt.is_empty() && !state.encrypted_master_key.is_empty())
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
        let mut ns_bytes = ns_secret.to_bytes();
        let mut author_bytes = author.to_bytes();
        
        let encrypted_ns = crypto::encrypt(&ns_bytes, &master_key)?;
        let encrypted_author = crypto::encrypt(&author_bytes, &master_key)?;
        
        master_key.zeroize();
        kek.zeroize();
        ns_bytes.zeroize();
        author_bytes.zeroize();
        
        // 5. Store everything in persistent JSON file
        let state = LocalState {
            salt: hex::encode(salt),
            encrypted_master_key: hex::encode(encrypted_master_key),
            encrypted_ns_secret: hex::encode(encrypted_ns),
            encrypted_author: hex::encode(encrypted_author),
            namespace_id: namespace_id.to_string(),
            author_id: author_id.to_string(),
        };
        let state_path = self.base_dir.join("state.json");
        let state_str = serde_json::to_string_pretty(&state)?;
        std::fs::write(state_path, state_str)?;
        
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
        let state_path = self.base_dir.join("state.json");
        let state_str = std::fs::read_to_string(&state_path)?;
        let state: LocalState = serde_json::from_str(&state_str)?;
            
        let salt = hex::decode(&state.salt).context("Failed to decode salt hex")?;
        let enc_master_key = hex::decode(&state.encrypted_master_key).context("Failed to decode encrypted master key hex")?;
        
        // 2. Derive KEK
        let mut kek = [0u8; 32];
        crypto::derive_key(master_password, &salt, &mut kek);
        
        // 3. Decrypt master key
        let mut master_key_vec = crypto::decrypt(&enc_master_key, &kek)
            .map_err(|_| anyhow!("Incorrect master password"))?;
            
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_vec);
        
        let master_key_hex = hex::encode(master_key);
        
        // 4. Open index
        self.load_unlocked_state(master_key)?;
        
        kek.zeroize();
        master_key_vec.zeroize();
        master_key.zeroize();
        
        Ok(master_key_hex)
    }
    
    /// Unlocks the vault with a pre-decrypted master key hex (e.g. from environment variable).
    pub fn unlock_with_session(&mut self, session_key_hex: &str) -> Result<()> {
        let mut master_key_vec = hex::decode(session_key_hex)
            .context("Invalid session key format")?;
            
        if master_key_vec.len() != 32 {
            return Err(anyhow!("Session key must be 32 bytes (64 hex characters)"));
        }
        
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_vec);
        
        self.load_unlocked_state(master_key)?;
        
        master_key_vec.zeroize();
        master_key.zeroize();
        Ok(())
    }
    
    /// Helper to populate decrypted states into memory.
    fn load_unlocked_state(&mut self, master_key: [u8; 32]) -> Result<()> {
        // 1. Fetch encrypted replica secrets
        let state_path = self.base_dir.join("state.json");
        let state_str = std::fs::read_to_string(&state_path)?;
        let state: LocalState = serde_json::from_str(&state_str)?;
            
        let enc_ns = hex::decode(&state.encrypted_ns_secret)?;
        let enc_author = hex::decode(&state.encrypted_author)?;
        
        // 2. Decrypt replica keys
        let mut ns_bytes_vec = crypto::decrypt(&enc_ns, &master_key)
            .context("Failed to decrypt namespace secret")?;
        let mut author_bytes_vec = crypto::decrypt(&enc_author, &master_key)
            .context("Failed to decrypt author")?;
            
        let mut ns_bytes = [0u8; 32];
        let mut author_bytes = [0u8; 32];
        ns_bytes.copy_from_slice(&ns_bytes_vec);
        author_bytes.copy_from_slice(&author_bytes_vec);
        
        let ns_secret = NamespaceSecret::from_bytes(&ns_bytes);
        let author = Author::from_bytes(&author_bytes);
        
        ns_bytes_vec.zeroize();
        author_bytes_vec.zeroize();
        ns_bytes.zeroize();
        author_bytes.zeroize();
        
        let namespace_id = ns_secret.id();
        let author_id = author.id();
        
        // 3. Load replica entries from iroh-docs and populate memory list
        let mut items = Vec::new();
        let entries = docs::get_replica_entries(&mut self.doc_store, namespace_id)?;
        
        for signed_entry in entries {
            let key = signed_entry.key();
            let key_str = String::from_utf8_lossy(key);
            
            // Vault item keys look like: "items/<uuid>"
            if key_str.starts_with("items/") {
                let id = &key_str["items/".len()..];
                // If content len is 0, it means it is a tombstone / deleted entry
                if signed_entry.content_len() == 0 {
                    items.retain(|item: &VaultItem| item.id != id);
                    continue;
                }
                
                let content_hash = signed_entry.content_hash();
                let hash_hex = content_hash.to_hex();
                
                // Fetch encrypted blob from flat file
                let blob_path = self.base_dir.join("blobs").join(&hash_hex);
                if blob_path.exists() {
                    if let Ok(enc_content) = std::fs::read(&blob_path) {
                        // Decrypt blob
                        if let Ok(dec_bytes) = crypto::decrypt(&enc_content, &master_key) {
                            // Parse VaultItem
                            if let Ok(item) = serde_json::from_slice::<VaultItem>(&dec_bytes) {
                                items.retain(|existing: &VaultItem| existing.id != item.id);
                                items.push(item);
                            }
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
            items,
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
    

    
    /// Returns basic details about the current replica configuration.
    pub fn get_status(&self) -> Result<serde_json::Value> {
        let is_init = self.is_initialized()?;
        let is_unlocked = self.unlocked.is_some();
        
        let (namespace_id, author_id, num_items) = if is_init {
            let state_path = self.base_dir.join("state.json");
            let state_str = std::fs::read_to_string(&state_path)?;
            let state: LocalState = serde_json::from_str(&state_str)?;
            let count = if let Some(ref state_unlocked) = self.unlocked {
                state_unlocked.items.len()
            } else {
                0
            };
            (state.namespace_id, state.author_id, count)
        } else {
            ("N/A".to_string(), "N/A".to_string(), 0)
        };
        
        Ok(serde_json::json!({
            "initialized": is_init,
            "unlocked": is_unlocked,
            "namespace_id": namespace_id,
            "author_id": author_id,
            "item_count": num_items,
        }))
    }
    
    /// Adds a login password item to the vault.
    pub async fn add_item(
        &mut self,
        name: String,
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        notes: Option<String>,
        uris: Vec<String>,
        favorite: bool,
        fields: Vec<CustomField>,
        folder_id: Option<String>,
    ) -> Result<VaultItem> {
        let (master_key, namespace_id, ns_secret, author) = {
            let state = self.get_unlocked()?;
            (state.master_key, state.namespace_id, state.ns_secret.clone(), state.author.clone())
        };
        
        // 1. Construct VaultItem
        let id = Uuid::new_v4().to_string();
        let revision_date = Utc::now().to_rfc3339();
        
        let login = if username.is_some() || password.is_some() || totp.is_some() || !uris.is_empty() {
            Some(LoginDetails { username, password, uris, totp })
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
            folder_id,
            fields,
        };
        
        // 2. Serialize and Encrypt
        let item_bytes = serde_json::to_vec(&item)?;
        let encrypted_bytes = crypto::encrypt(&item_bytes, &master_key)?;
        
        // 3. Compute BLAKE3 Hash
        let hash = Hash::new(&encrypted_bytes);
        let hash_hex = hash.to_hex();
        
        // 4. Store encrypted blob in flat file
        let blobs_dir = self.base_dir.join("blobs");
        std::fs::create_dir_all(&blobs_dir)?;
        std::fs::write(blobs_dir.join(&hash_hex), &encrypted_bytes)?;
        
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
        if let Some(ref mut state) = self.unlocked {
            state.items.retain(|existing: &VaultItem| existing.id != item.id);
            state.items.push(item.clone());
        }
        
        Ok(item)
    }

    /// Edits an existing item in the vault.
    pub async fn edit_item(
        &mut self,
        id: String,
        name: String,
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        notes: Option<String>,
        uris: Vec<String>,
        favorite: bool,
        fields: Vec<CustomField>,
        folder_id: Option<String>,
    ) -> Result<VaultItem> {
        // Verify item exists and get keys
        let (master_key, namespace_id, ns_secret, author) = {
            let state = self.get_unlocked()?;
            let _existing = state.items.iter()
                .find(|item| item.id == id)
                .ok_or_else(|| anyhow!("Item not found: {}", id))?;
            (state.master_key, state.namespace_id, state.ns_secret.clone(), state.author.clone())
        };
        
        let revision_date = Utc::now().to_rfc3339();
        
        let login = if username.is_some() || password.is_some() || totp.is_some() || !uris.is_empty() {
            Some(LoginDetails { username, password, uris, totp })
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
            folder_id,
            fields,
        };
        
        // Serialize and Encrypt
        let item_bytes = serde_json::to_vec(&item)?;
        let encrypted_bytes = crypto::encrypt(&item_bytes, &master_key)?;
        
        // Compute Hash
        let hash = Hash::new(&encrypted_bytes);
        let hash_hex = hash.to_hex();
        
        // Save encrypted blob in flat file
        let blobs_dir = self.base_dir.join("blobs");
        std::fs::create_dir_all(&blobs_dir)?;
        std::fs::write(blobs_dir.join(&hash_hex), &encrypted_bytes)?;
        
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
        if let Some(ref mut state) = self.unlocked {
            state.items.retain(|existing: &VaultItem| existing.id != item.id);
            state.items.push(item.clone());
        }
        
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
        
        // Remove from memory
        if let Some(ref mut state) = self.unlocked {
            state.items.retain(|existing: &VaultItem| existing.id != id);
        }
        
        Ok(())
    }
    
    /// Searches items matching a query string.
    pub fn search_items(&self, query: &str) -> Result<Vec<VaultItem>> {
        let state = self.get_unlocked()?;
        let query_lower = query.to_lowercase();
        let mut filtered: Vec<VaultItem> = state.items.iter()
            .filter(|item| {
                item.name.to_lowercase().contains(&query_lower)
                    || item.login.as_ref().map_or(false, |l| {
                        l.username.as_ref().map_or(false, |u| u.to_lowercase().contains(&query_lower))
                            || l.uris.iter().any(|uri| uri.to_lowercase().contains(&query_lower))
                    })
                    || item.notes.as_ref().map_or(false, |n| n.to_lowercase().contains(&query_lower))
            })
            .cloned()
            .collect();
        
        filtered.sort_by(|a, b| {
            b.favorite.cmp(&a.favorite)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        
        Ok(filtered)
    }
    
    /// Lists all items in the vault.
    pub fn list_items(&self) -> Result<Vec<VaultItem>> {
        let state = self.get_unlocked()?;
        let mut items = state.items.clone();
        items.sort_by(|a, b| {
            b.favorite.cmp(&a.favorite)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(items)
    }
    
    /// Retrieves a single item by ID.
    pub fn get_item(&self, id: &str) -> Result<Option<VaultItem>> {
        let state = self.get_unlocked()?;
        let item = state.items.iter().find(|i| i.id == id).cloned();
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
        
        // Decode keys to validate
        let mut ns_bytes_vec = hex::decode(ns_secret_hex).context("Invalid namespace secret hex")?;
        let mut author_bytes_vec = hex::decode(author_hex).context("Invalid author hex")?;
        
        if ns_bytes_vec.len() != 32 || author_bytes_vec.len() != 32 {
            return Err(anyhow!("Keys must be 32 bytes (64 hex characters)"));
        }
        
        ns_bytes_vec.zeroize();
        author_bytes_vec.zeroize();
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
        
        let mut ns_bytes_vec = ns_bytes_vec;
        let mut author_bytes_vec = author_bytes_vec;
        ns_bytes_vec.zeroize();
        author_bytes_vec.zeroize();
        ns_bytes.zeroize();
        author_bytes.zeroize();
        master_key.zeroize();
        kek.zeroize();
        
        // 6. Save state in JSON file
        let state = LocalState {
            salt: hex::encode(salt),
            encrypted_master_key: hex::encode(encrypted_master_key),
            encrypted_ns_secret: hex::encode(encrypted_ns),
            encrypted_author: hex::encode(encrypted_author),
            namespace_id: namespace_id.to_string(),
            author_id: author_id.to_string(),
        };
        let state_path = self.base_dir.join("state.json");
        let state_str = serde_json::to_string_pretty(&state)?;
        std::fs::write(state_path, state_str)?;
        
        self.doc_store.flush()?;
        
        Ok(())
    }

    pub fn get_doc_store_mut(&mut self) -> &mut DocStore {
        &mut self.doc_store
    }
}
