use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use iroh_docs::{Author, AuthorId, NamespaceId, NamespaceSecret};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto;
use crate::iroh;
use crate::vault::{CustomField, LoginDetails, VaultItem};

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct LocalState {
    pub salt: String,
    pub encrypted_master_key: String,
    pub encrypted_ns_secret: String,
    pub encrypted_author: String,
    pub namespace_id: String,
    pub author_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyrohSyncTicket {
    pub iroh_ticket: String,
    pub salt: String,
    pub encrypted_master_key: String,
}

#[derive(Clone)]
pub struct MasterKey(Box<[u8; 32]>);

impl MasterKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        let mut inner = Box::new(bytes);
        #[cfg(target_os = "linux")]
        unsafe {
            let addr = inner.as_mut_ptr() as *mut libc::c_void;
            let len = inner.len();
            let _ = libc::mlock(addr, len);
        }
        Self(inner)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.as_mut().zeroize();
        #[cfg(target_os = "linux")]
        unsafe {
            let addr = self.0.as_mut_ptr() as *mut libc::c_void;
            let len = self.0.len();
            let _ = libc::munlock(addr, len);
        }
    }
}

impl zeroize::Zeroize for MasterKey {
    fn zeroize(&mut self) {
        self.0.as_mut().zeroize();
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey(***REDACTED***)")
    }
}

impl PartialEq for MasterKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

pub struct UnlockedState {
    pub master_key: MasterKey,
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
    iroh: crate::iroh::Iroh,
    unlocked: Option<UnlockedState>,
}

impl VaultManager {
    /// Opens the vault manager, initializing directories.
    pub async fn open(base_dir: &Path) -> Result<Self> {
        let iroh = crate::iroh::Iroh::new(base_dir.to_path_buf()).await?;

        Ok(VaultManager {
            base_dir: base_dir.to_path_buf(),
            iroh,
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
    pub async fn init(&mut self, master_password: &str) -> Result<()> {
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
        let (ns_secret, author) = iroh::create_vault_replica(self.iroh.docs()).await?;
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

        Ok(())
    }

    /// Unlocks the vault with the master password, decrypting the master key.
    /// Returns the decrypted master key as hex (wrapped in Zeroizing).
    pub async fn unlock(&mut self, master_password: &str) -> Result<zeroize::Zeroizing<String>> {
        if !self.is_initialized()? {
            return Err(anyhow!("Vault has not been initialized. Run init first."));
        }

        // 1. Fetch salt and encrypted master key
        let state_path = self.base_dir.join("state.json");
        let state_str = std::fs::read_to_string(&state_path)?;
        let state: LocalState = serde_json::from_str(&state_str)?;

        let salt = hex::decode(&state.salt).context("Failed to decode salt hex")?;
        let enc_master_key = hex::decode(&state.encrypted_master_key)
            .context("Failed to decode encrypted master key hex")?;

        // 2. Derive KEK
        let mut kek = [0u8; 32];
        crypto::derive_key(master_password, &salt, &mut kek);

        // 3. Decrypt master key
        let mut master_key_vec = crypto::decrypt(&enc_master_key, &kek)
            .map_err(|_| anyhow!("Incorrect master password"))?;

        let mut master_key_raw = [0u8; 32];
        master_key_raw.copy_from_slice(&master_key_vec);

        let master_key = MasterKey::new(master_key_raw);
        master_key_raw.zeroize();

        let master_key_hex = zeroize::Zeroizing::new(hex::encode(master_key.as_bytes()));

        // 4. Open index
        self.load_unlocked_state(master_key).await?;

        kek.zeroize();
        master_key_vec.zeroize();

        Ok(master_key_hex)
    }

    /// Unlocks the vault with a pre-decrypted master key hex (e.g. from environment variable).
    pub async fn unlock_with_session(&mut self, session_key_hex: &str) -> Result<()> {
        let mut master_key_vec =
            hex::decode(session_key_hex).context("Invalid session key format")?;

        if master_key_vec.len() != 32 {
            return Err(anyhow!("Session key must be 32 bytes (64 hex characters)"));
        }

        let mut master_key_raw = [0u8; 32];
        master_key_raw.copy_from_slice(&master_key_vec);

        let master_key = MasterKey::new(master_key_raw);
        master_key_raw.zeroize();

        self.load_unlocked_state(master_key).await?;

        master_key_vec.zeroize();
        Ok(())
    }

    /// Helper to populate decrypted states into memory.
    async fn load_unlocked_state(&mut self, master_key: MasterKey) -> Result<()> {
        // 1. Fetch encrypted replica secrets
        let state_path = self.base_dir.join("state.json");
        let state_str = std::fs::read_to_string(&state_path)?;
        let state: LocalState = serde_json::from_str(&state_str)?;

        let enc_ns = hex::decode(&state.encrypted_ns_secret)?;
        let enc_author = hex::decode(&state.encrypted_author)?;

        // 2. Decrypt replica keys
        let mut ns_bytes_vec = crypto::decrypt(&enc_ns, master_key.as_bytes())
            .context("Failed to decrypt namespace secret")?;
        let mut author_bytes_vec = crypto::decrypt(&enc_author, master_key.as_bytes())
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
        let entries = iroh::get_replica_entries(self.iroh.docs(), namespace_id).await?;

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

                // Fetch encrypted blob from iroh-blobs
                if let Ok(enc_content) = self.iroh.blobs().get_bytes(content_hash).await {
                    // Decrypt blob
                    if let Ok(dec_bytes) = crypto::decrypt(&enc_content, master_key.as_bytes()) {
                        // Parse VaultItem
                        if let Ok(item) = serde_json::from_slice::<VaultItem>(&dec_bytes) {
                            items.retain(|existing: &VaultItem| existing.id != item.id);
                            items.push(item);
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

    pub async fn refresh_items(&mut self) -> Result<()> {
        let master_key = if let Some(ref state) = self.unlocked {
            state.master_key.clone()
        } else {
            return Err(anyhow!("Vault is locked"));
        };
        self.load_unlocked_state(master_key).await?;
        Ok(())
    }

    /// Locks the vault, discarding memory keys and search indexes.
    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    /// Gets the UnlockedState, returning error if locked.
    fn get_unlocked(&self) -> Result<&UnlockedState> {
        self.unlocked
            .as_ref()
            .ok_or_else(|| anyhow!("Vault is locked. Export KEYROH_SESSION or run unlock command."))
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
        let (master_key, namespace_id, _ns_secret, author) = {
            let state = self.get_unlocked()?;
            (
                state.master_key.clone(),
                state.namespace_id,
                state.ns_secret.clone(),
                state.author.clone(),
            )
        };

        // 1. Construct VaultItem
        let id = Uuid::new_v4().to_string();
        let revision_date = Utc::now().to_rfc3339();

        let login =
            if username.is_some() || password.is_some() || totp.is_some() || !uris.is_empty() {
                Some(LoginDetails {
                    username,
                    password,
                    uris,
                    totp,
                })
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
        let encrypted_bytes = crypto::encrypt(&item_bytes, master_key.as_bytes())?;

        // 3. Store entry in iroh-docs and blobs store
        let key = format!("items/{}", id);

        iroh::insert_doc_bytes(
            self.iroh.docs(),
            &namespace_id,
            &author,
            key.as_bytes(),
            encrypted_bytes.into(),
        )
        .await?;

        // 4. Index item in memory
        if let Some(ref mut state) = self.unlocked {
            state
                .items
                .retain(|existing: &VaultItem| existing.id != item.id);
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
        let (master_key, namespace_id, _ns_secret, author) = {
            let state = self.get_unlocked()?;
            let _existing = state
                .items
                .iter()
                .find(|item| item.id == id)
                .ok_or_else(|| anyhow!("Item not found: {}", id))?;
            (
                state.master_key.clone(),
                state.namespace_id,
                state.ns_secret.clone(),
                state.author.clone(),
            )
        };

        let revision_date = Utc::now().to_rfc3339();

        let login =
            if username.is_some() || password.is_some() || totp.is_some() || !uris.is_empty() {
                Some(LoginDetails {
                    username,
                    password,
                    uris,
                    totp,
                })
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
        let encrypted_bytes = crypto::encrypt(&item_bytes, master_key.as_bytes())?;

        // Store entry in iroh-docs and blobs store
        let key = format!("items/{}", id);

        iroh::insert_doc_bytes(
            self.iroh.docs(),
            &namespace_id,
            &author,
            key.as_bytes(),
            encrypted_bytes.into(),
        )
        .await?;

        // Index item in memory
        if let Some(ref mut state) = self.unlocked {
            state
                .items
                .retain(|existing: &VaultItem| existing.id != item.id);
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
        iroh::delete_doc_entry(self.iroh.docs(), &namespace_id, &author, key.as_bytes()).await?;

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
        let mut filtered: Vec<VaultItem> = state
            .items
            .iter()
            .filter(|item| {
                item.name.to_lowercase().contains(&query_lower)
                    || item.login.as_ref().map_or(false, |l| {
                        l.username
                            .as_ref()
                            .map_or(false, |u| u.to_lowercase().contains(&query_lower))
                            || l.uris
                                .iter()
                                .any(|uri| uri.to_lowercase().contains(&query_lower))
                    })
                    || item
                        .notes
                        .as_ref()
                        .map_or(false, |n| n.to_lowercase().contains(&query_lower))
            })
            .cloned()
            .collect();

        filtered.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        Ok(filtered)
    }

    /// Lists all items in the vault.
    pub fn list_items(&self) -> Result<Vec<VaultItem>> {
        let state = self.get_unlocked()?;
        let mut items = state.items.clone();
        items.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
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

    /// Exports a replication sync ticket.
    pub async fn export_sync_ticket(&self) -> Result<String> {
        if !self.is_initialized()? {
            return Err(anyhow!("Vault not initialized"));
        }

        let state = self.get_unlocked()?;
        // Fetch iroh DocTicket
        let iroh_ticket = iroh::export_vault_ticket(self.iroh.docs(), state.namespace_id).await?;

        // Read salt and encrypted_master_key from state.json
        let state_path = self.base_dir.join("state.json");
        let state_str = std::fs::read_to_string(&state_path)?;
        let local_state: LocalState = serde_json::from_str(&state_str)?;

        let custom_ticket = KeyrohSyncTicket {
            iroh_ticket,
            salt: local_state.salt,
            encrypted_master_key: local_state.encrypted_master_key,
        };

        let json_str = serde_json::to_string(&custom_ticket)?;
        let ticket_hex = hex::encode(json_str);

        Ok(format!("keyroh:{}", ticket_hex))
    }

    /// Imports a replica sync ticket AND initializes the master password.
    pub async fn import_and_init(&mut self, master_password: &str, ticket_str: &str) -> Result<()> {
        if self.is_initialized()? {
            return Err(anyhow!("Vault already initialized"));
        }

        // 1. Parse and validate the custom ticket
        let ticket_str = ticket_str.trim();
        let hex_data = if let Some(stripped) = ticket_str.strip_prefix("keyroh:") {
            stripped
        } else {
            return Err(anyhow!("Invalid sync ticket: missing 'keyroh:' prefix"));
        };

        let json_bytes =
            hex::decode(hex_data).context("Invalid sync ticket: not valid hex data")?;
        let custom_ticket: KeyrohSyncTicket =
            serde_json::from_slice(&json_bytes).context("Invalid sync ticket JSON structure")?;

        // 2. Decode KEK from master_password and ticket's salt
        let src_salt = hex::decode(&custom_ticket.salt).context("Invalid salt in ticket")?;
        let src_enc_master_key = hex::decode(&custom_ticket.encrypted_master_key)
            .context("Invalid encrypted master key in ticket")?;

        let mut src_kek = [0u8; 32];
        crypto::derive_key(master_password, &src_salt, &mut src_kek);

        // 3. Decrypt the master key from the ticket
        let mut master_key_vec = crypto::decrypt(&src_enc_master_key, &src_kek)
            .map_err(|_| anyhow!("Incorrect master password for the synced vault"))?;

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_vec);

        // 4. Parse the Iroh DocTicket
        let ticket = iroh_docs::DocTicket::from_str(&custom_ticket.iroh_ticket)
            .context("Invalid iroh doc ticket string in ticket")?;

        // 5. Import the iroh doc ticket to start synchronization
        let (ns_secret, author) = iroh::import_vault_ticket(self.iroh.docs(), ticket).await?;

        let namespace_id = ns_secret.id();
        let author_id = author.id();

        // 6. Generate a NEW local salt for this device
        let mut local_salt = [0u8; 16];
        rand::rng().fill_bytes(&mut local_salt);

        let mut local_kek = [0u8; 32];
        crypto::derive_key(master_password, &local_salt, &mut local_kek);

        // 7. Encrypt the master key with the local KEK
        let encrypted_master_key = crypto::encrypt(&master_key, &local_kek)?;

        // 8. Encrypt the replica keys with the master key
        let mut ns_bytes = ns_secret.to_bytes();
        let mut author_bytes = author.to_bytes();

        let encrypted_ns = crypto::encrypt(&ns_bytes, &master_key)?;
        let encrypted_author = crypto::encrypt(&author_bytes, &master_key)?;

        let mut ns_bytes_vec = ns_bytes.to_vec();
        let mut author_bytes_vec = author_bytes.to_vec();
        ns_bytes_vec.zeroize();
        author_bytes_vec.zeroize();
        ns_bytes.zeroize();
        author_bytes.zeroize();
        master_key_vec.zeroize();
        master_key.zeroize();
        src_kek.zeroize();
        local_kek.zeroize();

        // 9. Save everything in local state.json file
        let state = LocalState {
            salt: hex::encode(local_salt),
            encrypted_master_key: hex::encode(encrypted_master_key),
            encrypted_ns_secret: hex::encode(encrypted_ns),
            encrypted_author: hex::encode(encrypted_author),
            namespace_id: namespace_id.to_string(),
            author_id: author_id.to_string(),
        };
        let state_path = self.base_dir.join("state.json");
        let state_str = serde_json::to_string_pretty(&state)?;
        std::fs::write(state_path, state_str)?;

        Ok(())
    }

    /// Gracefully shuts down the iroh P2P stack.
    ///
    /// This ensures:
    /// - The iroh `Router` has closed all open connections cleanly.
    /// - The `Docs` and `FsStore` (blobs) actors have processed all pending
    ///   in-flight writes and closed their SQLite / file handles.
    /// - `UnlockedState` (and the master key in memory) is dropped and zeroed.
    ///
    /// Always call this before process exit to avoid partial SQLite WAL frames
    /// or in-flight blob data remaining unmerged.
    pub async fn shutdown(&mut self) -> Result<()> {
        // Zero and drop the unlocked state (master key) first
        drop(self.unlocked.take());

        // Clone the iroh handle (it is Arc-backed) and shut down
        let iroh = self.iroh.clone();
        iroh.shutdown().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_sync_ticket_import_export() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();

        let mut dev1 = VaultManager::open(dir1.path()).await.unwrap();
        let mut dev2 = VaultManager::open(dir2.path()).await.unwrap();

        let password = "super_secure_password_123";

        // Initialize dev1
        dev1.init(password).await.unwrap();
        let master_key_hex1 = dev1.unlock(password).await.unwrap();

        // Add an item to dev1
        let _item = dev1
            .add_item(
                "Test Account".to_string(),
                Some("user1".to_string()),
                Some("pass1".to_string()),
                None,
                None,
                vec![],
                false,
                vec![],
                None,
            )
            .await
            .unwrap();

        // Export ticket
        let ticket = dev1.export_sync_ticket().await.unwrap();
        assert!(ticket.starts_with("keyroh:"));

        // Import on dev2
        dev2.import_and_init(password, &ticket).await.unwrap();

        // Unlock dev2
        let master_key_hex2 = dev2.unlock(password).await.unwrap();

        // Verify master keys match exactly!
        assert_eq!(master_key_hex1, master_key_hex2);

        let unlocked1 = dev1.get_unlocked().unwrap();
        let unlocked2 = dev2.get_unlocked().unwrap();
        assert_eq!(unlocked1.master_key, unlocked2.master_key);
        assert_eq!(unlocked1.namespace_id, unlocked2.namespace_id);
    }
}
