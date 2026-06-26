use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use futures::stream::Stream;
pub use iroh_docs::engine::LiveEvent;
use iroh_docs::{Author, AuthorId, NamespaceId, NamespaceSecret};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto;
use crate::iroh;
use crate::vault::{CustomField, ItemData, LoginDetails, UriEntry, VaultItem};

/// Outer envelope for every item blob stored in iroh.
///
/// Serialized with msgpack (`rmp-serde`): binary fields are native (no
/// base64) and new named fields can be added without breaking old clients
/// — unknown fields are silently ignored on deserialization.
#[derive(Serialize, Deserialize)]
struct ItemEnvelope {
    /// DEK version used to encrypt `cipher`.  Resolves to `_meta/dek/<dek_v>`.
    dek_v: u32,
    /// AES-256-GCM nonce (12 bytes).
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    /// AES-256-GCM ciphertext (without nonce).
    #[serde(with = "serde_bytes")]
    cipher: Vec<u8>,
}

/// Persisted per-device vault state (state.json).
///
/// The master key is never stored — it is derived on demand via
/// `Argon2id(password, salt)`.  The salt is the single shared secret
/// bootstrapped from the source device during `import_and_init`.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct LocalState {
    /// Hex-encoded 16-byte Argon2id salt, shared across all devices.
    pub salt: String,
    /// AES-256-GCM ciphertext of the iroh NamespaceSecret, keyed by master_key.
    pub encrypted_ns_secret: String,
    /// AES-256-GCM ciphertext of this device's iroh Author key, keyed by master_key.
    pub encrypted_author: String,
    pub namespace_id: String,
    pub author_id: String,
}

#[derive(Clone)]
pub struct MasterKey(Box<[u8; 32]>);

impl MasterKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        #[allow(unused_mut)] // as_mut_ptr() is called in the Linux mlock block
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
    /// All known DEK versions: version number → raw key bytes.
    pub deks: HashMap<u32, [u8; 32]>,
    /// The highest DEK version — used when encrypting new items.
    pub current_dek_version: u32,
}

impl Drop for UnlockedState {
    fn drop(&mut self) {
        self.master_key.zeroize();
        for dek in self.deks.values_mut() {
            dek.zeroize();
        }
    }
}

/// Live P2P network and document status, collected for TUI display.
#[derive(Debug, Clone, Default)]
pub struct SyncInfo {
    /// Local node public key (iroh EndpointId).
    pub node_id: String,
    /// Home relay URL, if connected.
    pub relay_url: Option<String>,
    /// UDP sockets currently bound by the iroh endpoint.
    pub bound_sockets: Vec<String>,
    /// Iroh-docs namespace (document) ID.
    pub namespace_id: String,
    /// Iroh-docs author ID for this device.
    pub author_id: String,
    /// Number of vault items currently loaded in memory.
    pub item_count: usize,
    /// Hex-encoded public keys of known sync peers (from iroh-docs replica).
    pub sync_peers: Vec<String>,
    /// Whether the vault has been initialised on disk.
    pub is_initialized: bool,
    /// Whether the vault is currently unlocked in memory.
    pub is_unlocked: bool,
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
        Ok(!state.salt.is_empty() && !state.encrypted_ns_secret.is_empty())
    }

    /// Initializes a new vault with a master password.
    pub async fn init(&mut self, master_password: &str) -> Result<()> {
        if self.is_initialized()? {
            return Err(anyhow!("Vault is already initialized"));
        }

        // 1. Generate a random salt and derive the master key directly.
        //    master_key = Argon2id(password, salt) — no separate random key needed.
        //    The salt is the only thing that needs to be shared with other devices;
        //    they can derive the same master key from password + salt independently.
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);

        let mut master_key = [0u8; 32];
        crypto::derive_key(master_password, &salt, &mut master_key);

        // 2. Create document replica and author in iroh-docs.
        let (ns_secret, author) = iroh::create_vault_replica(self.iroh.docs()).await?;
        let namespace_id = ns_secret.id();
        let author_id = author.id();

        // 3. Encrypt the iroh replica keys with the master key.
        let mut ns_bytes = ns_secret.to_bytes();
        let mut author_bytes = author.to_bytes();

        let encrypted_ns = crypto::encrypt_blob(&ns_bytes, &master_key)?;
        let encrypted_author = crypto::encrypt_blob(&author_bytes, &master_key)?;

        ns_bytes.zeroize();
        author_bytes.zeroize();

        // 4. Publish the salt as a plaintext entry in the iroh document.
        //    The salt is not secret — Argon2id is designed for a public salt.
        //    Other devices fetch this entry over P2P, combine it with the
        //    password, and derive the same master key locally.
        iroh::insert_doc_bytes(
            self.iroh.docs(),
            &namespace_id,
            &author,
            b"_meta/salt",
            bytes::Bytes::copy_from_slice(&salt),
        )
        .await
        .context("Failed to write salt entry to iroh document")?;

        // Write a password-verification tag: AES-GCM(salt_bytes, master_key).
        // An importing device decrypts this after deriving its master key; if
        // decryption fails the user entered the wrong password and no corrupted
        // state.json is ever written.
        let auth_tag = crypto::encrypt_blob(&salt, &master_key)?;
        iroh::insert_doc_bytes(
            self.iroh.docs(),
            &namespace_id,
            &author,
            b"_meta/auth_tag",
            auth_tag.into(),
        )
        .await
        .context("Failed to write auth tag to iroh document")?;

        // Generate DEK v1 — the random key used to encrypt vault items.
        // Stored encrypted with master_key; iroh key: `_meta/dek/1`.
        let mut dek_v1 = [0u8; 32];
        rand::rng().fill_bytes(&mut dek_v1);
        let enc_dek = crypto::encrypt_blob(&dek_v1, &master_key)?;
        iroh::insert_doc_bytes(
            self.iroh.docs(),
            &namespace_id,
            &author,
            b"_meta/dek/1",
            enc_dek.into(),
        )
        .await
        .context("Failed to write DEK v1 to iroh document")?;
        dek_v1.zeroize();

        master_key.zeroize();

        // 5. Persist state locally.
        let state = LocalState {
            salt: hex::encode(salt),
            encrypted_ns_secret: hex::encode(encrypted_ns),
            encrypted_author: hex::encode(encrypted_author),
            namespace_id: namespace_id.to_string(),
            author_id: author_id.to_string(),
        };
        let state_path = self.base_dir.join("state.json");
        let state_str = serde_json::to_string_pretty(&state)?;
        std::fs::write(&state_path, state_str)?;
        // Restrict state.json to owner-only read/write (0600) so other local
        // users cannot access the encrypted master key or salt.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&state_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&state_path, perms);
            }
        }

        Ok(())
    }

    /// Unlocks the vault by deriving the master key from `password + salt`.
    ///
    /// Returns the derived master key as hex in a `Zeroizing` wrapper so the
    /// caller can export it as `KEYROH_SESSION` for subsequent CLI commands.
    pub async fn unlock(&mut self, master_password: &str) -> Result<zeroize::Zeroizing<String>> {
        if !self.is_initialized()? {
            return Err(anyhow!("Vault has not been initialized. Run init first."));
        }

        let state_path = self.base_dir.join("state.json");
        let state_str = std::fs::read_to_string(&state_path)?;
        let state: LocalState = serde_json::from_str(&state_str)?;

        let salt = hex::decode(&state.salt).context("Failed to decode salt hex")?;

        // Derive master key directly — no KEK layer, no stored encrypted key.
        // Wrong password → decryption of ns_secret/author fails in load_unlocked_state.
        let mut master_key_raw = [0u8; 32];
        crypto::derive_key(master_password, &salt, &mut master_key_raw);

        let master_key = MasterKey::new(master_key_raw);
        master_key_raw.zeroize();

        let master_key_hex = zeroize::Zeroizing::new(hex::encode(master_key.as_bytes()));

        // A wrong password produces the correct-length key bytes but the
        // AES-GCM auth tag on the stored ns_secret/author will fail → map to
        // a user-friendly message here rather than leaking the internal error.
        self.load_unlocked_state(master_key).await.map_err(|e| {
            if e.to_string().contains("Failed to decrypt") {
                anyhow!("Incorrect master password")
            } else {
                e
            }
        })?;

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
        let mut ns_bytes_vec = crypto::decrypt_blob(&enc_ns, master_key.as_bytes())
            .context("Failed to decrypt namespace secret")?;
        let mut author_bytes_vec = crypto::decrypt_blob(&enc_author, master_key.as_bytes())
            .context("Failed to decrypt author")?;

        if ns_bytes_vec.len() != 32 {
            return Err(anyhow!(
                "Decrypted namespace secret has unexpected length (corrupted state?)"
            ));
        }
        if author_bytes_vec.len() != 32 {
            return Err(anyhow!(
                "Decrypted author bytes have unexpected length (corrupted state?)"
            ));
        }
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

        // 3. Two-pass scan: DEKs must be loaded before items because item
        //    decryption needs the DEK referenced in each envelope.
        let mut deks: HashMap<u32, [u8; 32]> = HashMap::new();
        let mut items = Vec::new();
        let entries = iroh::get_replica_entries(self.iroh.docs(), namespace_id).await?;

        // Pass 1: load all DEK versions.
        for signed_entry in &entries {
            let key_str = String::from_utf8_lossy(signed_entry.key());
            if !key_str.starts_with("_meta/dek/") || signed_entry.content_len() == 0 {
                continue;
            }
            let ver_str = &key_str["_meta/dek/".len()..];
            if let Ok(ver) = ver_str.parse::<u32>() {
                if let Ok(enc_dek) = self
                    .iroh
                    .blobs()
                    .get_bytes(signed_entry.content_hash())
                    .await
                {
                    if let Ok(dek_bytes) = crypto::decrypt_blob(&enc_dek, master_key.as_bytes()) {
                        if dek_bytes.len() == 32 {
                            let mut dek = [0u8; 32];
                            dek.copy_from_slice(&dek_bytes);
                            deks.insert(ver, dek);
                        }
                    }
                }
            }
        }

        // Pass 2: decrypt vault items using the loaded DEKs.
        for signed_entry in &entries {
            let key_str = String::from_utf8_lossy(signed_entry.key());
            if !key_str.starts_with("items/") {
                continue;
            }
            let id = &key_str["items/".len()..];
            if signed_entry.content_len() == 0 {
                items.retain(|item: &VaultItem| item.id != id);
                continue;
            }
            if let Ok(blob) = self
                .iroh
                .blobs()
                .get_bytes(signed_entry.content_hash())
                .await
            {
                if let Ok(envelope) = rmp_serde::from_slice::<ItemEnvelope>(&blob) {
                    if let Some(dek) = deks.get(&envelope.dek_v) {
                        if let Ok(nonce) = <[u8; 12]>::try_from(envelope.nonce.as_slice()) {
                            if let Ok(dec_bytes) = crypto::decrypt(&nonce, &envelope.cipher, dek) {
                                if let Ok(item) = serde_json::from_slice::<VaultItem>(&dec_bytes) {
                                    items.retain(|existing: &VaultItem| existing.id != item.id);
                                    items.push(item);
                                }
                            }
                        }
                    }
                }
            }
        }

        let current_dek_version = deks.keys().copied().max().unwrap_or(0);

        self.unlocked = Some(UnlockedState {
            master_key,
            ns_secret,
            author,
            namespace_id,
            author_id,
            items,
            deks,
            current_dek_version,
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

    /// Adds a new login item to the vault.
    pub async fn add_item(
        &mut self,
        name: String,
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        notes: Option<String>,
        uris: Vec<UriEntry>,
        favorite: bool,
        fields: Vec<CustomField>,
        folder_id: Option<String>,
    ) -> Result<VaultItem> {
        let (namespace_id, author, dek_v, dek) = {
            let state = self.get_unlocked()?;
            let v = state.current_dek_version;
            let dek = *state
                .deks
                .get(&v)
                .ok_or_else(|| anyhow!("No DEK found — was the vault properly initialized?"))?;
            (state.namespace_id, state.author.clone(), v, dek)
        };

        // 1. Construct VaultItem
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        let item = VaultItem {
            id: id.clone(),
            name,
            notes,
            favorite,
            reprompt: false,
            folder_id,
            fields,
            password_history: vec![],
            creation_date: now.clone(),
            revision_date: now,
            data: ItemData::Login {
                login: LoginDetails {
                    username,
                    password,
                    uris,
                    totp,
                },
            },
        };

        // 2. Serialize → encrypt with current DEK → wrap in msgpack envelope
        let item_bytes = serde_json::to_vec(&item)?;
        let (nonce, cipher) = crypto::encrypt(&item_bytes, &dek)?;
        let blob = rmp_serde::to_vec_named(&ItemEnvelope {
            dek_v,
            nonce: nonce.to_vec(),
            cipher,
        })?;

        // 3. Store entry in iroh-docs and blobs store
        let key = format!("items/{}", id);

        iroh::insert_doc_bytes(
            self.iroh.docs(),
            &namespace_id,
            &author,
            key.as_bytes(),
            blob.into(),
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

    /// Edits an existing login item in the vault.
    pub async fn edit_item(
        &mut self,
        id: String,
        name: String,
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        notes: Option<String>,
        uris: Vec<UriEntry>,
        favorite: bool,
        fields: Vec<CustomField>,
        folder_id: Option<String>,
    ) -> Result<VaultItem> {
        // Verify item exists and get keys; preserve creation_date and password_history.
        let (namespace_id, author, dek_v, dek, creation_date, password_history) = {
            let state = self.get_unlocked()?;
            let existing = state
                .items
                .iter()
                .find(|item| item.id == id)
                .ok_or_else(|| anyhow!("Item not found: {}", id))?;
            let v = state.current_dek_version;
            let dek = *state.deks.get(&v).ok_or_else(|| anyhow!("No DEK found"))?;
            (
                state.namespace_id,
                state.author.clone(),
                v,
                dek,
                existing.creation_date.clone(),
                existing.password_history.clone(),
            )
        };

        let item = VaultItem {
            id: id.clone(),
            name,
            notes,
            favorite,
            reprompt: false,
            folder_id,
            fields,
            password_history,
            creation_date,
            revision_date: Utc::now().to_rfc3339(),
            data: ItemData::Login {
                login: LoginDetails {
                    username,
                    password,
                    uris,
                    totp,
                },
            },
        };

        // Serialize → encrypt with current DEK → wrap in msgpack envelope
        let item_bytes = serde_json::to_vec(&item)?;
        let (nonce, cipher) = crypto::encrypt(&item_bytes, &dek)?;
        let blob = rmp_serde::to_vec_named(&ItemEnvelope {
            dek_v,
            nonce: nonce.to_vec(),
            cipher,
        })?;

        // Store entry in iroh-docs and blobs store
        let key = format!("items/{}", id);

        iroh::insert_doc_bytes(
            self.iroh.docs(),
            &namespace_id,
            &author,
            key.as_bytes(),
            blob.into(),
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
                    || item.login().map_or(false, |l| {
                        l.username
                            .as_ref()
                            .map_or(false, |u| u.to_lowercase().contains(&query_lower))
                            || l.uris
                                .iter()
                                .any(|u| u.uri.to_lowercase().contains(&query_lower))
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

    /// Exports a standard iroh sync ticket.
    ///
    /// The ticket is a plain iroh `DocTicket` string — P2P connectivity plus
    /// the document's write capability.  The Argon2id salt lives in the iroh
    /// document as `_meta/salt` (plaintext) and is fetched over P2P by the
    /// importing device, which then derives the master key locally from
    /// `Argon2id(password, salt)`.  No key material is transmitted.
    pub async fn export_sync_ticket(&self) -> Result<String> {
        if !self.is_initialized()? {
            return Err(anyhow!("Vault not initialized"));
        }
        let state = self.get_unlocked()?;
        let ticket = iroh::export_vault_ticket(self.iroh.docs(), state.namespace_id).await?;
        Ok(ticket)
    }

    /// Imports a standard iroh sync ticket and initializes the local vault.
    ///
    /// The salt is fetched in plaintext from `_meta/salt` in the iroh document.
    /// The master key is never transmitted — each device derives it locally via
    /// `Argon2id(password, salt)`.  The importing device must be online so that
    /// P2P sync can deliver the salt entry.
    pub async fn import_and_init(&mut self, master_password: &str, ticket_str: &str) -> Result<()> {
        if self.is_initialized()? {
            return Err(anyhow!("Vault already initialized"));
        }

        // 1. Parse the standard iroh DocTicket.
        let ticket = iroh_docs::DocTicket::from_str(ticket_str.trim())
            .context("Invalid iroh sync ticket")?;

        // 2. Connect to the P2P network and start replication.
        let (ns_secret, author) = iroh::import_vault_ticket(self.iroh.docs(), ticket).await?;
        let namespace_id = ns_secret.id();
        let author_id = author.id();

        // 3. Wait for the salt entry to arrive from the source device (up to 30 s).
        //    The salt is stored as raw bytes in `_meta/salt` and is not secret.
        let salt_blob = self
            .iroh
            .fetch_doc_entry_bytes(
                namespace_id,
                b"_meta/salt",
                std::time::Duration::from_secs(30),
            )
            .await?;

        if salt_blob.len() != 16 {
            return Err(anyhow!(
                "Salt entry has unexpected length ({} bytes, expected 16)",
                salt_blob.len()
            ));
        }

        // 4. Derive master key locally — nothing secret crossed the wire.
        let mut master_key = [0u8; 32];
        crypto::derive_key(master_password, &salt_blob, &mut master_key);

        // 4b. Verify the password before writing anything locally.
        //     The source device stored AES-GCM(salt_bytes, master_key) as
        //     `_meta/auth_tag`.  Decrypting it with the derived master key
        //     and comparing to the fetched salt proves the password is correct.
        //     Without this check a wrong password would silently corrupt state.json.
        let auth_blob = self
            .iroh
            .fetch_doc_entry_bytes(
                namespace_id,
                b"_meta/auth_tag",
                std::time::Duration::from_secs(10),
            )
            .await?;
        let decrypted_salt = crypto::decrypt_blob(&auth_blob, &master_key)
            .map_err(|_| anyhow!("Incorrect master password for the synced vault"))?;
        if decrypted_salt.as_slice() != salt_blob.as_ref() {
            master_key.zeroize();
            return Err(anyhow!("Incorrect master password for the synced vault"));
        }

        // 5. Encrypt the iroh replica keys with the derived master key.
        let mut ns_bytes = ns_secret.to_bytes();
        let mut author_bytes = author.to_bytes();

        let encrypted_ns = crypto::encrypt_blob(&ns_bytes, &master_key)?;
        let encrypted_author = crypto::encrypt_blob(&author_bytes, &master_key)?;

        ns_bytes.zeroize();
        author_bytes.zeroize();
        master_key.zeroize();

        // 6. Save state locally (same salt as source device).
        let state = LocalState {
            salt: hex::encode(&salt_blob[..]),
            encrypted_ns_secret: hex::encode(encrypted_ns),
            encrypted_author: hex::encode(encrypted_author),
            namespace_id: namespace_id.to_string(),
            author_id: author_id.to_string(),
        };
        let state_path = self.base_dir.join("state.json");
        let state_str = serde_json::to_string_pretty(&state)?;
        std::fs::write(&state_path, state_str)?;
        // Restrict state.json to owner-only read/write (0600).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&state_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&state_path, perms);
            }
        }

        Ok(())
    }

    /// Returns live P2P network and document sync status for display in the TUI.
    pub async fn get_sync_info(&self) -> SyncInfo {
        let endpoint = self.iroh.endpoint();

        // Node identity
        let node_id = endpoint.id().to_string();

        // Current endpoint address (relay + direct addrs)
        let addr = endpoint.addr();
        let relay_url = addr.relay_urls().next().map(|u| u.to_string());
        let bound_sockets: Vec<String> = endpoint
            .bound_sockets()
            .iter()
            .map(|a| a.to_string())
            .collect();

        // Vault / document state
        let (namespace_id, author_id, item_count, sync_peers) =
            if let Some(ref state) = self.unlocked {
                let ns_id = state.namespace_id.to_string();
                let auth_id = state.author_id.to_string();
                let count = state.items.len();

                // Query known sync peers from the iroh-docs replica
                let peers = match self.iroh.docs().open(state.namespace_id).await {
                    Ok(Some(doc)) => match doc.get_sync_peers().await {
                        Ok(Some(peers)) => peers.iter().map(|p| hex::encode(p)).collect::<Vec<_>>(),
                        _ => vec![],
                    },
                    _ => vec![],
                };

                (ns_id, auth_id, count, peers)
            } else if self.is_initialized().unwrap_or(false) {
                // Read namespace/author IDs from state.json even when locked
                let state_path = self.base_dir.join("state.json");
                if let Ok(s) = std::fs::read_to_string(&state_path) {
                    if let Ok(st) = serde_json::from_str::<LocalState>(&s) {
                        (st.namespace_id, st.author_id, 0, vec![])
                    } else {
                        ("N/A".into(), "N/A".into(), 0, vec![])
                    }
                } else {
                    ("N/A".into(), "N/A".into(), 0, vec![])
                }
            } else {
                ("N/A".into(), "N/A".into(), 0, vec![])
            };

        SyncInfo {
            node_id,
            relay_url,
            bound_sockets,
            namespace_id,
            author_id,
            item_count,
            sync_peers,
            is_initialized: self.is_initialized().unwrap_or(false),
            is_unlocked: self.unlocked.is_some(),
        }
    }

    /// Subscribe to live vault events from the iroh-docs sync layer.
    ///
    /// Returns a stream of [`LiveEvent`]s. Requires the vault to be unlocked.
    pub async fn subscribe_events(
        &self,
    ) -> Result<impl Stream<Item = Result<LiveEvent>> + Send + Unpin + 'static> {
        let namespace_id = self.get_unlocked()?.namespace_id;

        let doc = self
            .iroh
            .docs()
            .open(namespace_id)
            .await?
            .ok_or_else(|| anyhow!("Namespace not found for event subscription"))?;

        doc.subscribe().await
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
    /// Import vault items from a Bitwarden JSON export file.
    ///
    /// For encrypted exports, `password` (Bitwarden master password), `email`,
    /// and `iterations` (PBKDF2 count, default 600 000) are required.
    /// For unencrypted exports, `password` may be `None`.
    pub async fn import_bitwarden_json(
        &mut self,
        path: &str,
        password: Option<&str>,
        email: &str,
        iterations: u32,
    ) -> Result<usize> {
        let items = crate::bitwarden_import::import_from_file(path, password, email, iterations)?;
        let count = items.len();
        for item in items {
            // Serialize → encrypt → store in iroh (reuse add_item logic inline).
            let (namespace_id, author, dek_v, dek) = {
                let state = self.get_unlocked()?;
                let v = state.current_dek_version;
                let dek = *state
                    .deks
                    .get(&v)
                    .ok_or_else(|| anyhow!("No DEK — vault not properly initialized"))?;
                (state.namespace_id, state.author.clone(), v, dek)
            };

            let item_bytes = serde_json::to_vec(&item)?;
            let (nonce, cipher) = crate::crypto::encrypt(&item_bytes, &dek)?;
            let blob = rmp_serde::to_vec_named(&ItemEnvelope {
                dek_v,
                nonce: nonce.to_vec(),
                cipher,
            })?;

            let key = format!("items/{}", item.id);
            iroh::insert_doc_bytes(
                self.iroh.docs(),
                &namespace_id,
                &author,
                key.as_bytes(),
                blob.into(),
            )
            .await?;

            if let Some(ref mut state) = self.unlocked {
                state.items.retain(|e: &VaultItem| e.id != item.id);
                state.items.push(item);
            }
        }
        Ok(count)
    }

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

        // Export ticket — now a plain iroh DocTicket, no custom wrapper
        let ticket = dev1.export_sync_ticket().await.unwrap();
        assert!(!ticket.is_empty(), "ticket should be non-empty");
        // DocTicket strings are base32-encoded and typically start with "doc"
        assert!(
            !ticket.starts_with("keyroh:"),
            "ticket should no longer use the keyroh: prefix"
        );

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
