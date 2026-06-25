use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use futures::StreamExt;
use iroh::SecretKey;
use iroh::protocol::Router;
use iroh_blobs::{ALPN as BLOBS_ALPN, BlobsProtocol, Hash, api::blobs::Blobs, store::fs::FsStore};
use iroh_docs::{
    ALPN as DOCS_ALPN, Author, Capability, DocTicket, Entry, NamespaceId, NamespaceSecret,
    api::protocol::{AddrInfoOptions, ShareMode},
    protocol::Docs,
    store::Query,
};
use iroh_gossip::{ALPN as GOSSIP_ALPN, net::Gossip};
use keyring::Entry as KeyringEntry;
use tokio::io::AsyncWriteExt;

#[derive(Clone, Debug)]
pub struct Iroh {
    #[allow(dead_code)]
    router: Router,
    store: FsStore,
    docs: Docs,
}

impl Iroh {
    pub async fn new(path: PathBuf) -> Result<Self> {
        // create dir if it doesn't already exist
        tokio::fs::create_dir_all(&path).await?;

        let key = load_secret_key(path.clone().join("keypair")).await?;

        // create endpoint using the loaded secret key
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(key)
            .bind()
            .await?;

        // add iroh gossip
        let gossip = Gossip::builder().spawn(endpoint.clone());

        let blobs = FsStore::load(&path).await?;

        // add docs
        let docs = Docs::persistent(path)
            .spawn(endpoint.clone(), (*blobs).clone(), gossip.clone())
            .await?;

        // build the protocol router
        let builder = iroh::protocol::Router::builder(endpoint.clone());

        let router = builder
            .accept(BLOBS_ALPN, BlobsProtocol::new(&blobs, None))
            .accept(GOSSIP_ALPN, gossip)
            .accept(DOCS_ALPN, docs.clone())
            .spawn();

        Ok(Self {
            router,
            docs,
            store: blobs,
        })
    }

    pub fn blobs(&self) -> &Blobs {
        self.store.blobs()
    }

    pub fn docs(&self) -> &Docs {
        &self.docs
    }

    pub async fn shutdown(self) -> Result<()> {
        self.router.shutdown().await?;
        Ok(())
    }
}

#[cfg(not(test))]
const KEYRING_SERVICE: &str = "keyroh-p2p";
#[cfg(test)]
const KEYRING_SERVICE: &str = "keyroh-p2p-test";

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    pub static TEST_KEYRING_USER: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn get_keyring_user() -> String {
    #[cfg(test)]
    {
        let overridden = TEST_KEYRING_USER.with(|override_user| override_user.borrow().clone());
        if let Some(u) = overridden {
            return u;
        }
        "endpoint-keypair-test".to_string()
    }
    #[cfg(not(test))]
    "endpoint-keypair".to_string()
}

fn load_from_keyring() -> Result<SecretKey> {
    let entry = KeyringEntry::new(KEYRING_SERVICE, &get_keyring_user())?;
    let hex_pass = entry.get_password()?;
    let bytes = hex::decode(&hex_pass)?;
    if bytes.len() != 32 {
        return Err(anyhow!("keyring secret key length is not 32 bytes"));
    }
    let secret_key = SecretKey::try_from(&bytes[0..32])?;
    Ok(secret_key)
}

fn save_to_keyring(secret_key: &SecretKey) -> Result<()> {
    let entry = KeyringEntry::new(KEYRING_SERVICE, &get_keyring_user())?;
    let hex_pass = hex::encode(secret_key.to_bytes());
    entry.set_password(&hex_pass)?;
    Ok(())
}

pub async fn load_secret_key(key_path: PathBuf) -> Result<SecretKey> {
    let keyring_disabled = std::env::var("KEYROH_NO_KEYRING").is_ok();

    if !keyring_disabled {
        // 1. Try loading from keyring first
        match load_from_keyring() {
            Ok(secret_key) => {
                println!("Successfully loaded iroh secret key from keyring.");
                return Ok(secret_key);
            }
            Err(e) => {
                eprintln!("Keyring load failed (will fall back to file): {e:?}");
            }
        }
    } else {
        println!("Keyring storage disabled via KEYROH_NO_KEYRING.");
    }

    // 2. Try loading from fallback file
    if key_path.exists() {
        let key_bytes = tokio::fs::read(&key_path).await?;
        let secret_key = SecretKey::try_from(&key_bytes[0..32])?;

        if !keyring_disabled {
            // Try saving it to keyring for future runs
            if let Err(e) = save_to_keyring(&secret_key) {
                eprintln!("Failed to save loaded key to keyring: {e:?}");
            }
        }

        Ok(secret_key)
    } else {
        // 3. Generate new key
        let secret_key = SecretKey::generate();

        let mut saved_to_keyring = false;
        if !keyring_disabled {
            // 4. Try saving to keyring first
            match save_to_keyring(&secret_key) {
                Ok(()) => {
                    println!("Successfully saved new iroh secret key to keyring.");
                    saved_to_keyring = true;
                }
                Err(e) => {
                    eprintln!(
                        "Failed to save new key to keyring: {e:?}. Falling back to file storage."
                    );
                }
            }
        }

        if !saved_to_keyring {
            // Fallback to writing file
            // Try to canonicalize if possible
            let key_path = key_path.canonicalize().unwrap_or(key_path);
            let key_path_parent = key_path
                .parent()
                .ok_or_else(|| anyhow!("no parent directory found for '{}'", key_path.display()))?;
            tokio::fs::create_dir_all(&key_path_parent).await?;

            // write to tempfile
            let (file, temp_file_path) = tempfile::NamedTempFile::new_in(key_path_parent)
                .context("unable to create tempfile")?
                .into_parts();
            let mut file = tokio::fs::File::from_std(file);
            file.write_all(&secret_key.to_bytes())
                .await
                .context("unable to write keyfile")?;
            file.flush().await?;
            drop(file);

            // move file
            tokio::fs::rename(&temp_file_path, &key_path)
                .await
                .context("failed to rename keyfile")?;

            // Set strict file permissions (0600) on Unix systems
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(&key_path) {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(&key_path, perms);
                }
            }
        }

        Ok(secret_key)
    }
}

// --- Document Replica Operations (formerly docs.rs) ---

/// Creates a new document replica and author in the store.
/// Returns the NamespaceSecret and the Author.
pub async fn create_vault_replica(docs: &Docs) -> Result<(NamespaceSecret, Author)> {
    let mut rng = rand::rng();

    // Generate NamespaceSecret and Author
    let ns_secret = NamespaceSecret::new(&mut rng);
    let author = Author::new(&mut rng);

    // Import author
    docs.author_import(author.clone())
        .await
        .context("Failed to import author")?;

    // Create new replica in the store
    docs.import_namespace(ns_secret.clone().into())
        .await
        .context("Failed to create replica namespace")?;

    Ok((ns_secret, author))
}

/// Exports a sync ticket for the vault database replica.
pub async fn export_vault_ticket(docs: &Docs, namespace_id: NamespaceId) -> Result<String> {
    let doc = docs
        .open(namespace_id)
        .await?
        .ok_or_else(|| anyhow!("Namespace not found"))?;

    let ticket = doc
        .share(ShareMode::Write, AddrInfoOptions::RelayAndAddresses)
        .await
        .context("Failed to share document to generate ticket")?;

    Ok(ticket.to_string())
}

/// Imports a sync ticket and generates a new local Author for this device.
pub async fn import_vault_ticket(
    docs: &Docs,
    ticket: DocTicket,
) -> Result<(NamespaceSecret, Author)> {
    let ns_secret = match &ticket.capability {
        Capability::Write(secret) => secret.clone(),
        Capability::Read(_) => {
            return Err(anyhow!(
                "Ticket must grant Write capability for a collaborative vault"
            ));
        }
    };

    // Import namespace capability
    docs.import_namespace(ticket.capability.clone())
        .await
        .context("Failed to import namespace capability")?;

    // Start synchronization with the peers listed in the ticket
    let doc = docs
        .open(ns_secret.id())
        .await?
        .ok_or_else(|| anyhow!("Namespace not found after import"))?;
    doc.start_sync(ticket.nodes).await?;

    // Generate a new local Author for this device
    let mut rng = rand::rng();
    let author = Author::new(&mut rng);

    // Import the new author
    docs.author_import(author.clone())
        .await
        .context("Failed to import new author")?;

    Ok((ns_secret, author))
}

/// Inserts an entry into the document replica.
pub async fn insert_doc_bytes(
    docs: &Docs,
    namespace_id: &NamespaceId,
    author: &Author,
    key: &[u8],
    content: bytes::Bytes,
) -> Result<Hash> {
    let doc = docs
        .open(*namespace_id)
        .await?
        .ok_or_else(|| anyhow!("Namespace not found"))?;

    let hash = doc
        .set_bytes(author.id(), key.to_vec(), content)
        .await
        .context("Failed to set bytes on document")?;

    Ok(hash)
}

/// Marks an entry as deleted by inserting an empty/tombstone entry under the prefix.
pub async fn delete_doc_entry(
    docs: &Docs,
    namespace_id: &NamespaceId,
    author: &Author,
    key: &[u8],
) -> Result<()> {
    let doc = docs
        .open(*namespace_id)
        .await?
        .ok_or_else(|| anyhow!("Namespace not found"))?;

    doc.del(author.id(), key.to_vec())
        .await
        .context("Failed to delete entry from document")?;

    Ok(())
}

/// Reads all entries from a document replica.
pub async fn get_replica_entries(docs: &Docs, namespace_id: NamespaceId) -> Result<Vec<Entry>> {
    let doc = docs
        .open(namespace_id)
        .await?
        .ok_or_else(|| anyhow!("Namespace not found"))?;

    let stream = doc.get_many(Query::all()).await?;
    tokio::pin!(stream);
    let mut entries = Vec::new();
    while let Some(entry_res) = stream.next().await {
        let entry = entry_res.context("Failed to read replica entry")?;
        entries.push(entry);
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_load_secret_key_fallback() {
        // Set unique keyring user for this thread to avoid parallel test races
        TEST_KEYRING_USER.with(|u| {
            *u.borrow_mut() = Some("endpoint-keypair-fallback-test".to_string());
        });

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("keypair");
        let keyring_user = get_keyring_user();

        // 1. Clear keyring first to ensure we test generation and fallback
        if let Ok(entry) = KeyringEntry::new(KEYRING_SERVICE, &keyring_user) {
            let _ = entry.delete_credential();
        }

        // 2. Generate/Load key for the first time
        let key1 = load_secret_key(key_path.clone()).await.unwrap();

        // 3. Load it again (it should match because it is either cached in keyring or file)
        let key2 = load_secret_key(key_path.clone()).await.unwrap();

        assert_eq!(key1.to_bytes(), key2.to_bytes());

        // 4. If we delete the fallback file, we should still be able to load the same key from keyring (if keyring is available)
        if key_path.exists() {
            tokio::fs::remove_file(&key_path).await.unwrap();
        }

        let keyring_working = KeyringEntry::new(KEYRING_SERVICE, &keyring_user)
            .and_then(|entry| entry.get_password())
            .is_ok();

        if keyring_working {
            let key3 = load_secret_key(key_path.clone()).await.unwrap();
            assert_eq!(key1.to_bytes(), key3.to_bytes());
            assert!(!key_path.exists());
        }
    }

    #[tokio::test]
    async fn test_keyring_disabled_env_var() {
        unsafe {
            std::env::set_var("KEYROH_NO_KEYRING", "1");
        }

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("keypair");

        // 1. Generate/Load key when keyring is disabled
        let key1 = load_secret_key(key_path.clone()).await.unwrap();

        // 2. The file MUST exist because it could not have been saved in keyring!
        assert!(key_path.exists());

        // 3. Load it again (should read from file)
        let key2 = load_secret_key(key_path.clone()).await.unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());

        // Clean up env var
        unsafe {
            std::env::remove_var("KEYROH_NO_KEYRING");
        }
    }
}
