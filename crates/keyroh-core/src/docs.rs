use anyhow::{Context, Result, anyhow};
use iroh_blobs::Hash;
use iroh_docs::store::Query;
use iroh_docs::store::fs::Store as DocStore;
use iroh_docs::{Author, NamespaceId, NamespaceSecret, SignedEntry};
use std::path::Path;

/// Opens the persistent iroh-docs store.
pub fn open_doc_store(docs_db_path: &Path) -> Result<DocStore> {
    DocStore::persistent(docs_db_path).context("Failed to open persistent iroh-docs store")
}

/// Creates a new document replica and author in the store.
/// Returns the NamespaceSecret and the Author.
pub fn create_vault_replica(doc_store: &mut DocStore) -> Result<(NamespaceSecret, Author)> {
    let mut rng = rand::rng();

    // Generate NamespaceSecret and Author
    let ns_secret = NamespaceSecret::new(&mut rng);
    let author = Author::new(&mut rng);

    // Create new replica in the store
    let _replica = doc_store
        .new_replica(ns_secret.clone())
        .context("Failed to create new document replica in store")?;

    // Import author into the store
    doc_store
        .import_author(author.clone())
        .context("Failed to import author into store")?;

    Ok((ns_secret, author))
}

/// Imports an existing replica namespace secret and author into the store.
pub fn import_vault_replica(
    doc_store: &mut DocStore,
    ns_secret: NamespaceSecret,
    author: Author,
) -> Result<()> {
    // Import namespace
    doc_store
        .import_namespace(ns_secret.clone().into())
        .context("Failed to import namespace capability")?;

    // Import author
    doc_store
        .import_author(author)
        .context("Failed to import author")?;

    Ok(())
}

/// Inserts an entry into the document replica.
pub async fn insert_doc_entry(
    doc_store: &mut DocStore,
    namespace_id: &NamespaceId,
    _ns_secret: &NamespaceSecret,
    author: &Author,
    key: &[u8],
    hash: Hash,
    len: u64,
) -> Result<()> {
    let mut replica = doc_store
        .open_replica(namespace_id)
        .map_err(|e| anyhow!("Failed to open replica: {:?}", e))?;

    replica
        .insert(key, author, hash, len)
        .await
        .context("Failed to insert entry into replica")?;

    // Flush to disk
    doc_store.flush().context("Failed to flush docs store")?;

    Ok(())
}

/// Marks an entry as deleted by inserting an empty/tombstone entry under the prefix.
pub async fn delete_doc_entry(
    doc_store: &mut DocStore,
    namespace_id: &NamespaceId,
    author: &Author,
    key: &[u8],
) -> Result<()> {
    let mut replica = doc_store
        .open_replica(namespace_id)
        .map_err(|e| anyhow!("Failed to open replica: {:?}", e))?;

    replica
        .delete_prefix(key, author)
        .await
        .context("Failed to delete entry from replica")?;

    // Flush to disk
    doc_store.flush().context("Failed to flush docs store")?;

    Ok(())
}

/// Reads all entries from a document replica.
pub fn get_replica_entries(
    doc_store: &mut DocStore,
    namespace_id: NamespaceId,
) -> Result<Vec<SignedEntry>> {
    let query_iter = doc_store
        .get_many(namespace_id, Query::all())
        .context("Failed to query entries from docs store")?;

    let mut entries = Vec::new();
    for entry_res in query_iter {
        let entry = entry_res.context("Failed to read replica entry")?;
        entries.push(entry);
    }

    Ok(entries)
}
