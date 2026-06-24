use rusqlite::{params, Connection, Result};
use std::path::Path;
use anyhow::{anyhow, Context};
use crate::vault::VaultItem;

/// Initializes the persistent local SQLite database if not already initialized.
pub fn init_persistent_db(db_path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(db_path)
        .context("Failed to open persistent SQLite database")?;
    
    // Create state table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS local_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    ).context("Failed to create local_state table")?;

    // Create blobs table to store encrypted vault item values
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blobs (
            hash TEXT PRIMARY KEY,
            content BLOB NOT NULL
        )",
        [],
    ).context("Failed to create blobs table")?;

    Ok(conn)
}

/// Sets a state key/value pair in local_state.
pub fn set_state_value(conn: &Connection, key: &str, value: &str) -> anyhow::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO local_state (key, value) VALUES (?1, ?2)",
        params![key, value],
    ).context("Failed to set state value")?;
    Ok(())
}

/// Gets a state value from local_state.
pub fn get_state_value(conn: &Connection, key: &str) -> anyhow::Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM local_state WHERE key = ?1")?;
    let mut rows = stmt.query(params![key])?;
    if let Some(row) = rows.next()? {
        let val: String = row.get(0)?;
        Ok(Some(val))
    } else {
        Ok(None)
    }
}

/// Saves an encrypted blob to the blobs table.
pub fn save_blob(conn: &Connection, hash: &str, content: &[u8]) -> anyhow::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO blobs (hash, content) VALUES (?1, ?2)",
        params![hash, content],
    ).context("Failed to save blob")?;
    Ok(())
}

/// Retrieves an encrypted blob from the blobs table.
pub fn get_blob(conn: &Connection, hash: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let mut stmt = conn.prepare("SELECT content FROM blobs WHERE hash = ?1")?;
    let mut rows = stmt.query(params![hash])?;
    if let Some(row) = rows.next()? {
        let content: Vec<u8> = row.get(0)?;
        Ok(Some(content))
    } else {
        Ok(None)
    }
}

/// Deletes an encrypted blob from the blobs table if no longer referenced.
pub fn delete_blob(conn: &Connection, hash: &str) -> anyhow::Result<()> {
    conn.execute(
        "DELETE FROM blobs WHERE hash = ?1",
        params![hash],
    ).context("Failed to delete blob")?;
    Ok(())
}

/// Creates an in-memory SQLite database connection with a decrypted search index table.
pub fn create_in_memory_index_db() -> anyhow::Result<Connection> {
    let conn = Connection::open_in_memory()
        .context("Failed to open in-memory SQLite database")?;
        
    conn.execute(
        "CREATE TABLE vault_items (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            username TEXT,
            password TEXT,
            notes TEXT,
            uris TEXT,
            favorite INTEGER NOT NULL,
            revision_date TEXT NOT NULL
        )",
        [],
    ).context("Failed to create in-memory vault_items table")?;
    
    Ok(conn)
}

/// Upserts a decrypted vault item into the in-memory search index.
pub fn upsert_index_item(conn: &Connection, item: &VaultItem) -> anyhow::Result<()> {
    let login = item.login.as_ref();
    let username = login.and_then(|l| l.username.clone());
    let password = login.and_then(|l| l.password.clone());
    
    let uris_str = if let Some(l) = login {
        serde_json::to_string(&l.uris).unwrap_or_else(|_| "[]".to_string())
    } else {
        "[]".to_string()
    };
    
    conn.execute(
        "INSERT OR REPLACE INTO vault_items (id, name, username, password, notes, uris, favorite, revision_date)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            item.id,
            item.name,
            username,
            password,
            item.notes,
            uris_str,
            if item.favorite { 1 } else { 0 },
            item.revision_date
        ],
    ).context("Failed to upsert item to search index")?;
    
    Ok(())
}

/// Deletes an item from the in-memory search index.
pub fn delete_index_item(conn: &Connection, id: &str) -> anyhow::Result<()> {
    conn.execute(
        "DELETE FROM vault_items WHERE id = ?1",
        params![id],
    ).context("Failed to delete item from search index")?;
    Ok(())
}

/// Searches decrypted items in the in-memory SQLite database.
pub fn search_index_items(conn: &Connection, query_str: &str) -> anyhow::Result<Vec<VaultItem>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, username, password, notes, uris, favorite, revision_date
         FROM vault_items
         WHERE name LIKE ?1 OR username LIKE ?1 OR notes LIKE ?1 OR uris LIKE ?1
         ORDER BY favorite DESC, name ASC"
    )?;
    
    let sql_query = format!("%{}%", query_str);
    let rows = stmt.query_map(params![sql_query], |row| {
        let id: String = row.get(0)?;
        let name: String = row.get(1)?;
        let username: Option<String> = row.get(2)?;
        let password: Option<String> = row.get(3)?;
        let notes: Option<String> = row.get(4)?;
        let uris_str: String = row.get(5)?;
        let favorite_val: i32 = row.get(6)?;
        let revision_date: String = row.get(7)?;
        
        let uris: Vec<String> = serde_json::from_str(&uris_str).unwrap_or_default();
        
        let login = if username.is_some() || password.is_some() || !uris.is_empty() {
            Some(LoginDetails {
                username,
                password,
                uris,
            })
        } else {
            None
        };
        
        Ok(VaultItem {
            id,
            name,
            notes,
            login,
            favorite: favorite_val != 0,
            revision_date,
        })
    })?;
    
    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }
    
    Ok(items)
}

/// Lists all items in the search index.
pub fn list_index_items(conn: &Connection) -> anyhow::Result<Vec<VaultItem>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, username, password, notes, uris, favorite, revision_date
         FROM vault_items
         ORDER BY favorite DESC, name ASC"
    )?;
    
    let rows = stmt.query_map([], |row| {
        let id: String = row.get(0)?;
        let name: String = row.get(1)?;
        let username: Option<String> = row.get(2)?;
        let password: Option<String> = row.get(3)?;
        let notes: Option<String> = row.get(4)?;
        let uris_str: String = row.get(5)?;
        let favorite_val: i32 = row.get(6)?;
        let revision_date: String = row.get(7)?;
        
        let uris: Vec<String> = serde_json::from_str(&uris_str).unwrap_or_default();
        
        let login = if username.is_some() || password.is_some() || !uris.is_empty() {
            Some(LoginDetails {
                username,
                password,
                uris,
            })
        } else {
            None
        };
        
        Ok(VaultItem {
            id,
            name,
            notes,
            login,
            favorite: favorite_val != 0,
            revision_date,
        })
    })?;
    
    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }
    
    Ok(items)
}

// Temporary structs used by rusqlite mapping
use crate::vault::LoginDetails;
