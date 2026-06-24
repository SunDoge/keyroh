use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    pub notes: Option<String>,
    pub login: Option<LoginDetails>,
    pub favorite: bool,
    pub revision_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginDetails {
    pub username: Option<String>,
    pub password: Option<String>,
    pub uris: Vec<String>,
}
