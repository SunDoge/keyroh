use serde::{Deserialize, Serialize};

// ── URI ──────────────────────────────────────────────────────────────────────

/// How a URI should be matched against the active browser tab.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UriMatch {
    Domain,
    Host,
    StartsWith,
    Exact,
    Regex,
    Never,
}

/// A URI entry, optionally carrying an explicit match strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UriEntry {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#match: Option<UriMatch>,
}

impl UriEntry {
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            r#match: None,
        }
    }
}

// ── Custom fields ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CustomField {
    Text { name: String, value: String },
    Hidden { name: String, value: String },
    Boolean { name: String, value: bool },
}

// ── Password history ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub last_used_date: String,
}

// ── Type-specific payloads ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uris: Vec<UriEntry>,
    /// Base32-encoded TOTP secret or an `otpauth://` URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
}

impl LoginDetails {
    pub fn get_totp_code(&self) -> Option<String> {
        let secret = self.totp.as_ref()?;
        use totp_rs::{Secret, TOTP};
        if secret.starts_with("otpauth://") {
            return TOTP::from_url(secret).ok()?.generate_current().ok();
        }
        let cleaned = secret.replace(' ', "");
        let bytes = Secret::Encoded(cleaned).to_bytes().ok()?;
        TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            bytes,
            None,
            "keyroh".into(),
        )
        .ok()?
        .generate_current()
        .ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardholder_name: Option<String>,
    /// Brand string, e.g. "Visa", "Mastercard".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_month: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_year: Option<String>,
    /// CVV / security code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_number: Option<String>,
}

// ── Tagged payload ────────────────────────────────────────────────────────────

/// The type-discriminated payload of a vault item.
///
/// Serialized as `{"type": "login", "login": {...}}` etc. so that unknown
/// future variants round-trip through serde without data loss.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemData {
    Login { login: LoginDetails },
    SecureNote,
    Card { card: CardDetails },
    Identity { identity: IdentityDetails },
}

// ── VaultItem ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,

    pub favorite: bool,

    /// Re-prompt for master password before revealing sensitive fields.
    #[serde(default)]
    pub reprompt: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<CustomField>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_history: Vec<PasswordHistoryEntry>,

    pub creation_date: String,
    pub revision_date: String,

    /// Type-specific payload.
    pub data: ItemData,
}

impl VaultItem {
    /// Convenience: return the TOTP code if this is a Login with a TOTP secret.
    pub fn get_totp_code(&self) -> Option<String> {
        match &self.data {
            ItemData::Login { login } => login.get_totp_code(),
            _ => None,
        }
    }

    /// Convenience: return a reference to `LoginDetails` if this is a login item.
    pub fn login(&self) -> Option<&LoginDetails> {
        match &self.data {
            ItemData::Login { login } => Some(login),
            _ => None,
        }
    }

    /// Convenience: return a reference to `CardDetails` if this is a card item.
    pub fn card(&self) -> Option<&CardDetails> {
        match &self.data {
            ItemData::Card { card } => Some(card),
            _ => None,
        }
    }

    /// Convenience: return a reference to `IdentityDetails` if this is an identity item.
    pub fn identity(&self) -> Option<&IdentityDetails> {
        match &self.data {
            ItemData::Identity { identity } => Some(identity),
            _ => None,
        }
    }
}

// ── Bitwarden import types ────────────────────────────────────────────────────
//
// The unencrypted Bitwarden JSON export uses integer discriminants (1–4) and
// camelCase field names.  These shadow types exist solely for deserialization;
// the `From` impls convert them into keyroh's canonical `VaultItem`.

pub mod bitwarden {
    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct BwUri {
        pub uri: String,
        pub r#match: Option<u8>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct BwLogin {
        pub username: Option<String>,
        pub password: Option<String>,
        #[serde(default)]
        pub uris: Vec<BwUri>,
        pub totp: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct BwCard {
        pub cardholder_name: Option<String>,
        pub brand: Option<String>,
        pub number: Option<String>,
        pub exp_month: Option<String>,
        pub exp_year: Option<String>,
        pub code: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct BwIdentity {
        pub title: Option<String>,
        pub first_name: Option<String>,
        pub middle_name: Option<String>,
        pub last_name: Option<String>,
        pub address1: Option<String>,
        pub address2: Option<String>,
        pub address3: Option<String>,
        pub city: Option<String>,
        pub state: Option<String>,
        pub postal_code: Option<String>,
        pub country: Option<String>,
        pub company: Option<String>,
        pub email: Option<String>,
        pub phone: Option<String>,
        pub ssn: Option<String>,
        pub username: Option<String>,
        pub passport_number: Option<String>,
        pub license_number: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct BwField {
        pub r#type: u8,
        pub name: Option<String>,
        pub value: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct BwPasswordHistory {
        pub password: String,
        pub last_used_date: String,
    }

    /// A single plaintext item from a Bitwarden unencrypted (or pre-decrypted) export.
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct BwItem {
        pub id: Option<String>,
        pub r#type: u8,
        pub name: String,
        pub notes: Option<String>,
        #[serde(default)]
        pub favorite: bool,
        #[serde(default)]
        pub reprompt: u8,
        pub folder_id: Option<String>,
        #[serde(default)]
        pub fields: Vec<BwField>,
        #[serde(default)]
        pub password_history: Vec<BwPasswordHistory>,
        pub creation_date: Option<String>,
        pub revision_date: Option<String>,
        pub login: Option<BwLogin>,
        pub card: Option<BwCard>,
        pub identity: Option<BwIdentity>,
    }

    impl BwUri {
        fn into_uri_entry(self) -> UriEntry {
            let r#match = self.r#match.and_then(|n| match n {
                0 => None, // Default → let keyroh decide
                1 => Some(UriMatch::Domain),
                2 => Some(UriMatch::Host),
                3 => Some(UriMatch::StartsWith),
                4 => Some(UriMatch::Exact),
                5 => Some(UriMatch::Regex),
                6 => Some(UriMatch::Never),
                _ => None,
            });
            UriEntry {
                uri: self.uri,
                r#match,
            }
        }
    }

    impl BwField {
        fn into_custom_field(self) -> Option<CustomField> {
            let name = self.name.unwrap_or_default();
            match self.r#type {
                0 => Some(CustomField::Text {
                    name,
                    value: self.value.unwrap_or_default(),
                }),
                1 => Some(CustomField::Hidden {
                    name,
                    value: self.value.unwrap_or_default(),
                }),
                2 => Some(CustomField::Boolean {
                    name,
                    value: self.value.as_deref() == Some("true"),
                }),
                _ => None,
            }
        }
    }

    impl From<BwItem> for VaultItem {
        fn from(bw: BwItem) -> Self {
            use chrono::Utc;
            let now = Utc::now().to_rfc3339();

            let data = match bw.r#type {
                1 => {
                    let l = bw.login.unwrap_or_else(|| BwLogin {
                        username: None,
                        password: None,
                        uris: vec![],
                        totp: None,
                    });
                    ItemData::Login {
                        login: LoginDetails {
                            username: l.username,
                            password: l.password,
                            uris: l.uris.into_iter().map(BwUri::into_uri_entry).collect(),
                            totp: l.totp,
                        },
                    }
                }
                2 => ItemData::SecureNote,
                3 => {
                    let c = bw.card.unwrap_or_else(|| BwCard {
                        cardholder_name: None,
                        brand: None,
                        number: None,
                        exp_month: None,
                        exp_year: None,
                        code: None,
                    });
                    ItemData::Card {
                        card: CardDetails {
                            cardholder_name: c.cardholder_name,
                            brand: c.brand,
                            number: c.number,
                            exp_month: c.exp_month,
                            exp_year: c.exp_year,
                            code: c.code,
                        },
                    }
                }
                4 => {
                    let i = bw.identity.unwrap_or_else(|| BwIdentity {
                        title: None,
                        first_name: None,
                        middle_name: None,
                        last_name: None,
                        address1: None,
                        address2: None,
                        address3: None,
                        city: None,
                        state: None,
                        postal_code: None,
                        country: None,
                        company: None,
                        email: None,
                        phone: None,
                        ssn: None,
                        username: None,
                        passport_number: None,
                        license_number: None,
                    });
                    ItemData::Identity {
                        identity: IdentityDetails {
                            title: i.title,
                            first_name: i.first_name,
                            middle_name: i.middle_name,
                            last_name: i.last_name,
                            address1: i.address1,
                            address2: i.address2,
                            address3: i.address3,
                            city: i.city,
                            state: i.state,
                            postal_code: i.postal_code,
                            country: i.country,
                            company: i.company,
                            email: i.email,
                            phone: i.phone,
                            ssn: i.ssn,
                            username: i.username,
                            passport_number: i.passport_number,
                            license_number: i.license_number,
                        },
                    }
                }
                _ => ItemData::SecureNote, // unknown type → treat as note
            };

            VaultItem {
                id: bw.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                name: bw.name,
                notes: bw.notes,
                favorite: bw.favorite,
                reprompt: bw.reprompt != 0,
                folder_id: bw.folder_id,
                fields: bw
                    .fields
                    .into_iter()
                    .filter_map(BwField::into_custom_field)
                    .collect(),
                password_history: bw
                    .password_history
                    .into_iter()
                    .map(|h| PasswordHistoryEntry {
                        password: h.password,
                        last_used_date: h.last_used_date,
                    })
                    .collect(),
                creation_date: bw.creation_date.unwrap_or_else(|| now.clone()),
                revision_date: bw.revision_date.unwrap_or(now),
                data,
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_roundtrip() {
        let item = VaultItem {
            id: "abc".into(),
            name: "GitHub".into(),
            notes: None,
            favorite: true,
            reprompt: false,
            folder_id: None,
            fields: vec![],
            password_history: vec![],
            creation_date: "2026-01-01T00:00:00Z".into(),
            revision_date: "2026-01-01T00:00:00Z".into(),
            data: ItemData::Login {
                login: LoginDetails {
                    username: Some("alice".into()),
                    password: Some("s3cr3t".into()),
                    uris: vec![UriEntry::new("https://github.com")],
                    totp: None,
                },
            },
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains(r#""type":"login""#));
        let back: VaultItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "GitHub");
        assert!(back.login().is_some());
    }

    #[test]
    fn test_card_roundtrip() {
        let item = VaultItem {
            id: "xyz".into(),
            name: "Visa".into(),
            notes: None,
            favorite: false,
            reprompt: true,
            folder_id: None,
            fields: vec![],
            password_history: vec![],
            creation_date: "2026-01-01T00:00:00Z".into(),
            revision_date: "2026-01-01T00:00:00Z".into(),
            data: ItemData::Card {
                card: CardDetails {
                    cardholder_name: Some("Alice".into()),
                    brand: Some("Visa".into()),
                    number: Some("4111111111111111".into()),
                    exp_month: Some("12".into()),
                    exp_year: Some("2028".into()),
                    code: Some("123".into()),
                },
            },
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains(r#""type":"card""#));
        let back: VaultItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.card().unwrap().brand, Some("Visa".into()));
    }

    #[test]
    fn test_totp_generation() {
        let item = VaultItem {
            id: "t".into(),
            name: "TOTP Test".into(),
            notes: None,
            favorite: false,
            reprompt: false,
            folder_id: None,
            fields: vec![],
            password_history: vec![],
            creation_date: "2026-01-01T00:00:00Z".into(),
            revision_date: "2026-01-01T00:00:00Z".into(),
            data: ItemData::Login {
                login: LoginDetails {
                    username: None,
                    password: None,
                    uris: vec![],
                    totp: Some("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".into()),
                },
            },
        };
        let code = item.get_totp_code().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_bitwarden_import_login() {
        use super::bitwarden::BwItem;
        let json = r#"{
            "type": 1,
            "name": "Test",
            "favorite": false,
            "reprompt": 0,
            "fields": [],
            "passwordHistory": [],
            "login": {
                "username": "alice",
                "password": "secret",
                "uris": [{"uri": "https://example.com", "match": null}],
                "totp": null
            }
        }"#;
        let bw: BwItem = serde_json::from_str(json).unwrap();
        let item = VaultItem::from(bw);
        let login = item.login().unwrap();
        assert_eq!(login.username.as_deref(), Some("alice"));
        assert_eq!(login.uris[0].uri, "https://example.com");
    }
}
