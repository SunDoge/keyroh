use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CustomField {
    Text { name: String, value: String },
    Hidden { name: String, value: String },
    Boolean { name: String, value: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    pub notes: Option<String>,
    pub login: Option<LoginDetails>,
    pub favorite: bool,
    pub revision_date: String,
    pub folder_id: Option<String>,
    #[serde(default)]
    pub fields: Vec<CustomField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginDetails {
    pub username: Option<String>,
    pub password: Option<String>,
    pub uris: Vec<String>,
    #[serde(default)]
    pub totp: Option<String>,
}

impl LoginDetails {
    pub fn get_totp_code(&self) -> Option<String> {
        let totp_secret = self.totp.as_ref()?;
        
        use totp_rs::{TOTP, Secret};
        
        if totp_secret.starts_with("otpauth://") {
            if let Ok(totp) = TOTP::from_url(totp_secret) {
                return totp.generate_current().ok();
            }
        }
        
        let cleaned = totp_secret.replace(' ', "");
        let secret = Secret::Encoded(cleaned);
        if let Ok(bytes) = secret.to_bytes() {
            if let Ok(totp) = TOTP::new(
                totp_rs::Algorithm::SHA1,
                6,
                1,
                30,
                bytes,
                None,
                "keyroh".to_string(),
            ) {
                return totp.generate_current().ok();
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_field_serde() {
        let field = CustomField::Text {
            name: "api_key".to_string(),
            value: "secret_value".to_string(),
        };
        let serialized = serde_json::to_string(&field).unwrap();
        assert!(serialized.contains(r#""type":"text""#));
        assert!(serialized.contains(r#""name":"api_key""#));
        assert!(serialized.contains(r#""value":"secret_value""#));

        let deserialized: CustomField = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            CustomField::Text { name, value } => {
                assert_eq!(name, "api_key");
                assert_eq!(value, "secret_value");
            }
            _ => panic!("Expected CustomField::Text"),
        }
    }

    #[test]
    fn test_totp_generation_base32() {
        let login = LoginDetails {
            username: None,
            password: None,
            uris: vec![],
            totp: Some("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_string()),
        };
        let code = login.get_totp_code();
        assert!(code.is_some());
        let code_str = code.unwrap();
        assert_eq!(code_str.len(), 6);
        assert!(code_str.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_generation_otpauth_url() {
        let login = LoginDetails {
            username: None,
            password: None,
            uris: vec![],
            totp: Some("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example".to_string()),
        };
        let code = login.get_totp_code();
        assert!(code.is_some());
        let code_str = code.unwrap();
        assert_eq!(code_str.len(), 6);
        assert!(code_str.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_vault_item_folder_id_serde() {
        let item = VaultItem {
            id: "123".to_string(),
            name: "test_item".to_string(),
            notes: None,
            login: None,
            favorite: false,
            revision_date: "2026-06-25T01:00:00Z".to_string(),
            folder_id: Some("folder-uuid-abc".to_string()),
            fields: vec![],
        };
        let serialized = serde_json::to_string(&item).unwrap();
        assert!(serialized.contains(r#""folder_id":"folder-uuid-abc""#));
        assert!(!serialized.contains(r#""folderId""#));

        let deserialized: VaultItem = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.folder_id, Some("folder-uuid-abc".to_string()));
    }
}
