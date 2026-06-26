/// Bitwarden encrypted JSON export importer.
///
/// Supports the "Account Backup" encrypted export format where every field
/// is an AES-256-CBC + HMAC-SHA256 CipherString (type prefix `2.`).
///
/// Key derivation:
///   master_key = PBKDF2-SHA256(password, email.to_lowercase(), iterations)
///   enc_key    = HKDF-expand(master_key, "enc", 32)
///   mac_key    = HKDF-expand(master_key, "mac", 32)
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;
use zeroize::Zeroize;

use crate::vault::{VaultItem, bitwarden::BwItem};

// ── Derived keys (zeroized on drop) ─────────────────────────────────────────

pub struct BwKeys {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl Drop for BwKeys {
    fn drop(&mut self) {
        self.enc.zeroize();
        self.mac.zeroize();
    }
}

/// Derive Bitwarden vault keys from master password + email + PBKDF2 iterations.
pub fn derive_keys(password: &str, email: &str, iterations: u32) -> Result<BwKeys> {
    use hkdf::Hkdf;
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    // Step 1: PBKDF2-SHA256(password, email_lower, iterations) → 32-byte master key
    let mut master_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        email.to_lowercase().as_bytes(),
        iterations,
        &mut master_key,
    );

    // Step 2: HKDF expand (no extract — master_key is used directly as PRK)
    let hk =
        Hkdf::<Sha256>::from_prk(&master_key).map_err(|_| anyhow!("HKDF: invalid PRK length"))?;
    master_key.zeroize();

    let mut keys = BwKeys {
        enc: [0u8; 32],
        mac: [0u8; 32],
    };
    hk.expand(b"enc", &mut keys.enc)
        .map_err(|_| anyhow!("HKDF expand 'enc' failed"))?;
    hk.expand(b"mac", &mut keys.mac)
        .map_err(|_| anyhow!("HKDF expand 'mac' failed"))?;

    Ok(keys)
}

// ── CipherString parser ───────────────────────────────────────────────────────

struct CipherString {
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    mac: Vec<u8>,
}

impl CipherString {
    fn parse(s: &str) -> Result<Self> {
        let body = s
            .strip_prefix("2.")
            .ok_or_else(|| anyhow!("unsupported CipherString type (expected '2.' prefix)"))?;
        let parts: Vec<&str> = body.splitn(3, '|').collect();
        if parts.len() != 3 {
            return Err(anyhow!(
                "malformed CipherString: expected 3 pipe-separated segments"
            ));
        }
        Ok(Self {
            iv: B64
                .decode(parts[0])
                .context("CipherString: invalid base64 IV")?,
            ciphertext: B64
                .decode(parts[1])
                .context("CipherString: invalid base64 ciphertext")?,
            mac: B64
                .decode(parts[2])
                .context("CipherString: invalid base64 MAC")?,
        })
    }
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

/// Decrypt one CipherString field using `keys`.
/// Returns the raw plaintext bytes.
fn decrypt_field(cipher_string: &str, keys: &BwKeys) -> Result<Vec<u8>> {
    use aes::Aes256;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let cs = CipherString::parse(cipher_string)?;

    // HMAC-SHA256(iv || ciphertext, mac_key) must match the stored MAC.
    let mut hmac = <Hmac<Sha256>>::new_from_slice(&keys.mac)
        .map_err(|_| anyhow!("HMAC: invalid key length"))?;
    hmac.update(&cs.iv);
    hmac.update(&cs.ciphertext);
    hmac.verify_slice(&cs.mac)
        .map_err(|_| anyhow!("HMAC verification failed — wrong password, email, or iterations"))?;

    // AES-256-CBC decrypt.
    type Aes256CbcDec = cbc::Decryptor<Aes256>;
    let plaintext = Aes256CbcDec::new_from_slices(&keys.enc, &cs.iv)
        .map_err(|_| anyhow!("AES-CBC: invalid key or IV length"))?
        .decrypt_padded_vec_mut::<Pkcs7>(&cs.ciphertext)
        .map_err(|_| anyhow!("AES-CBC: PKCS7 unpadding failed"))?;

    Ok(plaintext)
}

/// Decrypt a CipherString field as a UTF-8 string.
fn decrypt_str(cipher_string: &str, keys: &BwKeys) -> Result<String> {
    let bytes = decrypt_field(cipher_string, keys)?;
    String::from_utf8(bytes).map_err(|e| anyhow!("UTF-8 decode: {}", e))
}

/// Decrypt an optional field — returns `None` for null/missing, error on bad ciphertext.
#[allow(dead_code)]
fn decrypt_opt(value: Option<&str>, keys: &BwKeys) -> Result<Option<String>> {
    match value {
        None | Some("") => Ok(None),
        Some(s) if s.starts_with("2.") => Ok(Some(decrypt_str(s, keys)?)),
        Some(s) => Ok(Some(s.to_owned())), // already plaintext (unencrypted export)
    }
}

/// Prove that `keys` are correct by verifying the `encKeyValidation_DO_NOT_EDIT`
/// field decrypts without an HMAC failure. Returns `Ok(())` on success.
pub fn verify_keys(enc_key_validation: &str, keys: &BwKeys) -> Result<()> {
    // The field encrypts a random UUID — we don't validate the value,
    // only that the HMAC passes (which is sufficient proof of correct keys).
    decrypt_field(enc_key_validation, keys)
        .map(|_| ())
        .map_err(|_| anyhow!("Incorrect Bitwarden password, email, or iteration count"))
}

// ── Export JSON schema ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct BwExport {
    encrypted: bool,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    enc_key_validation: Option<String>,
    items: Vec<serde_json::Value>,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Import items from a Bitwarden JSON export file.
///
/// `path`       — file system path to the `.json` export
/// `password`   — Bitwarden master password (`None` for unencrypted exports)
/// `email`      — Bitwarden account email (only used for encrypted exports)
/// `iterations` — PBKDF2 iteration count (default 600,000; ignored for unencrypted)
///
/// Returns the list of `VaultItem`s ready to be added to the vault.
pub fn import_from_file(
    path: &str,
    password: Option<&str>,
    email: &str,
    iterations: u32,
) -> Result<Vec<VaultItem>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("Cannot read file: {path}"))?;
    let export: BwExport =
        serde_json::from_str(&raw).context("Not a valid Bitwarden JSON export")?;

    if export.encrypted {
        let pw =
            password.ok_or_else(|| anyhow!("Export is encrypted — master password required"))?;
        let validation = export
            .enc_key_validation
            .as_deref()
            .ok_or_else(|| anyhow!("Missing encKeyValidation_DO_NOT_EDIT field"))?;

        let keys = derive_keys(pw, email, iterations)?;
        verify_keys(validation, &keys)?;

        export
            .items
            .into_iter()
            .map(|v| decrypt_item(v, &keys))
            .collect()
    } else {
        // Plain JSON export — no decryption needed.
        export
            .items
            .into_iter()
            .map(|v| {
                serde_json::from_value::<BwItem>(v)
                    .map(VaultItem::from)
                    .map_err(|e| anyhow!("Failed to parse item: {e}"))
            })
            .collect()
    }
}

/// Decrypt every encrypted field in a single Bitwarden item JSON value, then
/// convert to a `VaultItem`.
fn decrypt_item(mut value: serde_json::Value, keys: &BwKeys) -> Result<VaultItem> {
    decrypt_value_fields(&mut value, keys)?;
    serde_json::from_value::<BwItem>(value)
        .map(VaultItem::from)
        .map_err(|e| anyhow!("Failed to parse decrypted item: {e}"))
}

/// Recursively walk a JSON value and decrypt every string that looks like a
/// CipherString (starts with `"2."`).
fn decrypt_value_fields(value: &mut serde_json::Value, keys: &BwKeys) -> Result<()> {
    match value {
        serde_json::Value::String(s) if s.starts_with("2.") => {
            *s = decrypt_str(s, keys)?;
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                decrypt_value_fields(v, keys)?;
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                decrypt_value_fields(v, keys)?;
            }
        }
        _ => {}
    }
    Ok(())
}
