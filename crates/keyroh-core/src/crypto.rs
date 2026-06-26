use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, anyhow};
use argon2::Argon2;
use rand::Rng;

/// Derives a 32-byte key from a password and salt using Argon2id.
pub fn derive_key(password: &str, salt: &[u8], out: &mut [u8; 32]) {
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, out)
        .expect("Argon2 key derivation failed");
}

/// Encrypts `data` with AES-256-GCM, returning `(nonce, ciphertext)`.
///
/// The nonce is 12 random bytes.  The caller decides how to store them —
/// use [`encrypt_blob`] when you want the traditional prepended format.
pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<([u8; 12], Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to initialize cipher: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow!("Failed to encrypt: {}", e))?;

    Ok((nonce_bytes, ciphertext))
}

/// Decrypts `ciphertext` with AES-256-GCM using an explicit `nonce`.
pub fn decrypt(nonce: &[u8; 12], ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to initialize cipher: {}", e))?;

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| anyhow!("Failed to decrypt (invalid key or corrupted data): {}", e))
}

/// Encrypt and return `nonce || ciphertext` as a single `Vec<u8>`.
///
/// Convenient for values stored in state.json (hex) or iroh blobs where the
/// caller does not need the nonce as a separate field.
pub fn encrypt_blob(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let (nonce, ciphertext) = encrypt(data, key)?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob of the form `nonce(12 B) || ciphertext`.
///
/// Counterpart to [`encrypt_blob`].
pub fn decrypt_blob(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if blob.len() < 12 {
        return Err(anyhow!("Encrypted blob too short ({} bytes)", blob.len()));
    }
    let nonce: [u8; 12] = blob[..12].try_into().expect("slice is exactly 12 bytes");
    decrypt(&nonce, &blob[12..], key)
}
