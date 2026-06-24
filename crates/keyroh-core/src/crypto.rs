use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use ring::pbkdf2;
use std::num::NonZeroU32;
use rand::Rng;
use anyhow::{anyhow, Result};

const PBKDF2_ITERATIONS: u32 = 100_000;

/// Derives a 32-byte key from a password and salt using PBKDF2-HMAC-SHA256.
pub fn derive_key(password: &str, salt: &[u8], out: &mut [u8; 32]) {
    let iterations = NonZeroU32::new(PBKDF2_ITERATIONS).unwrap();
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password.as_bytes(),
        out,
    );
}

/// Encrypts data using AES-256-GCM.
/// Prepends a 12-byte random nonce to the ciphertext.
pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to initialize cipher: {}", e))?;
    
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| anyhow!("Failed to encrypt: {}", e))?;
    
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts data using AES-256-GCM.
/// Expects the first 12 bytes of `encrypted_data` to be the nonce.
pub fn decrypt(encrypted_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if encrypted_data.len() < 12 {
        return Err(anyhow!("Encrypted data too short"));
    }
    
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to initialize cipher: {}", e))?;
    
    let nonce = Nonce::from_slice(&encrypted_data[..12]);
    let ciphertext = &encrypted_data[12..];
    
    let decrypted = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Failed to decrypt (invalid password or corrupted data): {}", e))?;
        
    Ok(decrypted)
}
