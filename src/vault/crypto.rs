/// AES-256-GCM encryption/decryption and PBKDF2-HMAC-SHA256 key derivation for vault values.
///
/// # Storage format
///
/// Encrypted blobs are stored as `nonce(12) || ciphertext+tag(n+16)` where `n` is the
/// plaintext length. The 12-byte nonce is prepended and the 16-byte authentication tag
/// is appended by `aes-gcm` as part of the ciphertext output.
///
/// # Security notes
///
/// - Each call to [`encrypt`] generates a fresh random 12-byte nonce via `rand`.
///   Nonces are NEVER reused for the same key; AES-GCM is catastrophically broken
///   on nonce reuse.
/// - The encryption key is derived via PBKDF2-HMAC-SHA256 with 100,000 iterations.
///   A fixed domain-separation salt is used (`privox-vault-key-v1`). The installation
///   secret provides the entropy; the salt provides domain separation.
/// - This module is the only component that performs encryption/decryption.
///   Plaintext values must not escape this module.
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

use crate::error::VaultError;

/// Domain-separation salt for PBKDF2.
///
/// The installation secret provides all entropy; this constant ensures that keys
/// derived by `privox` are distinct from keys derived by other applications
/// that might share the same secret material.
const KEY_DERIVATION_SALT: &[u8] = b"privox-vault-key-v1";

/// Number of PBKDF2 iterations. NIST SP 800-132 recommends ≥10,000; we use 100,000.
const PBKDF2_ITERATIONS: u32 = 100_000;

/// AES-GCM nonce length in bytes (96 bits).
const NONCE_LEN: usize = 12;

/// Derives a 256-bit AES-GCM encryption key from the installation secret.
///
/// Uses PBKDF2-HMAC-SHA256 with [`PBKDF2_ITERATIONS`] rounds and a fixed
/// domain-separation salt. The output is suitable for use as an AES-256-GCM key.
///
/// # Errors
///
/// Returns [`VaultError::KeyDerivation`] if the PBKDF2 output length is unexpected
/// (should not happen in practice with a fixed 32-byte output buffer).
///
/// # Example
///
/// ```no_run
/// # use privox::vault::crypto::derive_key;
/// let secret = b"my-installation-secret";
/// let key = derive_key(secret).unwrap();
/// assert_eq!(key.len(), 32);
/// ```
pub fn derive_key(secret: &[u8]) -> Result<[u8; 32], VaultError> {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(secret, KEY_DERIVATION_SALT, PBKDF2_ITERATIONS, &mut key);
    Ok(key)
}

/// Encrypts `plaintext` with AES-256-GCM using the provided 256-bit `key`.
///
/// A fresh 12-byte nonce is generated for each call. The returned blob has the format:
/// `nonce(12) || ciphertext+tag(n+16)`.
///
/// # Errors
///
/// Returns [`VaultError::Encryption`] if AES-GCM encryption fails (should not
/// happen under normal conditions with a valid key).
///
/// # Example
///
/// ```no_run
/// # use privox::vault::crypto::{derive_key, encrypt, decrypt};
/// let key = derive_key(b"secret").unwrap();
/// let blob = encrypt(&key, b"sensitive value").unwrap();
/// let recovered = decrypt(&key, &blob).unwrap();
/// assert_eq!(recovered, b"sensitive value");
/// ```
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    // Generate a fresh random nonce for every encryption call.
    // AES-GCM is broken if the same nonce is used twice with the same key.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| VaultError::Encryption(e.to_string()))?;

    // Prepend the nonce so decrypt can recover it: nonce || ciphertext+tag
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypts a blob produced by [`encrypt`].
///
/// Expects the format `nonce(12) || ciphertext+tag(n+16)`.
///
/// # Errors
///
/// Returns [`VaultError::Decryption`] if the blob is too short, the tag is invalid
/// (tampered or corrupted data), or any other AES-GCM failure.
///
/// # Example
///
/// ```no_run
/// # use privox::vault::crypto::{derive_key, encrypt, decrypt};
/// let key = derive_key(b"secret").unwrap();
/// let blob = encrypt(&key, b"hello").unwrap();
/// assert_eq!(decrypt(&key, &blob).unwrap(), b"hello");
/// ```
pub fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, VaultError> {
    if blob.len() < NONCE_LEN {
        return Err(VaultError::Decryption(format!(
            "blob too short: expected at least {NONCE_LEN} bytes for nonce, got {}",
            blob.len()
        )));
    }

    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| VaultError::Decryption(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test-installation-secret-for-unit-tests";

    #[test]
    fn derive_key_produces_32_bytes() {
        let key = derive_key(TEST_SECRET).expect("key derivation must succeed");
        assert_eq!(key.len(), 32, "derived key must be 32 bytes (AES-256)");
    }

    #[test]
    fn derive_key_is_deterministic() {
        let key1 = derive_key(TEST_SECRET).expect("first derivation must succeed");
        let key2 = derive_key(TEST_SECRET).expect("second derivation must succeed");
        assert_eq!(
            key1, key2,
            "key derivation must be deterministic for the same secret"
        );
    }

    #[test]
    fn derive_key_differs_for_different_secrets() {
        let key1 = derive_key(b"secret-a").expect("must succeed");
        let key2 = derive_key(b"secret-b").expect("must succeed");
        assert_ne!(key1, key2, "different secrets must produce different keys");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_key(TEST_SECRET).expect("must succeed");
        let plaintext = b"sensitive-test-value@example.com";
        let blob = encrypt(&key, plaintext).expect("encryption must succeed");
        let recovered = decrypt(&key, &blob).expect("decryption must succeed");
        assert_eq!(
            recovered, plaintext,
            "decrypted value must match original plaintext"
        );
    }

    #[test]
    fn encrypt_produces_fresh_nonce_each_call() {
        let key = derive_key(TEST_SECRET).expect("must succeed");
        let plaintext = b"same plaintext";
        let blob1 = encrypt(&key, plaintext).expect("first encrypt must succeed");
        let blob2 = encrypt(&key, plaintext).expect("second encrypt must succeed");
        // The nonces (first 12 bytes) should differ with overwhelming probability.
        assert_ne!(
            &blob1[..NONCE_LEN],
            &blob2[..NONCE_LEN],
            "consecutive encryptions of the same value must use different nonces"
        );
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = derive_key(TEST_SECRET).expect("must succeed");
        let mut blob = encrypt(&key, b"original").expect("must succeed");
        // Flip a byte in the ciphertext portion (after the nonce).
        blob[NONCE_LEN] ^= 0xFF;
        let result = decrypt(&key, &blob);
        assert!(
            result.is_err(),
            "decryption of tampered ciphertext must return an error"
        );
    }

    #[test]
    fn decrypt_rejects_truncated_blob() {
        let key = derive_key(TEST_SECRET).expect("must succeed");
        let short_blob = &[0u8; 5];
        let result = decrypt(&key, short_blob);
        assert!(
            result.is_err(),
            "decryption of a blob shorter than nonce length must fail"
        );
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let key1 = derive_key(b"secret-one").expect("must succeed");
        let key2 = derive_key(b"secret-two").expect("must succeed");
        let blob = encrypt(&key1, b"secret data").expect("must succeed");
        let result = decrypt(&key2, &blob);
        assert!(
            result.is_err(),
            "decryption with wrong key must fail authentication"
        );
    }

    #[test]
    fn encrypt_handles_empty_plaintext() {
        let key = derive_key(TEST_SECRET).expect("must succeed");
        let blob = encrypt(&key, b"").expect("encrypting empty plaintext must succeed");
        let recovered = decrypt(&key, &blob).expect("must succeed");
        assert!(recovered.is_empty(), "recovered value must be empty");
    }
}
