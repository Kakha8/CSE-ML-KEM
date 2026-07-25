use std::{
    env, fs,
    path::{Path, PathBuf},
};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::dpapi;

const AES_256_KEY_LENGTH: usize = 32;
const KEY_FILE_NAME: &str = "aes-256-key.dpapi";

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("LOCALAPPDATA is not available")]
    MissingLocalAppData,

    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("secure random generation failed: {0}")]
    Random(#[from] getrandom::Error),

    #[error("DPAPI operation failed: {0}")]
    Dpapi(#[from] dpapi::DpapiError),

    #[error("invalid AES-256 key length: found {0} bytes, expected 32")]
    InvalidKeyLength(usize),
}

/// Returns:
/// C:\Users\<user>\AppData\Local\CSE-ML-KEM\aes-256-key.dpapi
pub fn default_aes_key_path() -> Result<PathBuf, KeystoreError> {
    let local_app_data = env::var_os("LOCALAPPDATA").ok_or(KeystoreError::MissingLocalAppData)?;

    Ok(PathBuf::from(local_app_data)
        .join("CSE-ML-KEM")
        .join(KEY_FILE_NAME))
}

/// Generates a new AES-256 key and saves only its DPAPI-protected form.
pub fn generate_and_store_aes256_key() -> Result<PathBuf, KeystoreError> {
    let mut key = Zeroizing::new([0u8; AES_256_KEY_LENGTH]);

    // Fill all 32 bytes using the operating system RNG.
    getrandom::fill(&mut key[..])?;

    let path = default_aes_key_path()?;
    save_aes256_key_at(&path, &key[..])?;

    // `key` is zeroized when this function ends.
    Ok(path)
}

/// Protects and writes an existing 32-byte key.
///
/// This helper is also useful for deterministic unit tests.
fn save_aes256_key_at(path: &Path, key: &[u8]) -> Result<(), KeystoreError> {
    if key.len() != AES_256_KEY_LENGTH {
        return Err(KeystoreError::InvalidKeyLength(key.len()));
    }

    let protected_blob = dpapi::protect(key)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Only the protected blob is written.
    fs::write(path, protected_blob)?;

    Ok(())
}

/// Reads and recovers the AES-256 key.
pub fn load_aes256_key() -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let path = default_aes_key_path()?;
    load_aes256_key_at(&path)
}

fn load_aes256_key_at(path: &Path) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let protected_blob = fs::read(path)?;
    let key = dpapi::unprotect(&protected_blob)?;

    if key.len() != AES_256_KEY_LENGTH {
        return Err(KeystoreError::InvalidKeyLength(key.len()));
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_key_file_round_trip() {
        // Use a temporary test file instead of the real application key.
        let test_path =
            env::temp_dir().join(format!("cse-ml-kem-aes-test-{}.dpapi", std::process::id()));

        // Fixed test data, not a real randomly generated key.
        let original_key = [0xA5_u8; AES_256_KEY_LENGTH];

        save_aes256_key_at(&test_path, &original_key)
            .expect("saving the protected key should succeed");

        // Confirm plaintext was not written directly to disk.
        let stored_bytes = fs::read(&test_path).expect("test file should be readable");

        assert_ne!(
            stored_bytes.as_slice(),
            original_key.as_slice(),
            "the file must not contain the plaintext key"
        );

        let recovered_key =
            load_aes256_key_at(&test_path).expect("loading the protected key should succeed");

        assert_eq!(
            recovered_key.as_slice(),
            original_key.as_slice(),
            "the recovered key must match the original"
        );

        let _ = fs::remove_file(test_path);
    }
}

#[test]
#[ignore = "creates a real AES key under LOCALAPPDATA"]
fn create_and_load_real_aes_key() {
    let path = generate_and_store_aes256_key()
        .expect("AES-256 key generation and storage should succeed");

    println!("Protected key stored at: {}", path.display());

    let recovered = load_aes256_key()
        .expect("stored AES-256 key should load successfully");

    assert_eq!(recovered.len(), AES_256_KEY_LENGTH);
}
