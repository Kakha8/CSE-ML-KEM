use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
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

    #[error("an AES-256 key already exists at {0}")]
    AlreadyExists(PathBuf),

    #[error("invalid AES-256 key length: found {0} bytes, expected 32")]
    InvalidKeyLength(usize),
}

/// Returns the default protected-key location:
///
/// C:\Users\<user>\AppData\Local\CSE-ML-KEM\aes-256-key.dpapi
pub fn default_aes_key_path() -> Result<PathBuf, KeystoreError> {
    let local_app_data = env::var_os("LOCALAPPDATA").ok_or(KeystoreError::MissingLocalAppData)?;

    Ok(PathBuf::from(local_app_data)
        .join("CSE-ML-KEM")
        .join(KEY_FILE_NAME))
}

/// Generates a secure random 32-byte AES-256 key.
///
/// Only the DPAPI-protected representation is written to disk.
/// The plaintext key is zeroized when this function returns.
pub fn generate_and_store_aes256_key() -> Result<PathBuf, KeystoreError> {
    let mut key = Zeroizing::new([0u8; AES_256_KEY_LENGTH]);

    // Uses the operating system's secure random source.
    getrandom::fill(&mut key[..])?;

    let path = default_aes_key_path()?;

    create_aes256_key_at(&path, &key[..])?;

    // `key` is automatically zeroized here.
    Ok(path)
}

/// Loads and decrypts the stored AES-256 key.
///
/// The returned key is automatically zeroized when dropped.
pub fn load_aes256_key() -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let path = default_aes_key_path()?;
    load_aes256_key_at(&path)
}

/// Returns whether the default AES key file exists.
pub fn aes256_key_exists() -> Result<bool, KeystoreError> {
    let path = default_aes_key_path()?;
    Ok(path.exists())
}

/// Creates a new protected key file without overwriting an
/// existing key.
fn create_aes256_key_at(path: &Path, key: &[u8]) -> Result<(), KeystoreError> {
    if key.len() != AES_256_KEY_LENGTH {
        return Err(KeystoreError::InvalidKeyLength(key.len()));
    }

    // Protect the plaintext key before touching the filesystem.
    let protected_blob = dpapi::protect(key)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // create_new(true) guarantees that an existing key is not
    // silently overwritten.
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,

        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(KeystoreError::AlreadyExists(path.to_path_buf()));
        }

        Err(error) => return Err(error.into()),
    };

    let write_result = (|| -> Result<(), std::io::Error> {
        file.write_all(&protected_blob)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(error) = write_result {
        // Do not leave a partially written key file.
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }

    Ok(())
}

/// Loads a DPAPI-protected key from a specific location.
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

    fn test_path(name: &str) -> PathBuf {
        env::temp_dir().join(format!("cse-ml-kem-{name}-{}.dpapi", std::process::id()))
    }

    #[test]
    fn aes_key_file_round_trip() {
        let path = test_path("round-trip");

        // Remove leftovers from an interrupted earlier test.
        let _ = fs::remove_file(&path);

        // Fixed test bytes, not a real cryptographic key.
        let original_key = [0xA5_u8; AES_256_KEY_LENGTH];

        create_aes256_key_at(&path, &original_key)
            .expect("saving the protected key should succeed");

        let stored_bytes = fs::read(&path).expect("protected key file should be readable");

        assert!(!stored_bytes.is_empty());

        assert_ne!(
            stored_bytes.as_slice(),
            original_key.as_slice(),
            "the file must not contain the plaintext key"
        );

        let recovered_key =
            load_aes256_key_at(&path).expect("loading the protected key should succeed");

        assert_eq!(
            recovered_key.as_slice(),
            original_key.as_slice(),
            "the recovered key must match the original"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn refuses_to_overwrite_existing_key() {
        let path = test_path("overwrite");

        let _ = fs::remove_file(&path);

        let first_key = [0x11_u8; AES_256_KEY_LENGTH];

        let second_key = [0x22_u8; AES_256_KEY_LENGTH];

        create_aes256_key_at(&path, &first_key).expect("first key creation should succeed");

        let error = create_aes256_key_at(&path, &second_key)
            .expect_err("second key creation must be rejected");

        assert!(
            matches!(&error, KeystoreError::AlreadyExists(_)),
            "expected AlreadyExists, received: {error}"
        );

        let recovered_key = load_aes256_key_at(&path).expect("the original key should still load");

        assert_eq!(
            recovered_key.as_slice(),
            first_key.as_slice(),
            "the original key must not be overwritten"
        );

        let _ = fs::remove_file(path);
    }
}
