use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use ml_kem::{
    kem::{Decapsulate, Encapsulate, KeyExport, KeyInit},
    DecapsulationKey1024,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::dpapi;

const ML_KEM_1024_SEED_LENGTH: usize = 64;

const PRIVATE_KEY_FILE_NAME: &str =
    "ml-kem-1024-private.dpapi";

const PUBLIC_KEY_FILE_NAME: &str =
    "ml-kem-1024-public.bin";

#[derive(Debug, Error)]
pub enum MlKemKeystoreError {
    #[error("LOCALAPPDATA is not available")]
    MissingLocalAppData,

    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("secure random generation failed: {0}")]
    Random(#[from] getrandom::Error),

    #[error("DPAPI operation failed: {0}")]
    Dpapi(#[from] dpapi::DpapiError),

    #[error("ML-KEM-1024 key material already exists")]
    AlreadyExists,

    #[error(
        "invalid ML-KEM-1024 private seed length: \
         found {0} bytes, expected 64"
    )]
    InvalidPrivateSeedLength(usize),

    #[error("ML-KEM-1024 private seed is invalid")]
    InvalidPrivateSeed,

    #[error(
        "stored ML-KEM-1024 public key does not match \
         the stored private key"
    )]
    PublicKeyMismatch,

    #[error("ML-KEM-1024 encapsulation self-test failed")]
    SelfTestFailed,
}

#[derive(Debug)]
pub struct MlKemKeyPaths {
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
}

fn application_directory(
) -> Result<PathBuf, MlKemKeystoreError> {
    let local_app_data =
        env::var_os("LOCALAPPDATA")
            .ok_or(
                MlKemKeystoreError::MissingLocalAppData,
            )?;

    Ok(
        PathBuf::from(local_app_data)
            .join("CSE-ML-KEM"),
    )
}

pub fn default_ml_kem_key_paths(
) -> Result<MlKemKeyPaths, MlKemKeystoreError> {
    let directory = application_directory()?;

    Ok(MlKemKeyPaths {
        private_key_path:
        directory.join(PRIVATE_KEY_FILE_NAME),

        public_key_path:
        directory.join(PUBLIC_KEY_FILE_NAME),
    })
}

pub fn generate_and_store_ml_kem1024_keypair(
) -> Result<MlKemKeyPaths, MlKemKeystoreError> {
    let paths = default_ml_kem_key_paths()?;

    generate_and_store_at(
        &paths.private_key_path,
        &paths.public_key_path,
    )?;

    Ok(paths)
}

pub fn verify_stored_ml_kem1024_keypair(
) -> Result<(), MlKemKeystoreError> {
    let paths = default_ml_kem_key_paths()?;

    verify_at(
        &paths.private_key_path,
        &paths.public_key_path,
    )
}

pub fn ml_kem1024_keypair_exists(
) -> Result<bool, MlKemKeystoreError> {
    let paths = default_ml_kem_key_paths()?;

    Ok(
        paths.private_key_path.exists()
            && paths.public_key_path.exists(),
    )
}

/// Loads the DPAPI-protected private seed, reconstructs the
/// ML-KEM decapsulation key, and confirms that its public key
/// matches the stored public-key file.
pub fn load_stored_ml_kem1024_decapsulation_key(
) -> Result<DecapsulationKey1024, MlKemKeystoreError> {
    let paths = default_ml_kem_key_paths()?;

    let protected_private_seed =
        fs::read(&paths.private_key_path)?;

    let private_seed =
        dpapi::unprotect(&protected_private_seed)?;

    if private_seed.len() != ML_KEM_1024_SEED_LENGTH {
        return Err(
            MlKemKeystoreError::InvalidPrivateSeedLength(
                private_seed.len(),
            ),
        );
    }

    let decapsulation_key =
        DecapsulationKey1024::new_from_slice(
            private_seed.as_slice(),
        )
            .map_err(|_| {
                MlKemKeystoreError::InvalidPrivateSeed
            })?;

    let stored_public_key =
        fs::read(&paths.public_key_path)?;

    let derived_public_key =
        decapsulation_key
            .encapsulation_key()
            .to_bytes();

    let derived_public_key_bytes: &[u8] =
        AsRef::<[u8]>::as_ref(&derived_public_key);

    if stored_public_key.as_slice()
        != derived_public_key_bytes
    {
        return Err(
            MlKemKeystoreError::PublicKeyMismatch,
        );
    }

    // private_seed is zeroized when it leaves scope.
    Ok(decapsulation_key)
}

fn generate_and_store_at(
    private_key_path: &Path,
    public_key_path: &Path,
) -> Result<(), MlKemKeystoreError> {
    if private_key_path.exists()
        || public_key_path.exists()
    {
        return Err(
            MlKemKeystoreError::AlreadyExists,
        );
    }

    let mut private_seed =
        Zeroizing::new(
            [0u8; ML_KEM_1024_SEED_LENGTH],
        );

    getrandom::fill(&mut private_seed[..])?;

    let decapsulation_key =
        DecapsulationKey1024::new_from_slice(
            &private_seed[..],
        )
            .map_err(|_| {
                MlKemKeystoreError::InvalidPrivateSeed
            })?;

    let encapsulation_key =
        decapsulation_key.encapsulation_key();

    let public_key_bytes =
        encapsulation_key.to_bytes();

    let public_key_slice: &[u8] =
        AsRef::<[u8]>::as_ref(&public_key_bytes);

    let protected_private_seed =
        dpapi::protect(&private_seed[..])?;

    if let Some(parent) = private_key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    write_new_file(
        private_key_path,
        &protected_private_seed,
    )?;

    if let Err(error) =
        write_new_file(
            public_key_path,
            public_key_slice,
        )
    {
        let _ = fs::remove_file(private_key_path);
        return Err(error);
    }

    Ok(())
}

fn verify_at(
    private_key_path: &Path,
    public_key_path: &Path,
) -> Result<(), MlKemKeystoreError> {
    let protected_private_seed =
        fs::read(private_key_path)?;

    let private_seed =
        dpapi::unprotect(&protected_private_seed)?;

    if private_seed.len() != ML_KEM_1024_SEED_LENGTH {
        return Err(
            MlKemKeystoreError::InvalidPrivateSeedLength(
                private_seed.len(),
            ),
        );
    }

    let decapsulation_key =
        DecapsulationKey1024::new_from_slice(
            private_seed.as_slice(),
        )
            .map_err(|_| {
                MlKemKeystoreError::InvalidPrivateSeed
            })?;

    let encapsulation_key =
        decapsulation_key.encapsulation_key();

    let stored_public_key =
        fs::read(public_key_path)?;

    let derived_public_key =
        encapsulation_key.to_bytes();

    let derived_public_key_bytes: &[u8] =
        AsRef::<[u8]>::as_ref(&derived_public_key);

    if stored_public_key.as_slice()
        != derived_public_key_bytes
    {
        return Err(
            MlKemKeystoreError::PublicKeyMismatch,
        );
    }

    let (
        ciphertext,
        sender_shared_secret,
    ) = encapsulation_key.encapsulate();

    let receiver_shared_secret =
        decapsulation_key
            .decapsulate(&ciphertext);

    if sender_shared_secret
        != receiver_shared_secret
    {
        return Err(
            MlKemKeystoreError::SelfTestFailed,
        );
    }

    Ok(())
}

fn write_new_file(
    path: &Path,
    bytes: &[u8],
) -> Result<(), MlKemKeystoreError> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,

        Err(error)
        if error.kind()
            == std::io::ErrorKind::AlreadyExists =>
            {
                return Err(
                    MlKemKeystoreError::AlreadyExists,
                );
            }

        Err(error) => return Err(error.into()),
    };

    let result =
        (|| -> Result<(), std::io::Error> {
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        })();

    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths(
        test_name: &str,
    ) -> (PathBuf, PathBuf) {
        let process_id =
            std::process::id();

        let directory =
            env::temp_dir();

        let private_path = directory.join(
            format!(
                "cse-ml-kem-{test_name}-private-{process_id}.dpapi"
            ),
        );

        let public_path = directory.join(
            format!(
                "cse-ml-kem-{test_name}-public-{process_id}.bin"
            ),
        );

        (private_path, public_path)
    }

    #[test]
    fn ml_kem_keypair_file_round_trip() {
        let (
            private_path,
            public_path,
        ) = test_paths("round-trip");

        let _ = fs::remove_file(&private_path);
        let _ = fs::remove_file(&public_path);

        generate_and_store_at(
            &private_path,
            &public_path,
        )
            .expect(
                "ML-KEM key generation and storage should succeed",
            );

        let stored_private =
            fs::read(&private_path)
                .expect(
                    "protected private key should be readable",
                );

        let stored_public =
            fs::read(&public_path)
                .expect(
                    "public key should be readable",
                );

        assert!(!stored_private.is_empty());
        assert!(!stored_public.is_empty());

        assert_ne!(
            stored_private.len(),
            ML_KEM_1024_SEED_LENGTH,
            "the private file must contain a DPAPI blob",
        );

        verify_at(
            &private_path,
            &public_path,
        )
            .expect(
                "stored ML-KEM keypair should verify",
            );

        let _ = fs::remove_file(private_path);
        let _ = fs::remove_file(public_path);
    }

    #[test]
    fn refuses_to_overwrite_ml_kem_keypair() {
        let (
            private_path,
            public_path,
        ) = test_paths("overwrite");

        let _ = fs::remove_file(&private_path);
        let _ = fs::remove_file(&public_path);

        generate_and_store_at(
            &private_path,
            &public_path,
        )
            .expect(
                "first key generation should succeed",
            );

        let error =
            generate_and_store_at(
                &private_path,
                &public_path,
            )
                .expect_err(
                    "second generation must be rejected",
                );

        assert!(matches!(
            error,
            MlKemKeystoreError::AlreadyExists
        ));

        verify_at(
            &private_path,
            &public_path,
        )
            .expect(
                "the original keypair must remain valid",
            );

        let _ = fs::remove_file(private_path);
        let _ = fs::remove_file(public_path);
    }
}