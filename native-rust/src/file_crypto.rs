use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{
        consts::U12,
        Aead,
        KeyInit,
        Payload,
    },
    Aes256Gcm,
    Nonce,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    dek_envelope,
    mlkem_keystore,
};

const FILE_MAGIC: &[u8; 8] = b"CSEMLK01";
const FILE_NONCE_LENGTH: usize = 12;

// This prototype reads the entire input file into memory.
const MAX_INPUT_SIZE: u64 = 256 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FileCryptoError {
    #[error("input path is not a regular file: {0}")]
    NotARegularFile(PathBuf),

    #[error("input file is too large for this prototype: {0} bytes")]
    InputTooLarge(u64),

    #[error("input path has no file name")]
    MissingFileName,

    #[error("encrypted output already exists: {0}")]
    OutputAlreadyExists(PathBuf),

    #[error("file or envelope length is too large")]
    LengthTooLarge,

    #[error("could not initialize AES-256-GCM")]
    InvalidAesKey,

    #[error("AES-256-GCM file encryption failed")]
    EncryptionFailed,

    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("secure random generation failed: {0}")]
    Random(#[from] getrandom::Error),

    #[error("ML-KEM keystore operation failed: {0}")]
    MlKemKeystore(
        #[from] mlkem_keystore::MlKemKeystoreError,
    ),

    #[error("DEK envelope operation failed: {0}")]
    DekEnvelope(
        #[from] dek_envelope::DekEnvelopeError,
    ),
}

/// Encrypts a file without changing or deleting the original.
///
/// Example:
///
/// document.pdf -> document.pdf.cseml
pub fn encrypt_file(
    input_path: &Path,
) -> Result<PathBuf, FileCryptoError> {
    /*
     * Canonicalize the supplied path so Rust independently
     * validates the file even though Java already checked it.
     */
    let input_path = fs::canonicalize(input_path)?;
    let metadata = fs::metadata(&input_path)?;

    if !metadata.is_file() {
        return Err(
            FileCryptoError::NotARegularFile(input_path),
        );
    }

    if metadata.len() > MAX_INPUT_SIZE {
        return Err(
            FileCryptoError::InputTooLarge(metadata.len()),
        );
    }

    let output_path =
        encrypted_output_path(&input_path)?;

    if output_path.exists() {
        return Err(
            FileCryptoError::OutputAlreadyExists(
                output_path,
            ),
        );
    }

    /*
     * The complete plaintext file is held in zeroizing memory.
     * This prototype is therefore limited to reasonably sized
     * files. Streaming encryption can be added later.
     */
    let plaintext =
        Zeroizing::new(fs::read(&input_path)?);

    if plaintext.len() as u64 > MAX_INPUT_SIZE {
        return Err(
            FileCryptoError::InputTooLarge(
                plaintext.len() as u64,
            ),
        );
    }

    /*
     * Load the stored ML-KEM private key.
     *
     * The loader decrypts its private seed using DPAPI and
     * verifies that it matches the stored public key.
     */
    let ml_kem_private_key =
        mlkem_keystore::
        load_stored_ml_kem1024_decapsulation_key()?;

    /*
     * Generate a fresh random 32-byte AES-256 DEK for this file.
     */
    let dek = dek_envelope::generate_dek()?;

    /*
     * Wrap the DEK using the public part of the stored
     * ML-KEM-1024 keypair.
     */
    let wrapped_dek_envelope =
        dek_envelope::wrap_dek(
            ml_kem_private_key.encapsulation_key(),
            &*dek,
        )?;

    /*
     * Initialize AES-256-GCM using the plaintext DEK.
     */
    let cipher =
        Aes256Gcm::new_from_slice(&dek[..])
            .map_err(|_| {
                FileCryptoError::InvalidAesKey
            })?;

    /*
     * Generate a fresh 96-bit AES-GCM nonce for the file.
     */
    let mut file_nonce_bytes =
        [0u8; FILE_NONCE_LENGTH];

    getrandom::fill(&mut file_nonce_bytes)?;

    /*
     * Nonce expects the nonce-size type U12, not the
     * Aes256Gcm cipher type.
     */
    let file_nonce: Nonce<U12> =
        file_nonce_bytes.into();

    let ml_kem_ciphertext_length =
        u32::try_from(
            wrapped_dek_envelope
                .ml_kem_ciphertext
                .len(),
        )
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    let wrapped_dek_length =
        u32::try_from(
            wrapped_dek_envelope
                .wrapped_dek
                .len(),
        )
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    let original_file_length =
        u64::try_from(plaintext.len())
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    /*
     * Public authenticated header format:
     *
     * 8 bytes   magic/version
     * 4 bytes   ML-KEM ciphertext length
     * 4 bytes   wrapped DEK length
     * 8 bytes   original plaintext length
     * 12 bytes  DEK-envelope AES-GCM nonce
     * 12 bytes  file AES-GCM nonce
     *
     * The header is included as AES-GCM associated data.
     * It is visible but cannot be changed undetected.
     */
    let mut header = Vec::with_capacity(
        FILE_MAGIC.len()
            + size_of::<u32>()
            + size_of::<u32>()
            + size_of::<u64>()
            + wrapped_dek_envelope.nonce.len()
            + file_nonce_bytes.len(),
    );

    header.extend_from_slice(FILE_MAGIC);

    header.extend_from_slice(
        &ml_kem_ciphertext_length.to_le_bytes(),
    );

    header.extend_from_slice(
        &wrapped_dek_length.to_le_bytes(),
    );

    header.extend_from_slice(
        &original_file_length.to_le_bytes(),
    );

    header.extend_from_slice(
        &wrapped_dek_envelope.nonce,
    );

    header.extend_from_slice(
        &file_nonce_bytes,
    );

    /*
     * The returned value contains:
     *
     * encrypted file bytes + 16-byte AES-GCM tag
     */
    let encrypted_file = cipher
        .encrypt(
            &file_nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad: &header,
            },
        )
        .map_err(|_| {
            FileCryptoError::EncryptionFailed
        })?;

    write_encrypted_file(
        &output_path,
        &header,
        &wrapped_dek_envelope.ml_kem_ciphertext,
        &wrapped_dek_envelope.wrapped_dek,
        &encrypted_file,
    )?;

    Ok(output_path)
}

/// Creates an output path beside the original file.
///
/// report.pdf -> report.pdf.cseml
fn encrypted_output_path(
    input_path: &Path,
) -> Result<PathBuf, FileCryptoError> {
    let file_name = input_path
        .file_name()
        .ok_or(FileCryptoError::MissingFileName)?;

    let mut output_name =
        OsString::from(file_name);

    output_name.push(".cseml");

    Ok(input_path.with_file_name(output_name))
}

/// Writes the complete encrypted container without overwriting
/// an existing output file.
///
/// A partially written file is deleted when writing fails.
fn write_encrypted_file(
    output_path: &Path,
    header: &[u8],
    ml_kem_ciphertext: &[u8],
    wrapped_dek: &[u8],
    encrypted_file: &[u8],
) -> Result<(), FileCryptoError> {
    let mut output = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
    {
        Ok(file) => file,

        Err(error)
        if error.kind()
            == std::io::ErrorKind::AlreadyExists =>
            {
                return Err(
                    FileCryptoError::OutputAlreadyExists(
                        output_path.to_path_buf(),
                    ),
                );
            }

        Err(error) => {
            return Err(error.into());
        }
    };

    let result =
        (|| -> Result<(), std::io::Error> {
            output.write_all(header)?;

            output.write_all(
                ml_kem_ciphertext,
            )?;

            output.write_all(
                wrapped_dek,
            )?;

            output.write_all(
                encrypted_file,
            )?;

            output.sync_all()?;

            Ok(())
        })();

    if let Err(error) = result {
        drop(output);

        // Avoid leaving a damaged encrypted container.
        let _ = fs::remove_file(output_path);

        return Err(error.into());
    }

    Ok(())
}