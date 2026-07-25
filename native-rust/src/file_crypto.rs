use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    mem::size_of,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{consts::U12, Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{dek_envelope, mlkem_keystore};

const FILE_MAGIC: &[u8; 8] = b"CSEMLK01";
const FILE_NONCE_LENGTH: usize = 12;
const AES_GCM_TAG_LENGTH: usize = 16;

/*
 * Header:
 *
 * 8 bytes   magic/version
 * 4 bytes   ML-KEM ciphertext length (little-endian)
 * 4 bytes   wrapped DEK length (little-endian)
 * 8 bytes   original plaintext length (little-endian)
 * 12 bytes  DEK-envelope AES-GCM nonce
 * 12 bytes  file AES-GCM nonce
 */
const HEADER_LENGTH: usize =
    8 + size_of::<u32>() + size_of::<u32>() + size_of::<u64>()
        + FILE_NONCE_LENGTH + FILE_NONCE_LENGTH;

// This prototype reads the entire file into memory.
const MAX_INPUT_SIZE: u64 = 256 * 1024 * 1024;

// Allow room for the header, ML-KEM ciphertext, wrapped DEK, and tags.
const MAX_CONTAINER_SIZE: u64 = MAX_INPUT_SIZE + 4 * 1024 * 1024;

// Defensive bound for attacker-controlled container lengths.
const MAX_ENVELOPE_COMPONENT_LENGTH: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum FileCryptoError {
    #[error("input path is not a regular file: {0}")]
    NotARegularFile(PathBuf),

    #[error("input file is too large for this prototype: {0} bytes")]
    InputTooLarge(u64),

    #[error("encrypted container is too large for this prototype: {0} bytes")]
    ContainerTooLarge(u64),

    #[error("input path has no file name")]
    MissingFileName,

    #[error("output path points to the encrypted input file")]
    OutputMatchesInput,

    #[error("output path is a directory: {0}")]
    OutputIsDirectory(PathBuf),

    #[error("could not create a temporary output file")]
    TemporaryOutputUnavailable,

    #[error("output already exists: {0}")]
    OutputAlreadyExists(PathBuf),

    #[error("file or envelope length is too large")]
    LengthTooLarge,

    #[error("encrypted container magic or version is invalid")]
    InvalidMagic,

    #[error("encrypted container is invalid: {0}")]
    InvalidContainer(&'static str),

    #[error("could not initialize AES-256-GCM")]
    InvalidAesKey,

    #[error("AES-256-GCM file encryption failed")]
    EncryptionFailed,

    #[error("AES-256-GCM file decryption or authentication failed")]
    DecryptionFailed,

    #[error(
        "decrypted file length mismatch: expected {expected} bytes, found {actual}"
    )]
    DecryptedLengthMismatch {
        expected: u64,
        actual: usize,
    },

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

struct ParsedContainer<'a> {
    header: &'a [u8],
    ml_kem_ciphertext: &'a [u8],
    wrapped_dek: &'a [u8],
    encrypted_file: &'a [u8],
    envelope_nonce: [u8; FILE_NONCE_LENGTH],
    file_nonce: [u8; FILE_NONCE_LENGTH],
    original_file_length: u64,
}

/// Encrypts a file without changing or deleting the original.
///
/// Example:
///
/// document.pdf -> document.pdf.cseml
pub fn encrypt_file(
    input_path: &Path,
) -> Result<PathBuf, FileCryptoError> {
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
     * This prototype holds the whole plaintext in memory.
     * It is cleared when `plaintext` leaves scope.
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
     * Load and validate the stored ML-KEM keypair.
     */
    let ml_kem_private_key =
        mlkem_keystore::
        load_stored_ml_kem1024_decapsulation_key()?;

    /*
     * Generate a new random DEK for this file.
     */
    let dek = dek_envelope::generate_dek()?;

    /*
     * Wrap the DEK using ML-KEM plus the envelope AES-GCM
     * operation implemented in `dek_envelope.rs`.
     */
    let wrapped_dek_envelope =
        dek_envelope::wrap_dek(
            ml_kem_private_key.encapsulation_key(),
            &*dek,
        )?;

    let cipher =
        Aes256Gcm::new_from_slice(&dek[..])
            .map_err(|_| {
                FileCryptoError::InvalidAesKey
            })?;

    let mut file_nonce_bytes =
        [0u8; FILE_NONCE_LENGTH];

    getrandom::fill(&mut file_nonce_bytes)?;

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
     * The public header is authenticated as AES-GCM AAD.
     */
    let mut header =
        Vec::with_capacity(HEADER_LENGTH);

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

    debug_assert_eq!(header.len(), HEADER_LENGTH);

    /*
     * AES-GCM returns ciphertext followed by its authentication
     * tag.
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

/// Decrypts a `.cseml` container without deleting or changing it.
///
/// Example:
///
/// document.pdf.cseml -> document.pdf.decrypted
pub fn decrypt_file(
    input_path: &Path,
) -> Result<PathBuf, FileCryptoError> {
    let output_path =
        decrypted_output_path(input_path)?;

    decrypt_file_to(
        input_path,
        &output_path,
        false,
    )
}

/// Decrypts a `.cseml` container to a caller-selected path.
///
/// When `overwrite` is false, an existing output is rejected.
/// When it is true, the caller has explicitly approved replacing
/// the existing output. Authentication and decryption complete
/// before any existing file is replaced.
pub fn decrypt_file_to(
    input_path: &Path,
    output_path: &Path,
    overwrite: bool,
) -> Result<PathBuf, FileCryptoError> {
    let input_path = fs::canonicalize(input_path)?;
    let metadata = fs::metadata(&input_path)?;

    if !metadata.is_file() {
        return Err(
            FileCryptoError::NotARegularFile(input_path),
        );
    }

    if metadata.len() > MAX_CONTAINER_SIZE {
        return Err(
            FileCryptoError::ContainerTooLarge(
                metadata.len(),
            ),
        );
    }

    let output_path =
        normalize_output_path(output_path)?;

    if output_path == input_path {
        return Err(
            FileCryptoError::OutputMatchesInput,
        );
    }

    if output_path.exists() {
        let output_metadata =
            fs::metadata(&output_path)?;

        if output_metadata.is_dir() {
            return Err(
                FileCryptoError::OutputIsDirectory(
                    output_path,
                ),
            );
        }

        if !overwrite {
            return Err(
                FileCryptoError::OutputAlreadyExists(
                    output_path,
                ),
            );
        }
    }

    let container = fs::read(&input_path)?;
    let parsed = parse_container(&container)?;

    let ml_kem_private_key =
        mlkem_keystore::
        load_stored_ml_kem1024_decapsulation_key()?;

    let envelope = dek_envelope::DekEnvelope {
        ml_kem_ciphertext:
        parsed.ml_kem_ciphertext.to_vec(),

        nonce: parsed.envelope_nonce,

        wrapped_dek:
        parsed.wrapped_dek.to_vec(),
    };

    let dek = dek_envelope::unwrap_dek(
        &ml_kem_private_key,
        &envelope,
    )?;

    let cipher =
        Aes256Gcm::new_from_slice(&dek[..])
            .map_err(|_| {
                FileCryptoError::InvalidAesKey
            })?;

    let file_nonce: Nonce<U12> =
        parsed.file_nonce.into();

    /*
     * Authentication and decryption happen completely before
     * the existing output is touched.
     */
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &file_nonce,
                Payload {
                    msg: parsed.encrypted_file,
                    aad: parsed.header,
                },
            )
            .map_err(|_| {
                FileCryptoError::DecryptionFailed
            })?,
    );

    if plaintext.len() as u64
        != parsed.original_file_length
    {
        return Err(
            FileCryptoError::DecryptedLengthMismatch {
                expected:
                parsed.original_file_length,

                actual:
                plaintext.len(),
            },
        );
    }

    if overwrite {
        write_decrypted_file_replacing(
            &output_path,
            plaintext.as_slice(),
        )?;
    } else {
        write_decrypted_file(
            &output_path,
            plaintext.as_slice(),
        )?;
    }

    Ok(output_path)
}

fn parse_container(
    container: &[u8],
) -> Result<ParsedContainer<'_>, FileCryptoError> {
    if container.len()
        < HEADER_LENGTH + AES_GCM_TAG_LENGTH
    {
        return Err(
            FileCryptoError::InvalidContainer(
                "container is shorter than the minimum size",
            ),
        );
    }

    if &container[0..FILE_MAGIC.len()]
        != FILE_MAGIC
    {
        return Err(FileCryptoError::InvalidMagic);
    }

    let ml_kem_ciphertext_length =
        u32::from_le_bytes(
            container[8..12]
                .try_into()
                .map_err(|_| {
                    FileCryptoError::InvalidContainer(
                        "could not read ML-KEM ciphertext length",
                    )
                })?,
        ) as usize;

    let wrapped_dek_length =
        u32::from_le_bytes(
            container[12..16]
                .try_into()
                .map_err(|_| {
                    FileCryptoError::InvalidContainer(
                        "could not read wrapped DEK length",
                    )
                })?,
        ) as usize;

    let original_file_length =
        u64::from_le_bytes(
            container[16..24]
                .try_into()
                .map_err(|_| {
                    FileCryptoError::InvalidContainer(
                        "could not read original file length",
                    )
                })?,
        );

    if original_file_length > MAX_INPUT_SIZE {
        return Err(
            FileCryptoError::InputTooLarge(
                original_file_length,
            ),
        );
    }

    if ml_kem_ciphertext_length == 0
        || ml_kem_ciphertext_length
        > MAX_ENVELOPE_COMPONENT_LENGTH
    {
        return Err(
            FileCryptoError::InvalidContainer(
                "ML-KEM ciphertext length is invalid",
            ),
        );
    }

    if wrapped_dek_length < AES_GCM_TAG_LENGTH
        || wrapped_dek_length
        > MAX_ENVELOPE_COMPONENT_LENGTH
    {
        return Err(
            FileCryptoError::InvalidContainer(
                "wrapped DEK length is invalid",
            ),
        );
    }

    let original_file_length_usize =
        usize::try_from(original_file_length)
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    let encrypted_file_length =
        original_file_length_usize
            .checked_add(AES_GCM_TAG_LENGTH)
            .ok_or(
                FileCryptoError::LengthTooLarge,
            )?;

    let expected_total_length = HEADER_LENGTH
        .checked_add(ml_kem_ciphertext_length)
        .and_then(|value| {
            value.checked_add(wrapped_dek_length)
        })
        .and_then(|value| {
            value.checked_add(encrypted_file_length)
        })
        .ok_or(FileCryptoError::LengthTooLarge)?;

    if container.len() != expected_total_length {
        return Err(
            FileCryptoError::InvalidContainer(
                "container length does not match its header",
            ),
        );
    }

    let envelope_nonce:
        [u8; FILE_NONCE_LENGTH] =
        container[24..36]
            .try_into()
            .map_err(|_| {
                FileCryptoError::InvalidContainer(
                    "could not read envelope nonce",
                )
            })?;

    let file_nonce:
        [u8; FILE_NONCE_LENGTH] =
        container[36..48]
            .try_into()
            .map_err(|_| {
                FileCryptoError::InvalidContainer(
                    "could not read file nonce",
                )
            })?;

    let ml_kem_ciphertext_start =
        HEADER_LENGTH;

    let ml_kem_ciphertext_end =
        ml_kem_ciphertext_start
            + ml_kem_ciphertext_length;

    let wrapped_dek_end =
        ml_kem_ciphertext_end
            + wrapped_dek_length;

    Ok(ParsedContainer {
        header:
        &container[..HEADER_LENGTH],

        ml_kem_ciphertext:
        &container[
            ml_kem_ciphertext_start
                ..ml_kem_ciphertext_end
            ],

        wrapped_dek:
        &container[
            ml_kem_ciphertext_end
                ..wrapped_dek_end
            ],

        encrypted_file:
        &container[wrapped_dek_end..],

        envelope_nonce,

        file_nonce,

        original_file_length,
    })
}

fn normalize_output_path(
    output_path: &Path,
) -> Result<PathBuf, FileCryptoError> {
    if output_path.exists() {
        return Ok(fs::canonicalize(output_path)?);
    }

    let file_name = output_path
        .file_name()
        .ok_or(FileCryptoError::MissingFileName)?;

    let parent = output_path
        .parent()
        .filter(|path| {
            !path.as_os_str().is_empty()
        })
        .unwrap_or_else(|| Path::new("."));

    let canonical_parent =
        fs::canonicalize(parent)?;

    Ok(canonical_parent.join(file_name))
}

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

fn decrypted_output_path(
    input_path: &Path,
) -> Result<PathBuf, FileCryptoError> {
    let is_cseml_file = input_path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("cseml")
        });

    if !is_cseml_file {
        return Err(
            FileCryptoError::InvalidContainer(
                "encrypted file must have the .cseml extension",
            ),
        );
    }

    let original_file_name = input_path
        .file_stem()
        .ok_or(FileCryptoError::MissingFileName)?;

    Ok(input_path.with_file_name(original_file_name))
}

fn write_encrypted_file(
    output_path: &Path,
    header: &[u8],
    ml_kem_ciphertext: &[u8],
    wrapped_dek: &[u8],
    encrypted_file: &[u8],
) -> Result<(), FileCryptoError> {
    let mut output = open_new_output(output_path)?;

    let result =
        (|| -> Result<(), std::io::Error> {
            output.write_all(header)?;

            output.write_all(
                ml_kem_ciphertext,
            )?;

            output.write_all(wrapped_dek)?;

            output.write_all(encrypted_file)?;

            output.sync_all()?;

            Ok(())
        })();

    if let Err(error) = result {
        drop(output);

        let _ = fs::remove_file(output_path);

        return Err(error.into());
    }

    Ok(())
}

fn write_decrypted_file(
    output_path: &Path,
    plaintext: &[u8],
) -> Result<(), FileCryptoError> {
    let mut output = open_new_output(output_path)?;

    let result =
        (|| -> Result<(), std::io::Error> {
            output.write_all(plaintext)?;
            output.sync_all()?;
            Ok(())
        })();

    if let Err(error) = result {
        drop(output);

        let _ = fs::remove_file(output_path);

        return Err(error.into());
    }

    Ok(())
}

fn write_decrypted_file_replacing(
    output_path: &Path,
    plaintext: &[u8],
) -> Result<(), FileCryptoError> {
    let (mut temporary_file, temporary_path) =
        create_temporary_output(output_path)?;

    let write_result =
        (|| -> Result<(), std::io::Error> {
            temporary_file.write_all(plaintext)?;
            temporary_file.sync_all()?;
            Ok(())
        })();

    if let Err(error) = write_result {
        drop(temporary_file);
        let _ = fs::remove_file(&temporary_path);
        return Err(error.into());
    }

    drop(temporary_file);

    /*
     * The temporary file is in the same directory, so rename
     * performs the final replacement only after the complete
     * plaintext has been written and flushed.
     */
    if let Err(error) =
        fs::rename(&temporary_path, output_path)
    {
        let _ = fs::remove_file(&temporary_path);
        return Err(error.into());
    }

    Ok(())
}

fn create_temporary_output(
    output_path: &Path,
) -> Result<(std::fs::File, PathBuf), FileCryptoError> {
    let parent = output_path
        .parent()
        .ok_or(FileCryptoError::MissingFileName)?;

    let file_name = output_path
        .file_name()
        .ok_or(FileCryptoError::MissingFileName)?
        .to_string_lossy();

    for _ in 0..32 {
        let mut random_suffix = [0u8; 8];
        getrandom::fill(&mut random_suffix)?;

        let suffix = random_suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let temporary_name =
            format!(".{file_name}.cseml-tmp-{suffix}");

        let temporary_path =
            parent.join(temporary_name);

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(file) => {
                return Ok((file, temporary_path));
            }

            Err(error)
            if error.kind()
                == std::io::ErrorKind::AlreadyExists =>
                {
                    continue;
                }

            Err(error) => return Err(error.into()),
        }
    }

    Err(FileCryptoError::TemporaryOutputUnavailable)
}

fn open_new_output(
    output_path: &Path,
) -> Result<std::fs::File, FileCryptoError> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
    {
        Ok(file) => Ok(file),

        Err(error)
        if error.kind()
            == std::io::ErrorKind::AlreadyExists =>
            {
                Err(
                    FileCryptoError::OutputAlreadyExists(
                        output_path.to_path_buf(),
                    ),
                )
            }

        Err(error) => Err(error.into()),
    }
}