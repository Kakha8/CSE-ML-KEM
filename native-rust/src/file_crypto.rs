use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    mem::size_of,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{consts::U12, Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{dek_envelope, mlkem_keystore};

/*
 * Version 1 is retained for backward-compatible decryption.
 * New encryption always writes the chunked version 2 format.
 */
const V1_MAGIC: &[u8; 8] = b"CSEMLK01";
const V2_MAGIC: &[u8; 8] = b"CSEMLK02";

const AES_GCM_NONCE_LENGTH: usize = 12;
const AES_GCM_TAG_LENGTH: usize = 16;

/*
 * Existing version 1 header:
 *
 * 8 bytes   magic/version
 * 4 bytes   ML-KEM ciphertext length
 * 4 bytes   wrapped DEK length
 * 8 bytes   original plaintext length
 * 12 bytes  DEK-envelope nonce
 * 12 bytes  file-encryption nonce
 */
const V1_HEADER_LENGTH: usize =
    8 + size_of::<u32>() + size_of::<u32>() + size_of::<u64>()
        + AES_GCM_NONCE_LENGTH + AES_GCM_NONCE_LENGTH;

/*
 * Chunked version 2 header:
 *
 * 8 bytes   magic/version: CSEMLK02
 * 4 bytes   plaintext chunk size
 * 8 bytes   original plaintext length
 * 4 bytes   total chunk count
 * 4 bytes   ML-KEM ciphertext length
 * 4 bytes   wrapped DEK length
 * 12 bytes  DEK-envelope AES-GCM nonce
 * 8 bytes   random file-nonce prefix
 *
 * Every chunk uses:
 *
 * nonce = 8-byte random prefix || 4-byte chunk index
 *
 * Each encrypted chunk is:
 *
 * plaintext chunk || 16-byte AES-GCM authentication tag
 */
const V2_HEADER_LENGTH: usize =
    8 + size_of::<u32>() + size_of::<u64>() + size_of::<u32>()
        + size_of::<u32>() + size_of::<u32>()
        + AES_GCM_NONCE_LENGTH + 8;

const V2_CHUNK_SIZE: usize = 1024 * 1024;
const V2_NONCE_PREFIX_LENGTH: usize = 8;
const V2_CHUNK_AAD_DOMAIN: &[u8] = b"CSEMLK02|FILE-CHUNK|";

const MAX_ENVELOPE_COMPONENT_LENGTH: usize = 64 * 1024;

/*
 * Version 1 performs one-shot AES-GCM and therefore retains the
 * original prototype limit. Version 2 has no 256 MiB limit.
 */
const MAX_V1_PLAINTEXT_SIZE: u64 = 256 * 1024 * 1024;
const MAX_V1_CONTAINER_SIZE: u64 =
    MAX_V1_PLAINTEXT_SIZE + 4 * 1024 * 1024;

const IO_BUFFER_SIZE: usize = 1024 * 1024;
const PROGRESS_BAR_WIDTH: usize = 40;

struct TerminalProgress {
    operation: &'static str,
    last_percent: Option<u8>,
    finished: bool,
}

impl TerminalProgress {
    fn new(operation: &'static str) -> Self {
        Self {
            operation,
            last_percent: None,
            finished: false,
        }
    }

    fn update(&mut self, percent: u8, label: &str) {
        let percent = percent.min(100);

        if self.last_percent == Some(percent) {
            return;
        }

        self.last_percent = Some(percent);

        let filled =
            usize::from(percent) * PROGRESS_BAR_WIDTH / 100;

        let empty = PROGRESS_BAR_WIDTH - filled;

        print!(
            "\r{} [{}{}] {:>3}%  {:<32}",
            self.operation,
            "#".repeat(filled),
            "-".repeat(empty),
            percent,
            label,
        );

        let _ = std::io::stdout().flush();
    }

    fn finish(&mut self) {
        self.update(100, "Complete");
        println!();
        self.finished = true;
    }
}

impl Drop for TerminalProgress {
    fn drop(&mut self) {
        if !self.finished && self.last_percent.is_some() {
            println!();
        }
    }
}

#[derive(Debug, Error)]
pub enum FileCryptoError {
    #[error("input path is not a regular file: {0}")]
    NotARegularFile(PathBuf),

    #[error(
        "version 1 file is too large for one-shot decryption: {0} bytes"
    )]
    V1InputTooLarge(u64),

    #[error(
        "version 1 container is too large for one-shot decryption: {0} bytes"
    )]
    V1ContainerTooLarge(u64),

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

    #[error("file, chunk, or envelope length is too large")]
    LengthTooLarge,

    #[error("the input file changed while it was being encrypted")]
    InputChangedDuringEncryption,

    #[error("encrypted container magic or version is invalid")]
    InvalidMagic,

    #[error("encrypted container is invalid: {0}")]
    InvalidContainer(&'static str),

    #[error("could not initialize AES-256-GCM")]
    InvalidAesKey,

    #[error("AES-256-GCM chunk encryption failed")]
    EncryptionFailed,

    #[error(
        "AES-256-GCM authentication failed for encrypted chunk {0}"
    )]
    ChunkAuthenticationFailed(u32),

    #[error("AES-256-GCM version 1 file decryption failed")]
    V1DecryptionFailed,

    #[error(
        "decrypted file length mismatch: expected {expected} bytes, found {actual}"
    )]
    DecryptedLengthMismatch {
        expected: u64,
        actual: u64,
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

struct ParsedV1Container<'a> {
    header: &'a [u8],
    ml_kem_ciphertext: &'a [u8],
    wrapped_dek: &'a [u8],
    encrypted_file: &'a [u8],
    envelope_nonce: [u8; AES_GCM_NONCE_LENGTH],
    file_nonce: [u8; AES_GCM_NONCE_LENGTH],
    original_file_length: u64,
}

#[derive(Debug)]
struct V2Header {
    raw: [u8; V2_HEADER_LENGTH],
    chunk_size: u32,
    original_file_length: u64,
    total_chunks: u32,
    ml_kem_ciphertext_length: u32,
    wrapped_dek_length: u32,
    envelope_nonce: [u8; AES_GCM_NONCE_LENGTH],
    nonce_prefix: [u8; V2_NONCE_PREFIX_LENGTH],
}

/// Encrypts a file into a new chunked `CSEMLK02` container.
///
/// The original file remains unchanged.
///
/// Example:
///
/// document.pdf -> document.pdf.cseml
pub fn encrypt_file(
    input_path: &Path,
) -> Result<PathBuf, FileCryptoError> {
    encrypt_file_v2(input_path)
}

/// Decrypts a `.cseml` container to its original filename.
///
/// Both `CSEMLK01` and `CSEMLK02` are supported.
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
/// the existing file. Overwrite decryption is written to a
/// temporary file before the existing output is replaced.
pub fn decrypt_file_to(
    input_path: &Path,
    output_path: &Path,
    overwrite: bool,
) -> Result<PathBuf, FileCryptoError> {
    let input_path = fs::canonicalize(input_path)?;
    let input_metadata = fs::metadata(&input_path)?;

    if !input_metadata.is_file() {
        return Err(
            FileCryptoError::NotARegularFile(input_path),
        );
    }

    let output_path =
        normalize_output_path(output_path)?;

    validate_output_path(
        &input_path,
        &output_path,
        overwrite,
    )?;

    let magic = read_magic(&input_path)?;

    if magic == *V2_MAGIC {
        decrypt_file_v2_to(
            &input_path,
            input_metadata.len(),
            &output_path,
            overwrite,
        )
    } else if magic == *V1_MAGIC {
        decrypt_file_v1_to(
            &input_path,
            input_metadata.len(),
            &output_path,
            overwrite,
        )
    } else {
        Err(FileCryptoError::InvalidMagic)
    }
}

fn encrypt_file_v2(
    input_path: &Path,
) -> Result<PathBuf, FileCryptoError> {
    let mut progress =
        TerminalProgress::new("Encrypting");

    progress.update(0, "Validating input");

    let input_path = fs::canonicalize(input_path)?;
    let metadata = fs::metadata(&input_path)?;

    if !metadata.is_file() {
        return Err(
            FileCryptoError::NotARegularFile(input_path),
        );
    }

    let original_file_length = metadata.len();

    let output_path =
        encrypted_output_path(&input_path)?;

    if output_path.exists() {
        return Err(
            FileCryptoError::OutputAlreadyExists(
                output_path,
            ),
        );
    }

    let total_chunks = expected_chunk_count(
        original_file_length,
        V2_CHUNK_SIZE,
    )?;

    progress.update(2, "Loading ML-KEM key");

    let ml_kem_private_key =
        mlkem_keystore::
        load_stored_ml_kem1024_decapsulation_key()?;

    progress.update(4, "Generating AES-256 key");

    let dek = dek_envelope::generate_dek()?;

    progress.update(6, "Wrapping AES-256 key");

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

    let mut nonce_prefix =
        [0u8; V2_NONCE_PREFIX_LENGTH];

    getrandom::fill(&mut nonce_prefix)?;

    let header = build_v2_header(
        original_file_length,
        total_chunks,
        ml_kem_ciphertext_length,
        wrapped_dek_length,
        wrapped_dek_envelope.nonce,
        nonce_prefix,
    )?;

    progress.update(8, "Writing container header");

    let mut input = File::open(&input_path)?;
    let mut output = open_new_output(&output_path)?;

    let result =
        (|| -> Result<(), FileCryptoError> {
            output.write_all(&header.raw)?;

            output.write_all(
                &wrapped_dek_envelope
                    .ml_kem_ciphertext,
            )?;

            output.write_all(
                &wrapped_dek_envelope.wrapped_dek,
            )?;

            let mut plaintext_buffer =
                Zeroizing::new(
                    vec![0u8; V2_CHUNK_SIZE],
                );

            let mut processed_plaintext = 0u64;

            for chunk_index in 0..total_chunks {
                let plaintext_length =
                    chunk_plaintext_length(
                        original_file_length,
                        V2_CHUNK_SIZE,
                        chunk_index,
                        total_chunks,
                    )?;

                input.read_exact(
                    &mut plaintext_buffer[
                        ..plaintext_length
                        ],
                )?;

                let nonce = v2_chunk_nonce(
                    header.nonce_prefix,
                    chunk_index,
                );

                let aad = v2_chunk_aad(
                    &header.raw,
                    chunk_index,
                    plaintext_length,
                )?;

                let encrypted_chunk = cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: &plaintext_buffer[
                                ..plaintext_length
                                ],
                            aad: &aad,
                        },
                    )
                    .map_err(|_| {
                        FileCryptoError::EncryptionFailed
                    })?;

                output.write_all(&encrypted_chunk)?;

                plaintext_buffer[
                    ..plaintext_length
                    ]
                    .zeroize();

                processed_plaintext =
                    processed_plaintext
                        .saturating_add(
                            plaintext_length as u64,
                        );

                let percent =
                    chunk_progress_percent(
                        processed_plaintext,
                        original_file_length,
                        chunk_index + 1,
                        total_chunks,
                    );

                let label = format!(
                    "Chunk {}/{}",
                    chunk_index + 1,
                    total_chunks,
                );

                progress.update(percent, &label);
            }

            /*
             * Detect a file which grew after its initial metadata
             * was read.
             */
            let mut extra_byte = [0u8; 1];

            if input.read(&mut extra_byte)? != 0 {
                return Err(
                    FileCryptoError::
                    InputChangedDuringEncryption,
                );
            }

            progress.update(99, "Flushing output");
            output.sync_all()?;

            Ok(())
        })();

    if let Err(error) = result {
        drop(output);
        let _ = fs::remove_file(&output_path);
        return Err(error);
    }

    progress.finish();

    Ok(output_path)
}

fn decrypt_file_v2_to(
    input_path: &Path,
    container_length: u64,
    output_path: &Path,
    overwrite: bool,
) -> Result<PathBuf, FileCryptoError> {
    let mut progress =
        TerminalProgress::new("Decrypting");

    progress.update(0, "Reading v2 header");

    let mut input = File::open(input_path)?;
    let header = read_v2_header(&mut input)?;

    validate_v2_container_length(
        container_length,
        &header,
    )?;

    progress.update(3, "Reading key envelope");

    let ml_kem_ciphertext_length =
        usize::try_from(
            header.ml_kem_ciphertext_length,
        )
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    let wrapped_dek_length =
        usize::try_from(
            header.wrapped_dek_length,
        )
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    let mut ml_kem_ciphertext =
        vec![0u8; ml_kem_ciphertext_length];

    let mut wrapped_dek =
        vec![0u8; wrapped_dek_length];

    input.read_exact(&mut ml_kem_ciphertext)?;
    input.read_exact(&mut wrapped_dek)?;

    progress.update(5, "Loading ML-KEM key");

    let ml_kem_private_key =
        mlkem_keystore::
        load_stored_ml_kem1024_decapsulation_key()?;

    let envelope = dek_envelope::DekEnvelope {
        ml_kem_ciphertext,
        nonce: header.envelope_nonce,
        wrapped_dek,
    };

    progress.update(8, "Unwrapping AES-256 key");

    let dek = dek_envelope::unwrap_dek(
        &ml_kem_private_key,
        &envelope,
    )?;

    let cipher =
        Aes256Gcm::new_from_slice(&dek[..])
            .map_err(|_| {
                FileCryptoError::InvalidAesKey
            })?;

    let (
        mut output,
        temporary_output_path,
        actual_write_path,
    ) = create_decryption_output(
        output_path,
        overwrite,
    )?;

    let result =
        (|| -> Result<(), FileCryptoError> {
            let chunk_size =
                usize::try_from(header.chunk_size)
                    .map_err(|_| {
                        FileCryptoError::LengthTooLarge
                    })?;

            let mut processed_plaintext = 0u64;

            for chunk_index in 0..header.total_chunks {
                let plaintext_length =
                    chunk_plaintext_length(
                        header.original_file_length,
                        chunk_size,
                        chunk_index,
                        header.total_chunks,
                    )?;

                let encrypted_length =
                    plaintext_length
                        .checked_add(AES_GCM_TAG_LENGTH)
                        .ok_or(
                            FileCryptoError::
                            LengthTooLarge,
                        )?;

                let mut encrypted_chunk =
                    vec![0u8; encrypted_length];

                input.read_exact(&mut encrypted_chunk)?;

                let nonce = v2_chunk_nonce(
                    header.nonce_prefix,
                    chunk_index,
                );

                let aad = v2_chunk_aad(
                    &header.raw,
                    chunk_index,
                    plaintext_length,
                )?;

                let plaintext = Zeroizing::new(
                    cipher
                        .decrypt(
                            &nonce,
                            Payload {
                                msg: &encrypted_chunk,
                                aad: &aad,
                            },
                        )
                        .map_err(|_| {
                            FileCryptoError::
                            ChunkAuthenticationFailed(
                                chunk_index,
                            )
                        })?,
                );

                if plaintext.len()
                    != plaintext_length
                {
                    return Err(
                        FileCryptoError::
                        InvalidContainer(
                            "decrypted chunk length is invalid",
                        ),
                    );
                }

                output.write_all(
                    plaintext.as_slice(),
                )?;

                processed_plaintext =
                    processed_plaintext
                        .saturating_add(
                            plaintext_length as u64,
                        );

                let percent =
                    chunk_progress_percent(
                        processed_plaintext,
                        header.original_file_length,
                        chunk_index + 1,
                        header.total_chunks,
                    );

                let label = format!(
                    "Chunk {}/{}",
                    chunk_index + 1,
                    header.total_chunks,
                );

                progress.update(percent, &label);
            }

            let mut extra_byte = [0u8; 1];

            if input.read(&mut extra_byte)? != 0 {
                return Err(
                    FileCryptoError::InvalidContainer(
                        "container has trailing data",
                    ),
                );
            }

            if processed_plaintext
                != header.original_file_length
            {
                return Err(
                    FileCryptoError::
                    DecryptedLengthMismatch {
                        expected:
                        header
                            .original_file_length,

                        actual:
                        processed_plaintext,
                    },
                );
            }

            progress.update(99, "Flushing output");
            output.sync_all()?;

            Ok(())
        })();

    drop(output);

    if let Err(error) = result {
        let _ = fs::remove_file(&actual_write_path);
        return Err(error);
    }

    if let Some(temporary_path) =
        temporary_output_path
    {
        progress.update(99, "Replacing output");

        if let Err(error) =
            fs::rename(&temporary_path, output_path)
        {
            let _ = fs::remove_file(&temporary_path);
            return Err(error.into());
        }
    }

    progress.finish();

    Ok(output_path.to_path_buf())
}

fn decrypt_file_v1_to(
    input_path: &Path,
    container_length: u64,
    output_path: &Path,
    overwrite: bool,
) -> Result<PathBuf, FileCryptoError> {
    if container_length > MAX_V1_CONTAINER_SIZE {
        return Err(
            FileCryptoError::V1ContainerTooLarge(
                container_length,
            ),
        );
    }

    let mut progress =
        TerminalProgress::new("Decrypting v1");

    progress.update(0, "Reading old container");

    let container = read_v1_container_with_progress(
        input_path,
        container_length,
        &mut progress,
    )?;

    progress.update(32, "Parsing old container");

    let parsed = parse_v1_container(&container)?;

    progress.update(36, "Loading ML-KEM key");

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

    progress.update(40, "Unwrapping AES-256 key");

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

    progress.update(45, "One-shot AES-GCM");

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
                FileCryptoError::V1DecryptionFailed
            })?,
    );

    if plaintext.len() as u64
        != parsed.original_file_length
    {
        return Err(
            FileCryptoError::
            DecryptedLengthMismatch {
                expected:
                parsed.original_file_length,

                actual:
                plaintext.len() as u64,
            },
        );
    }

    progress.update(80, "Writing plaintext");

    write_complete_plaintext(
        output_path,
        plaintext.as_slice(),
        overwrite,
        &mut progress,
    )?;

    progress.finish();

    Ok(output_path.to_path_buf())
}

fn build_v2_header(
    original_file_length: u64,
    total_chunks: u32,
    ml_kem_ciphertext_length: u32,
    wrapped_dek_length: u32,
    envelope_nonce: [u8; AES_GCM_NONCE_LENGTH],
    nonce_prefix: [u8; V2_NONCE_PREFIX_LENGTH],
) -> Result<V2Header, FileCryptoError> {
    if ml_kem_ciphertext_length == 0
        || usize::try_from(
        ml_kem_ciphertext_length,
    )
        .map_err(|_| {
            FileCryptoError::LengthTooLarge
        })?
        > MAX_ENVELOPE_COMPONENT_LENGTH
    {
        return Err(
            FileCryptoError::InvalidContainer(
                "ML-KEM ciphertext length is invalid",
            ),
        );
    }

    if wrapped_dek_length < AES_GCM_TAG_LENGTH as u32
        || usize::try_from(wrapped_dek_length)
        .map_err(|_| {
            FileCryptoError::LengthTooLarge
        })?
        > MAX_ENVELOPE_COMPONENT_LENGTH
    {
        return Err(
            FileCryptoError::InvalidContainer(
                "wrapped DEK length is invalid",
            ),
        );
    }

    let expected_chunks =
        expected_chunk_count(
            original_file_length,
            V2_CHUNK_SIZE,
        )?;

    if total_chunks != expected_chunks {
        return Err(
            FileCryptoError::InvalidContainer(
                "chunk count does not match file length",
            ),
        );
    }

    let chunk_size =
        u32::try_from(V2_CHUNK_SIZE)
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    let mut raw = [0u8; V2_HEADER_LENGTH];
    let mut offset = 0usize;

    put_bytes(&mut raw, &mut offset, V2_MAGIC)?;
    put_bytes(
        &mut raw,
        &mut offset,
        &chunk_size.to_le_bytes(),
    )?;
    put_bytes(
        &mut raw,
        &mut offset,
        &original_file_length.to_le_bytes(),
    )?;
    put_bytes(
        &mut raw,
        &mut offset,
        &total_chunks.to_le_bytes(),
    )?;
    put_bytes(
        &mut raw,
        &mut offset,
        &ml_kem_ciphertext_length.to_le_bytes(),
    )?;
    put_bytes(
        &mut raw,
        &mut offset,
        &wrapped_dek_length.to_le_bytes(),
    )?;
    put_bytes(
        &mut raw,
        &mut offset,
        &envelope_nonce,
    )?;
    put_bytes(
        &mut raw,
        &mut offset,
        &nonce_prefix,
    )?;

    debug_assert_eq!(offset, V2_HEADER_LENGTH);

    Ok(V2Header {
        raw,
        chunk_size,
        original_file_length,
        total_chunks,
        ml_kem_ciphertext_length,
        wrapped_dek_length,
        envelope_nonce,
        nonce_prefix,
    })
}

fn read_v2_header(
    input: &mut File,
) -> Result<V2Header, FileCryptoError> {
    let mut raw = [0u8; V2_HEADER_LENGTH];
    input.read_exact(&mut raw)?;

    if &raw[0..8] != V2_MAGIC {
        return Err(FileCryptoError::InvalidMagic);
    }

    let chunk_size =
        read_u32(&raw, 8)?;

    let original_file_length =
        read_u64(&raw, 12)?;

    let total_chunks =
        read_u32(&raw, 20)?;

    let ml_kem_ciphertext_length =
        read_u32(&raw, 24)?;

    let wrapped_dek_length =
        read_u32(&raw, 28)?;

    let envelope_nonce:
        [u8; AES_GCM_NONCE_LENGTH] =
        raw[32..44]
            .try_into()
            .map_err(|_| {
                FileCryptoError::InvalidContainer(
                    "could not read envelope nonce",
                )
            })?;

    let nonce_prefix:
        [u8; V2_NONCE_PREFIX_LENGTH] =
        raw[44..52]
            .try_into()
            .map_err(|_| {
                FileCryptoError::InvalidContainer(
                    "could not read nonce prefix",
                )
            })?;

    if usize::try_from(chunk_size)
        .map_err(|_| {
            FileCryptoError::LengthTooLarge
        })?
        != V2_CHUNK_SIZE
    {
        return Err(
            FileCryptoError::InvalidContainer(
                "unsupported version 2 chunk size",
            ),
        );
    }

    if ml_kem_ciphertext_length == 0
        || usize::try_from(
        ml_kem_ciphertext_length,
    )
        .map_err(|_| {
            FileCryptoError::LengthTooLarge
        })?
        > MAX_ENVELOPE_COMPONENT_LENGTH
    {
        return Err(
            FileCryptoError::InvalidContainer(
                "ML-KEM ciphertext length is invalid",
            ),
        );
    }

    if wrapped_dek_length < AES_GCM_TAG_LENGTH as u32
        || usize::try_from(wrapped_dek_length)
        .map_err(|_| {
            FileCryptoError::LengthTooLarge
        })?
        > MAX_ENVELOPE_COMPONENT_LENGTH
    {
        return Err(
            FileCryptoError::InvalidContainer(
                "wrapped DEK length is invalid",
            ),
        );
    }

    let expected_chunks =
        expected_chunk_count(
            original_file_length,
            V2_CHUNK_SIZE,
        )?;

    if total_chunks != expected_chunks {
        return Err(
            FileCryptoError::InvalidContainer(
                "chunk count does not match file length",
            ),
        );
    }

    Ok(V2Header {
        raw,
        chunk_size,
        original_file_length,
        total_chunks,
        ml_kem_ciphertext_length,
        wrapped_dek_length,
        envelope_nonce,
        nonce_prefix,
    })
}

fn validate_v2_container_length(
    actual_length: u64,
    header: &V2Header,
) -> Result<(), FileCryptoError> {
    let chunk_tags_length =
        u64::from(header.total_chunks)
            .checked_mul(AES_GCM_TAG_LENGTH as u64)
            .ok_or(FileCryptoError::LengthTooLarge)?;

    let expected_length =
        (V2_HEADER_LENGTH as u64)
            .checked_add(
                u64::from(
                    header.ml_kem_ciphertext_length,
                ),
            )
            .and_then(|value| {
                value.checked_add(
                    u64::from(
                        header.wrapped_dek_length,
                    ),
                )
            })
            .and_then(|value| {
                value.checked_add(
                    header.original_file_length,
                )
            })
            .and_then(|value| {
                value.checked_add(chunk_tags_length)
            })
            .ok_or(FileCryptoError::LengthTooLarge)?;

    if actual_length != expected_length {
        return Err(
            FileCryptoError::InvalidContainer(
                "container length does not match its header",
            ),
        );
    }

    Ok(())
}

fn parse_v1_container(
    container: &[u8],
) -> Result<ParsedV1Container<'_>, FileCryptoError> {
    if container.len()
        < V1_HEADER_LENGTH + AES_GCM_TAG_LENGTH
    {
        return Err(
            FileCryptoError::InvalidContainer(
                "version 1 container is shorter than the minimum size",
            ),
        );
    }

    if &container[0..8] != V1_MAGIC {
        return Err(FileCryptoError::InvalidMagic);
    }

    let ml_kem_ciphertext_length =
        read_u32(container, 8)? as usize;

    let wrapped_dek_length =
        read_u32(container, 12)? as usize;

    let original_file_length =
        read_u64(container, 16)?;

    if original_file_length
        > MAX_V1_PLAINTEXT_SIZE
    {
        return Err(
            FileCryptoError::V1InputTooLarge(
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
                "version 1 ML-KEM ciphertext length is invalid",
            ),
        );
    }

    if wrapped_dek_length < AES_GCM_TAG_LENGTH
        || wrapped_dek_length
        > MAX_ENVELOPE_COMPONENT_LENGTH
    {
        return Err(
            FileCryptoError::InvalidContainer(
                "version 1 wrapped DEK length is invalid",
            ),
        );
    }

    let original_length_usize =
        usize::try_from(original_file_length)
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    let encrypted_file_length =
        original_length_usize
            .checked_add(AES_GCM_TAG_LENGTH)
            .ok_or(
                FileCryptoError::LengthTooLarge,
            )?;

    let expected_total_length =
        V1_HEADER_LENGTH
            .checked_add(
                ml_kem_ciphertext_length,
            )
            .and_then(|value| {
                value.checked_add(
                    wrapped_dek_length,
                )
            })
            .and_then(|value| {
                value.checked_add(
                    encrypted_file_length,
                )
            })
            .ok_or(FileCryptoError::LengthTooLarge)?;

    if container.len() != expected_total_length {
        return Err(
            FileCryptoError::InvalidContainer(
                "version 1 container length does not match its header",
            ),
        );
    }

    let envelope_nonce:
        [u8; AES_GCM_NONCE_LENGTH] =
        container[24..36]
            .try_into()
            .map_err(|_| {
                FileCryptoError::InvalidContainer(
                    "could not read version 1 envelope nonce",
                )
            })?;

    let file_nonce:
        [u8; AES_GCM_NONCE_LENGTH] =
        container[36..48]
            .try_into()
            .map_err(|_| {
                FileCryptoError::InvalidContainer(
                    "could not read version 1 file nonce",
                )
            })?;

    let ml_kem_start = V1_HEADER_LENGTH;
    let ml_kem_end =
        ml_kem_start + ml_kem_ciphertext_length;
    let wrapped_dek_end =
        ml_kem_end + wrapped_dek_length;

    Ok(ParsedV1Container {
        header:
        &container[..V1_HEADER_LENGTH],

        ml_kem_ciphertext:
        &container[ml_kem_start..ml_kem_end],

        wrapped_dek:
        &container[
            ml_kem_end..wrapped_dek_end
            ],

        encrypted_file:
        &container[wrapped_dek_end..],

        envelope_nonce,
        file_nonce,
        original_file_length,
    })
}

fn expected_chunk_count(
    original_file_length: u64,
    chunk_size: usize,
) -> Result<u32, FileCryptoError> {
    let chunk_size =
        u64::try_from(chunk_size)
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    if chunk_size == 0 {
        return Err(
            FileCryptoError::InvalidContainer(
                "chunk size cannot be zero",
            ),
        );
    }

    let count = if original_file_length == 0 {
        1
    } else {
        original_file_length
            .checked_add(chunk_size - 1)
            .ok_or(
                FileCryptoError::LengthTooLarge,
            )?
            / chunk_size
    };

    u32::try_from(count)
        .map_err(|_| {
            FileCryptoError::LengthTooLarge
        })
}

fn chunk_plaintext_length(
    original_file_length: u64,
    chunk_size: usize,
    chunk_index: u32,
    total_chunks: u32,
) -> Result<usize, FileCryptoError> {
    if chunk_index >= total_chunks {
        return Err(
            FileCryptoError::InvalidContainer(
                "chunk index is out of range",
            ),
        );
    }

    if original_file_length == 0 {
        if total_chunks != 1 || chunk_index != 0 {
            return Err(
                FileCryptoError::InvalidContainer(
                    "empty file chunk layout is invalid",
                ),
            );
        }

        return Ok(0);
    }

    let chunk_size_u64 =
        u64::try_from(chunk_size)
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    let start =
        u64::from(chunk_index)
            .checked_mul(chunk_size_u64)
            .ok_or(FileCryptoError::LengthTooLarge)?;

    let remaining =
        original_file_length
            .checked_sub(start)
            .ok_or(
                FileCryptoError::InvalidContainer(
                    "chunk starts beyond the file length",
                ),
            )?;

    let length =
        remaining.min(chunk_size_u64);

    usize::try_from(length)
        .map_err(|_| {
            FileCryptoError::LengthTooLarge
        })
}

fn v2_chunk_nonce(
    nonce_prefix: [u8; V2_NONCE_PREFIX_LENGTH],
    chunk_index: u32,
) -> Nonce<U12> {
    let mut nonce_bytes =
        [0u8; AES_GCM_NONCE_LENGTH];

    nonce_bytes[..V2_NONCE_PREFIX_LENGTH]
        .copy_from_slice(&nonce_prefix);

    nonce_bytes[V2_NONCE_PREFIX_LENGTH..]
        .copy_from_slice(
            &chunk_index.to_be_bytes(),
        );

    nonce_bytes.into()
}

fn v2_chunk_aad(
    header: &[u8; V2_HEADER_LENGTH],
    chunk_index: u32,
    plaintext_length: usize,
) -> Result<Vec<u8>, FileCryptoError> {
    let plaintext_length =
        u32::try_from(plaintext_length)
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    let mut aad = Vec::with_capacity(
        V2_CHUNK_AAD_DOMAIN.len()
            + V2_HEADER_LENGTH
            + size_of::<u32>()
            + size_of::<u32>(),
    );

    aad.extend_from_slice(V2_CHUNK_AAD_DOMAIN);
    aad.extend_from_slice(header);
    aad.extend_from_slice(
        &chunk_index.to_le_bytes(),
    );
    aad.extend_from_slice(
        &plaintext_length.to_le_bytes(),
    );

    Ok(aad)
}

fn chunk_progress_percent(
    processed_plaintext: u64,
    total_plaintext: u64,
    completed_chunks: u32,
    total_chunks: u32,
) -> u8 {
    let work_percent = (if total_plaintext == 0 {
        u64::from(completed_chunks)
            .saturating_mul(89)
            .checked_div(u64::from(total_chunks))
            .unwrap_or(89)
    } else {
        processed_plaintext
            .saturating_mul(89)
            .checked_div(total_plaintext)
            .unwrap_or(89)
    })
        .min(89);

    10 + work_percent as u8
}

fn read_magic(
    input_path: &Path,
) -> Result<[u8; 8], FileCryptoError> {
    let mut input = File::open(input_path)?;
    let mut magic = [0u8; 8];
    input.read_exact(&mut magic)?;
    Ok(magic)
}

fn read_v1_container_with_progress(
    input_path: &Path,
    total_bytes: u64,
    progress: &mut TerminalProgress,
) -> Result<Vec<u8>, FileCryptoError> {
    let capacity =
        usize::try_from(total_bytes)
            .map_err(|_| {
                FileCryptoError::LengthTooLarge
            })?;

    let mut input = File::open(input_path)?;
    let mut container =
        Vec::with_capacity(capacity);

    let mut buffer =
        vec![0u8; IO_BUFFER_SIZE];

    let mut processed = 0u64;

    loop {
        let count = input.read(&mut buffer)?;

        if count == 0 {
            break;
        }

        container.extend_from_slice(
            &buffer[..count],
        );

        processed =
            processed.saturating_add(count as u64);

        let percent = if total_bytes == 0 {
            30
        } else {
            processed
                .saturating_mul(30)
                .checked_div(total_bytes)
                .unwrap_or(30)
                .min(30) as u8
        };

        progress.update(
            percent,
            "Reading old container",
        );
    }

    progress.update(30, "Old container loaded");

    Ok(container)
}

fn write_complete_plaintext(
    output_path: &Path,
    plaintext: &[u8],
    overwrite: bool,
    progress: &mut TerminalProgress,
) -> Result<(), FileCryptoError> {
    let (
        mut output,
        temporary_output_path,
        actual_write_path,
    ) = create_decryption_output(
        output_path,
        overwrite,
    )?;

    let result =
        (|| -> Result<(), FileCryptoError> {
            let total = plaintext.len() as u64;
            let mut processed = 0u64;

            for chunk in plaintext.chunks(
                IO_BUFFER_SIZE,
            ) {
                output.write_all(chunk)?;

                processed =
                    processed.saturating_add(
                        chunk.len() as u64,
                    );

                let write_percent =
                    if total == 0 {
                        19
                    } else {
                        processed
                            .saturating_mul(19)
                            .checked_div(total)
                            .unwrap_or(19)
                            .min(19) as u8
                    };

                progress.update(
                    80 + write_percent,
                    "Writing plaintext",
                );
            }

            progress.update(99, "Flushing output");
            output.sync_all()?;

            Ok(())
        })();

    drop(output);

    if let Err(error) = result {
        let _ = fs::remove_file(&actual_write_path);
        return Err(error);
    }

    if let Some(temporary_path) =
        temporary_output_path
    {
        progress.update(99, "Replacing output");

        if let Err(error) =
            fs::rename(&temporary_path, output_path)
        {
            let _ = fs::remove_file(&temporary_path);
            return Err(error.into());
        }
    }

    Ok(())
}

fn create_decryption_output(
    output_path: &Path,
    overwrite: bool,
) -> Result<
    (File, Option<PathBuf>, PathBuf),
    FileCryptoError,
> {
    if overwrite {
        let (file, temporary_path) =
            create_temporary_output(output_path)?;

        Ok((
            file,
            Some(temporary_path.clone()),
            temporary_path,
        ))
    } else {
        let file = open_new_output(output_path)?;

        Ok((
            file,
            None,
            output_path.to_path_buf(),
        ))
    }
}

fn validate_output_path(
    input_path: &Path,
    output_path: &Path,
    overwrite: bool,
) -> Result<(), FileCryptoError> {
    if output_path == input_path {
        return Err(
            FileCryptoError::OutputMatchesInput,
        );
    }

    if output_path.exists() {
        let metadata = fs::metadata(output_path)?;

        if metadata.is_dir() {
            return Err(
                FileCryptoError::OutputIsDirectory(
                    output_path.to_path_buf(),
                ),
            );
        }

        if !overwrite {
            return Err(
                FileCryptoError::OutputAlreadyExists(
                    output_path.to_path_buf(),
                ),
            );
        }
    }

    Ok(())
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

    Ok(
        input_path.with_file_name(
            original_file_name,
        ),
    )
}

fn create_temporary_output(
    output_path: &Path,
) -> Result<(File, PathBuf), FileCryptoError> {
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
            .map(|byte| {
                format!("{byte:02x}")
            })
            .collect::<String>();

        let temporary_name = format!(
            ".{file_name}.cseml-tmp-{suffix}"
        );

        let temporary_path =
            parent.join(temporary_name);

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(file) => {
                return Ok((
                    file,
                    temporary_path,
                ));
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

    Err(
        FileCryptoError::
        TemporaryOutputUnavailable,
    )
}

fn open_new_output(
    output_path: &Path,
) -> Result<File, FileCryptoError> {
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

fn read_u32(
    bytes: &[u8],
    offset: usize,
) -> Result<u32, FileCryptoError> {
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or(FileCryptoError::LengthTooLarge)?;

    let value = bytes
        .get(offset..end)
        .ok_or(
            FileCryptoError::InvalidContainer(
                "could not read a 32-bit field",
            ),
        )?;

    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| {
            FileCryptoError::InvalidContainer(
                "could not decode a 32-bit field",
            )
        })?,
    ))
}

fn read_u64(
    bytes: &[u8],
    offset: usize,
) -> Result<u64, FileCryptoError> {
    let end = offset
        .checked_add(size_of::<u64>())
        .ok_or(FileCryptoError::LengthTooLarge)?;

    let value = bytes
        .get(offset..end)
        .ok_or(
            FileCryptoError::InvalidContainer(
                "could not read a 64-bit field",
            ),
        )?;

    Ok(u64::from_le_bytes(
        value.try_into().map_err(|_| {
            FileCryptoError::InvalidContainer(
                "could not decode a 64-bit field",
            )
        })?,
    ))
}

fn put_bytes(
    destination: &mut [u8],
    offset: &mut usize,
    source: &[u8],
) -> Result<(), FileCryptoError> {
    let end = offset
        .checked_add(source.len())
        .ok_or(FileCryptoError::LengthTooLarge)?;

    let target = destination
        .get_mut(*offset..end)
        .ok_or(
            FileCryptoError::InvalidContainer(
                "header construction overflowed",
            ),
        )?;

    target.copy_from_slice(source);
    *offset = end;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_count_handles_empty_and_boundaries() {
        assert_eq!(
            expected_chunk_count(
                0,
                V2_CHUNK_SIZE,
            )
            .unwrap(),
            1,
        );

        assert_eq!(
            expected_chunk_count(
                V2_CHUNK_SIZE as u64,
                V2_CHUNK_SIZE,
            )
            .unwrap(),
            1,
        );

        assert_eq!(
            expected_chunk_count(
                V2_CHUNK_SIZE as u64 + 1,
                V2_CHUNK_SIZE,
            )
            .unwrap(),
            2,
        );
    }

    #[test]
    fn chunk_lengths_cover_the_original_file() {
        let original_length =
            V2_CHUNK_SIZE as u64 * 2 + 123;

        let total_chunks =
            expected_chunk_count(
                original_length,
                V2_CHUNK_SIZE,
            )
                .unwrap();

        let mut total = 0usize;

        for index in 0..total_chunks {
            total += chunk_plaintext_length(
                original_length,
                V2_CHUNK_SIZE,
                index,
                total_chunks,
            )
                .unwrap();
        }

        assert_eq!(
            total as u64,
            original_length,
        );
    }

    #[test]
    fn chunk_nonce_changes_with_index() {
        let prefix = [0xA5u8; 8];

        let nonce_zero =
            v2_chunk_nonce(prefix, 0);

        let nonce_one =
            v2_chunk_nonce(prefix, 1);

        assert_ne!(
            nonce_zero.as_slice(),
            nonce_one.as_slice(),
        );

        assert_eq!(
            &nonce_zero.as_slice()[..8],
            &prefix,
        );
    }

    #[test]
    fn v2_header_has_expected_layout() {
        let header = build_v2_header(
            123,
            1,
            1568,
            48,
            [1u8; 12],
            [2u8; 8],
        )
            .unwrap();

        assert_eq!(
            &header.raw[..8],
            V2_MAGIC,
        );

        assert_eq!(
            read_u32(&header.raw, 8).unwrap(),
            V2_CHUNK_SIZE as u32,
        );

        assert_eq!(
            read_u64(&header.raw, 12).unwrap(),
            123,
        );

        assert_eq!(
            read_u32(&header.raw, 20).unwrap(),
            1,
        );
    }
}