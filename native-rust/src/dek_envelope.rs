use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Nonce, Payload},
};
use ml_kem::{
    DecapsulationKey1024, EncapsulationKey1024,
    kem::{Decapsulate, Encapsulate},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const AES_DEK_LENGTH: usize = 32;
pub const AES_GCM_NONCE_LENGTH: usize = 12;

const DEK_AAD: &[u8] = b"CSE-ML-KEM|ML-KEM-1024|AES-256-GCM|DEK|v1";

#[derive(Debug)]
pub struct DekEnvelope {
    pub ml_kem_ciphertext: Vec<u8>,
    pub nonce: [u8; AES_GCM_NONCE_LENGTH],
    pub wrapped_dek: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum DekEnvelopeError {
    #[error("secure random generation failed: {0}")]
    Random(#[from] getrandom::Error),

    #[error("ML-KEM ciphertext has an invalid length")]
    InvalidMlKemCiphertext,

    #[error("AES-GCM nonce has an invalid length")]
    InvalidNonce,

    #[error("could not initialize AES-256-GCM")]
    InvalidWrappingKey,

    #[error("AES-256-GCM failed to wrap the DEK")]
    EncryptionFailed,

    #[error("AES-256-GCM failed to authenticate or unwrap the DEK")]
    DecryptionFailed,

    #[error("unwrapped DEK has an invalid length: found {0} bytes, expected 32")]
    InvalidDekLength(usize),
}

/// Generates a fresh random AES-256 data-encryption key.
pub fn generate_dek() -> Result<Zeroizing<[u8; AES_DEK_LENGTH]>, getrandom::Error> {
    let mut dek = Zeroizing::new([0u8; AES_DEK_LENGTH]);

    getrandom::fill(&mut dek[..])?;

    Ok(dek)
}

/// Uses ML-KEM to establish a fresh shared secret, then uses
/// that shared secret as an ephemeral AES-256-GCM wrapping key.
pub fn wrap_dek(
    public_key: &EncapsulationKey1024,
    dek: &[u8; AES_DEK_LENGTH],
) -> Result<DekEnvelope, DekEnvelopeError> {
    let (ml_kem_ciphertext, mut shared_secret) = public_key.encapsulate();

    let cipher = Aes256Gcm::new_from_slice(shared_secret.as_slice())
        .map_err(|_| DekEnvelopeError::InvalidWrappingKey)?;

    // Aes256Gcm has copied the key into its own state.
    shared_secret.zeroize();

    let mut nonce_bytes = [0u8; AES_GCM_NONCE_LENGTH];
    getrandom::fill(&mut nonce_bytes)?;

    let nonce = Nonce::<Aes256Gcm>::try_from(&nonce_bytes[..])
        .map_err(|_| DekEnvelopeError::InvalidNonce)?;

    let wrapped_dek = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: dek,
                aad: DEK_AAD,
            },
        )
        .map_err(|_| DekEnvelopeError::EncryptionFailed)?;

    Ok(DekEnvelope {
        ml_kem_ciphertext: ml_kem_ciphertext.as_slice().to_vec(),

        nonce: nonce_bytes,

        // Contains the encrypted 32-byte DEK followed by the
        // 16-byte AES-GCM authentication tag.
        wrapped_dek,
    })
}

/// Uses the ML-KEM private key to recover the shared secret,
/// then uses AES-256-GCM to authenticate and recover the DEK.
pub fn unwrap_dek(
    private_key: &DecapsulationKey1024,
    envelope: &DekEnvelope,
) -> Result<Zeroizing<[u8; AES_DEK_LENGTH]>, DekEnvelopeError> {
    let mut shared_secret = private_key
        .decapsulate_slice(&envelope.ml_kem_ciphertext)
        .map_err(|_| DekEnvelopeError::InvalidMlKemCiphertext)?;

    let cipher = Aes256Gcm::new_from_slice(shared_secret.as_slice())
        .map_err(|_| DekEnvelopeError::InvalidWrappingKey)?;

    shared_secret.zeroize();

    let nonce = Nonce::<Aes256Gcm>::try_from(&envelope.nonce[..])
        .map_err(|_| DekEnvelopeError::InvalidNonce)?;

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &envelope.wrapped_dek,
                    aad: DEK_AAD,
                },
            )
            .map_err(|_| DekEnvelopeError::DecryptionFailed)?,
    );

    if plaintext.len() != AES_DEK_LENGTH {
        return Err(DekEnvelopeError::InvalidDekLength(plaintext.len()));
    }

    let mut recovered_dek = Zeroizing::new([0u8; AES_DEK_LENGTH]);

    recovered_dek.copy_from_slice(&plaintext[..]);

    Ok(recovered_dek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::{MlKem1024, kem::Kem};

    #[test]
    fn ml_kem_wraps_and_unwraps_aes_dek() {
        let (private_key, public_key) = MlKem1024::generate_keypair();

        let original_dek = generate_dek().expect("DEK generation should succeed");

        let envelope = wrap_dek(&public_key, &*original_dek).expect("DEK wrapping should succeed");

        assert!(!envelope.ml_kem_ciphertext.is_empty());

        // 32-byte ciphertext plus a 16-byte GCM tag.
        assert_eq!(envelope.wrapped_dek.len(), AES_DEK_LENGTH + 16,);

        let recovered_dek =
            unwrap_dek(&private_key, &envelope).expect("DEK unwrapping should succeed");

        assert_eq!(&recovered_dek[..], &original_dek[..],);
    }

    #[test]
    fn modified_wrapped_dek_is_rejected() {
        let (private_key, public_key) = MlKem1024::generate_keypair();

        let original_dek = generate_dek().expect("DEK generation should succeed");

        let mut envelope =
            wrap_dek(&public_key, &*original_dek).expect("DEK wrapping should succeed");

        envelope.wrapped_dek[0] ^= 0x01;

        let result = unwrap_dek(&private_key, &envelope);

        assert!(matches!(result, Err(DekEnvelopeError::DecryptionFailed)));
    }

    #[test]
    fn modified_nonce_is_rejected() {
        let (private_key, public_key) = MlKem1024::generate_keypair();

        let original_dek = generate_dek().expect("DEK generation should succeed");

        let mut envelope =
            wrap_dek(&public_key, &*original_dek).expect("DEK wrapping should succeed");

        envelope.nonce[0] ^= 0x01;

        let result = unwrap_dek(&private_key, &envelope);

        assert!(matches!(result, Err(DekEnvelopeError::DecryptionFailed)));
    }
}
