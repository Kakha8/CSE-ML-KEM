mod dek_envelope;
mod dpapi;
mod file_crypto;
mod keystore;
mod mlkem_keystore;

use jni::{
    EnvUnowned, jni_mangle,
    objects::JString,
    sys::{jboolean, jclass, jint},
};

use ml_kem::{
    MlKem1024,
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
};

use std::fmt::Write;

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        write!(&mut output, "{:02X}", *byte).expect("writing to a String should not fail");
    }

    output
}

#[jni_mangle("kakha.kudava.NativeMath")]
pub fn add<'local>(_env: EnvUnowned<'local>, _class: jclass, left: jint, right: jint) -> jint {
    left + right
}

#[jni_mangle("kakha.kudava.NativeMath", "generateAndPrintAes256Key")]
pub fn generate_and_print_aes256_key<'local>(_env: EnvUnowned<'local>, _class: jclass) {
    let mut key = [0u8; 32];

    if let Err(error) = getrandom::fill(&mut key) {
        eprintln!("Failed to generate AES-256 key: {error}");
        return;
    }

    println!("AES-256 key: {}", bytes_to_hex(&key));
}

#[jni_mangle("kakha.kudava.NativeMath", "generateAndPrintMlKem1024Keypair")]
pub fn generate_and_print_ml_kem_1024_keypair<'local>(_env: EnvUnowned<'local>, _class: jclass) {
    // Uses the operating system's cryptographically secure RNG.
    let (decapsulation_key, encapsulation_key) = MlKem1024::generate_keypair();

    // Public encapsulation key.
    let public_key_bytes = encapsulation_key.to_bytes();

    // The crate serializes the secret decapsulation key as a
    // 64-byte seed from which the complete private key is reconstructed.
    let private_key_seed = decapsulation_key.to_bytes();

    println!("ML-KEM-1024 PUBLIC KEY:");
    println!("{}", bytes_to_hex(public_key_bytes.as_ref()));

    println!("ML-KEM-1024 PRIVATE KEY SEED:");
    println!("{}", bytes_to_hex(private_key_seed.as_ref()));

    // Optional proof that the generated pair works:
    let (ciphertext, sender_shared_secret) = encapsulation_key.encapsulate();

    let receiver_shared_secret = decapsulation_key.decapsulate(&ciphertext);

    println!(
        "ML-KEM encapsulation test passed: {}",
        sender_shared_secret == receiver_shared_secret
    );

    println!(
        "ML-KEM shared secret: {}",
        bytes_to_hex(sender_shared_secret.as_ref())
    );
}

#[jni_mangle("kakha.kudava.NativeMath", "createStoredAes256Key")]
pub fn create_stored_aes256_key<'local>(_env: EnvUnowned<'local>, _class: jclass) -> jboolean {
    match keystore::generate_and_store_aes256_key() {
        Ok(path) => {
            println!("Created DPAPI-protected AES-256 key at: {}", path.display());
            true
        }

        Err(error) => {
            eprintln!("Could not create AES-256 key: {error}");
            false
        }
    }
}

#[jni_mangle("kakha.kudava.NativeMath", "verifyStoredAes256Key")]
pub fn verify_stored_aes256_key<'local>(_env: EnvUnowned<'local>, _class: jclass) -> jboolean {
    match keystore::load_aes256_key() {
        Ok(key) => {
            println!(
                "Successfully loaded a protected AES-256 key: {} bytes",
                key.len()
            );

            // `key` is zeroized when dropped.
            true
        }

        Err(error) => {
            eprintln!("Could not load AES-256 key: {error}");
            false
        }
    }
}

#[jni_mangle("kakha.kudava.NativeMath", "createStoredMlKem1024Keypair")]
pub fn create_stored_ml_kem1024_keypair<'local>(
    _env: EnvUnowned<'local>,
    _class: jclass,
) -> jboolean {
    match mlkem_keystore::generate_and_store_ml_kem1024_keypair() {
        Ok(paths) => {
            println!(
                "Created ML-KEM-1024 private key at: {}",
                paths.private_key_path.display()
            );

            println!(
                "Created ML-KEM-1024 public key at: {}",
                paths.public_key_path.display()
            );

            true
        }

        Err(error) => {
            eprintln!(
                "Could not create ML-KEM-1024 keypair: \
                 {error}"
            );

            false
        }
    }
}

#[jni_mangle("kakha.kudava.NativeMath", "verifyStoredMlKem1024Keypair")]
pub fn verify_stored_ml_kem1024_keypair<'local>(
    _env: EnvUnowned<'local>,
    _class: jclass,
) -> jboolean {
    match mlkem_keystore::verify_stored_ml_kem1024_keypair() {
        Ok(()) => {
            println!("Stored ML-KEM-1024 keypair verified");

            true
        }

        Err(error) => {
            eprintln!(
                "Could not verify ML-KEM-1024 keypair: \
                 {error}"
            );

            false
        }
    }
}
#[jni_mangle("kakha.kudava.NativeMath", "testStoredMlKemDekEnvelope")]
pub fn test_stored_ml_kem_dek_envelope<'local>(
    _env: EnvUnowned<'local>,
    _class: jclass,
) -> jboolean {
    let private_key = match mlkem_keystore::load_stored_ml_kem1024_decapsulation_key() {
        Ok(key) => key,

        Err(error) => {
            eprintln!("Could not load stored ML-KEM keypair: {error}");
            return false;
        }
    };

    let original_dek = match dek_envelope::generate_dek() {
        Ok(dek) => dek,

        Err(error) => {
            eprintln!("Could not generate AES-256 DEK: {error}");
            return false;
        }
    };

    let envelope = match dek_envelope::wrap_dek(private_key.encapsulation_key(), &*original_dek) {
        Ok(envelope) => envelope,

        Err(error) => {
            eprintln!("Could not wrap AES-256 DEK: {error}");
            return false;
        }
    };

    let recovered_dek = match dek_envelope::unwrap_dek(&private_key, &envelope) {
        Ok(dek) => dek,

        Err(error) => {
            eprintln!("Could not unwrap AES-256 DEK: {error}");
            return false;
        }
    };

    let keys_match = original_dek.as_slice() == recovered_dek.as_slice();

    if keys_match {
        println!("AES-256 DEK wrapped and unwrapped successfully");

        println!(
            "ML-KEM ciphertext: {} bytes",
            envelope.ml_kem_ciphertext.len()
        );

        println!("Wrapped DEK: {} bytes", envelope.wrapped_dek.len());
    } else {
        eprintln!("Recovered AES-256 DEK did not match the original");
    }

    keys_match
}

#[jni_mangle("kakha.kudava.NativeMath", "encryptSelectedFile")]
pub fn encrypt_selected_file<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: jclass,
    input_path: JString<'local>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> Result<jboolean, jni::errors::Error> {
            let input_path = input_path.try_to_string(env)?;

            let succeeded = match file_crypto::encrypt_file(std::path::Path::new(&input_path)) {
                Ok(output_path) => {
                    println!("File encrypted successfully");

                    println!("Encrypted output: {}", output_path.display());

                    true
                }

                Err(error) => {
                    eprintln!("File encryption failed: {error}");

                    false
                }
            };

            Ok(succeeded)
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

#[jni_mangle("kakha.kudava.NativeMath", "decryptSelectedFile")]
pub fn decrypt_selected_file<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: jclass,
    input_path: JString<'local>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> Result<jboolean, jni::errors::Error> {
            let input_path = input_path.try_to_string(env)?;

            let succeeded = match file_crypto::decrypt_file(std::path::Path::new(&input_path)) {
                Ok(output_path) => {
                    println!("File decrypted successfully");

                    println!("Decrypted output: {}", output_path.display());

                    true
                }

                Err(error) => {
                    eprintln!("File decryption failed: {error}");

                    false
                }
            };

            Ok(succeeded)
        })
        .resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}


#[jni_mangle(
    "kakha.kudava.NativeMath",
    "decryptSelectedFileTo"
)]
pub fn decrypt_selected_file_to<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: jclass,
    input_path: JString<'local>,
    output_path: JString<'local>,
    overwrite: jboolean,
) -> jboolean {
    unowned_env
        .with_env(
            |env| -> Result<
                jboolean,
                jni::errors::Error,
            > {
                let input_path =
                    input_path.try_to_string(env)?;

                let output_path =
                    output_path.try_to_string(env)?;

                let succeeded =
                    match file_crypto::decrypt_file_to(
                        std::path::Path::new(
                            &input_path,
                        ),
                        std::path::Path::new(
                            &output_path,
                        ),
                        overwrite,
                    ) {
                        Ok(created_path) => {
                            println!(
                                "File decrypted successfully"
                            );

                            println!(
                                "Decrypted output: {}",
                                created_path.display()
                            );

                            true
                        }

                        Err(error) => {
                            eprintln!(
                                "File decryption failed: {error}"
                            );

                            false
                        }
                    };

                Ok(succeeded)
            },
        )
        .resolve::<
            jni::errors::ThrowRuntimeExAndDefault,
        >()
}