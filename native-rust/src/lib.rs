mod dpapi;
mod keystore;
mod mlkem_keystore;

use jni::{
    EnvUnowned, jni_mangle,
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
