use jni::{
    jni_mangle,
    sys::{jclass, jint},
    EnvUnowned,
};

use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    MlKem1024,
};

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02X}", *byte))
        .collect()
}

#[jni_mangle("kakha.kudava.NativeMath")]
pub fn add<'local>(
    _env: EnvUnowned<'local>,
    _class: jclass,
    left: jint,
    right: jint,
) -> jint {
    left + right
}

#[jni_mangle(
    "kakha.kudava.NativeMath",
    "generateAndPrintAes256Key"
)]
pub fn generate_and_print_aes256_key<'local>(
    _env: EnvUnowned<'local>,
    _class: jclass,
) {
    let mut key = [0u8; 32];

    if let Err(error) = getrandom::fill(&mut key) {
        eprintln!("Failed to generate AES-256 key: {error}");
        return;
    }

    println!("AES-256 key: {}", bytes_to_hex(&key));
}

#[jni_mangle(
    "kakha.kudava.NativeMath",
    "generateAndPrintMlKem1024Keypair"
)]
pub fn generate_and_print_ml_kem_1024_keypair<'local>(
    _env: EnvUnowned<'local>,
    _class: jclass,
) {
    // Uses the operating system's cryptographically secure RNG.
    let (decapsulation_key, encapsulation_key) =
        MlKem1024::generate_keypair();

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
    let (ciphertext, sender_shared_secret) =
        encapsulation_key.encapsulate();

    let receiver_shared_secret =
        decapsulation_key.decapsulate(&ciphertext);

    println!(
        "ML-KEM encapsulation test passed: {}",
        sender_shared_secret == receiver_shared_secret
    );

    println!(
        "ML-KEM shared secret: {}",
        bytes_to_hex(sender_shared_secret.as_ref())
    );
}