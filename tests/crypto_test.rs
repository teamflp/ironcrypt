use ironcrypt::{
    algorithms::SymmetricAlgorithm,
    ecc_utils,
    encrypt_stream,
    keys::{PrivateKey, PublicKey},
    rsa_utils, Argon2Config, PasswordCriteria,
};
use p256::pkcs8::spki::EncodePublicKey;
use std::io::Cursor;
use tempfile::tempdir;

fn test_e2e_encryption(
    private_key: PrivateKey,
    public_key: PublicKey,
    sym_algo: SymmetricAlgorithm,
) {
    let original_data = b"This is a top secret message.";
    let mut source = Cursor::new(original_data);
    let mut encrypted_dest = Cursor::new(Vec::new());
    let mut decrypted_dest = Cursor::new(Vec::new());

    let key_version = "v1";
    let mut password = "test_password".to_string();

    let recipients = vec![(&public_key, key_version)];

    // Encrypt
    encrypt_stream(
        &mut source,
        &mut encrypted_dest,
        &mut password,
        recipients,
        &PasswordCriteria::default(),
        Argon2Config::default(),
        false,
        sym_algo,
    )
    .unwrap();

    encrypted_dest.set_position(0);

    // Decrypt
    ironcrypt::decrypt_stream(
        &mut encrypted_dest,
        &mut decrypted_dest,
        &private_key,
        key_version,
        "test_password",
    )
    .unwrap();

    assert_eq!(original_data, &decrypted_dest.into_inner()[..]);
}

#[test]
fn test_e2e_rsa_aes() {
    let (private_key, public_key) = rsa_utils::generate_rsa_keys(2048).unwrap();
    test_e2e_encryption(
        PrivateKey::Rsa(private_key),
        PublicKey::Rsa(public_key),
        SymmetricAlgorithm::Aes256Gcm,
    );
}

#[test]
fn test_e2e_rsa_chacha() {
    let (private_key, public_key) = rsa_utils::generate_rsa_keys(2048).unwrap();
    test_e2e_encryption(
        PrivateKey::Rsa(private_key),
        PublicKey::Rsa(public_key),
        SymmetricAlgorithm::ChaCha20Poly1305,
    );
}

#[test]
fn test_e2e_ecc_aes() {
    let (private_key, public_key) = ecc_utils::generate_ecc_keys().unwrap();
    test_e2e_encryption(
        PrivateKey::Ecc(private_key),
        PublicKey::Ecc(public_key),
        SymmetricAlgorithm::Aes256Gcm,
    );
}

#[test]
fn test_e2e_ecc_chacha() {
    let (private_key, public_key) = ecc_utils::generate_ecc_keys().unwrap();
    test_e2e_encryption(
        PrivateKey::Ecc(private_key),
        PublicKey::Ecc(public_key),
        SymmetricAlgorithm::ChaCha20Poly1305,
    );
}

#[test]
fn test_ecc_key_save_and_load() {
    let dir = tempdir().unwrap();
    let private_key_path = dir.path().join("ecc_private.pem");
    let public_key_path = dir.path().join("ecc_public.pem");

    // 1. Generate and save
    let (secret_key, public_key) = ecc_utils::generate_ecc_keys().unwrap();
    ecc_utils::save_keys_to_files(
        &secret_key,
        &public_key,
        private_key_path.to_str().unwrap(),
        public_key_path.to_str().unwrap(),
        None,
    )
    .unwrap();

    // 2. Load back
    let loaded_secret =
        ecc_utils::load_secret_key(private_key_path.to_str().unwrap(), None).unwrap();
    let loaded_public = ecc_utils::load_public_key(public_key_path.to_str().unwrap()).unwrap();

    // 3. Assert they are the same
    assert_eq!(secret_key.to_sec1_der().unwrap(), loaded_secret.to_sec1_der().unwrap());
    assert_eq!(public_key.to_public_key_der().unwrap(), loaded_public.to_public_key_der().unwrap());
}

#[test]
fn test_ecc_key_save_and_load_with_passphrase() {
    let dir = tempdir().unwrap();
    let private_key_path = dir.path().join("ecc_private_encrypted.pem");
    let public_key_path = dir.path().join("ecc_public_encrypted.pem");
    let passphrase = "test_password";

    // 1. Generate and save
    let (secret_key, public_key) = ecc_utils::generate_ecc_keys().unwrap();
    ecc_utils::save_keys_to_files(
        &secret_key,
        &public_key,
        private_key_path.to_str().unwrap(),
        public_key_path.to_str().unwrap(),
        Some(passphrase),
    )
    .unwrap();

    // 2. Load back
    let loaded_secret =
        ecc_utils::load_secret_key(private_key_path.to_str().unwrap(), Some(passphrase)).unwrap();
    let loaded_public = ecc_utils::load_public_key(public_key_path.to_str().unwrap()).unwrap();

    // 3. Assert they are the same
    assert_eq!(secret_key.to_sec1_der().unwrap(), loaded_secret.to_sec1_der().unwrap());
    assert_eq!(public_key.to_public_key_der().unwrap(), loaded_public.to_public_key_der().unwrap());
}
