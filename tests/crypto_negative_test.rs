//! Negative / adversarial crypto tests (wrong password, tampering, empty recipients).

use ironcrypt::{
    algorithms::SymmetricAlgorithm,
    encrypt_stream,
    keys::{PrivateKey, PublicKey},
    rsa_utils, Argon2Config, IronCryptError, PasswordCriteria,
};
use std::io::Cursor;

fn rsa_pair() -> (PrivateKey, PublicKey) {
    let (sk, pk) = rsa_utils::generate_rsa_keys(2048).unwrap();
    (PrivateKey::Rsa(sk), PublicKey::Rsa(pk))
}

#[test]
fn decrypt_rejects_wrong_password_before_plaintext() {
    let (private_key, public_key) = rsa_pair();
    let original = b"classified payload";
    let mut source = Cursor::new(original.to_vec());
    let mut encrypted = Cursor::new(Vec::new());
    let mut password = "CorrectP@ssw0rd1!".to_string();

    encrypt_stream(
        &mut source,
        &mut encrypted,
        &mut password,
        vec![(&public_key, "v1")],
        None,
        &PasswordCriteria::default(),
        Argon2Config::default(),
        true,
        SymmetricAlgorithm::Aes256Gcm,
    )
    .unwrap();

    encrypted.set_position(0);
    let mut out = Cursor::new(Vec::new());
    let err = ironcrypt::decrypt_stream(
        &mut encrypted,
        &mut out,
        &private_key,
        "v1",
        "WrongP@ssw0rd99!",
        None,
    )
    .unwrap_err();

    assert!(matches!(err, IronCryptError::PasswordVerificationError));
    assert!(
        out.get_ref().is_empty(),
        "no plaintext must be written when the password is wrong"
    );
}

#[test]
fn encrypt_rejects_empty_recipients() {
    let mut source = Cursor::new(b"data".to_vec());
    let mut dest = Cursor::new(Vec::new());
    let mut password = String::new();
    let empty: Vec<(&PublicKey, &str)> = vec![];

    let err = encrypt_stream(
        &mut source,
        &mut dest,
        &mut password,
        empty,
        None,
        &PasswordCriteria::default(),
        Argon2Config::default(),
        false,
        SymmetricAlgorithm::Aes256Gcm,
    )
    .unwrap_err();

    assert!(matches!(err, IronCryptError::EncryptionError(_)));
}

#[test]
fn decrypt_rejects_tampered_ciphertext() {
    let (private_key, public_key) = rsa_pair();
    let mut source = Cursor::new(b"integrity check".to_vec());
    let mut encrypted = Cursor::new(Vec::new());
    let mut password = String::new();

    encrypt_stream(
        &mut source,
        &mut encrypted,
        &mut password,
        vec![(&public_key, "v1")],
        None,
        &PasswordCriteria::default(),
        Argon2Config::default(),
        false,
        SymmetricAlgorithm::Aes256Gcm,
    )
    .unwrap();

    let mut bytes = encrypted.into_inner();
    let last = bytes.len() - 1;
    bytes[last] = bytes[last].wrapping_add(1);

    let mut tampered = Cursor::new(bytes);
    let mut out = Cursor::new(Vec::new());
    assert!(ironcrypt::decrypt_stream(
        &mut tampered,
        &mut out,
        &private_key,
        "v1",
        "",
        None,
    )
    .is_err());
}

#[test]
fn password_encrypt_json_does_not_leak_argon2_hash() {
    let (private_key, public_key) = rsa_pair();
    let json = ironcrypt::password::encrypt(
        "Str0ngP@ssw0rd42!",
        &public_key,
        "v1",
        &Argon2Config::default(),
    )
    .unwrap();
    let ed: ironcrypt::EncryptedData = serde_json::from_str(&json).unwrap();
    assert!(ed.password_hash.is_none());
    assert!(!json.contains("$argon2"));
    assert!(ironcrypt::password::verify(&json, "Str0ngP@ssw0rd42!", &private_key).unwrap());
    assert!(!ironcrypt::password::verify(&json, "nope", &private_key).unwrap());
}

#[test]
fn decrypt_rejects_unknown_key_version() {
    let (private_key, public_key) = rsa_pair();
    let mut source = Cursor::new(b"hello".to_vec());
    let mut encrypted = Cursor::new(Vec::new());
    let mut password = String::new();

    encrypt_stream(
        &mut source,
        &mut encrypted,
        &mut password,
        vec![(&public_key, "v1")],
        None,
        &PasswordCriteria::default(),
        Argon2Config::default(),
        false,
        SymmetricAlgorithm::Aes256Gcm,
    )
    .unwrap();

    encrypted.set_position(0);
    let mut out = Cursor::new(Vec::new());
    let err = ironcrypt::decrypt_stream(
        &mut encrypted,
        &mut out,
        &private_key,
        "v999",
        "",
        None,
    )
    .unwrap_err();
    assert!(matches!(err, IronCryptError::DecryptionError(_)));
}
