//! README: AES streaming (library quick start / file streaming section)
use ironcrypt::{
    algorithms::SymmetricAlgorithm,
    decrypt_stream, encrypt_stream, generate_rsa_keys,
    keys::{PrivateKey, PublicKey},
    Argon2Config, PasswordCriteria,
};
use std::io::Cursor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (sk, pk) = generate_rsa_keys(2048)?;
    let public_key = PublicKey::Rsa(pk);
    let private_key = PrivateKey::Rsa(sk);

    let original = b"secret streamed message";
    let mut src = Cursor::new(original.as_slice());
    let mut enc = Cursor::new(Vec::new());
    let mut password = String::new();

    encrypt_stream(
        &mut src,
        &mut enc,
        &mut password,
        [(&public_key, "v1")],
        None, // no signature → real AES streaming
        &PasswordCriteria::default(),
        Argon2Config::default(),
        false,
        SymmetricAlgorithm::Aes256Gcm,
    )?;

    enc.set_position(0);
    let mut out = Cursor::new(Vec::new());
    decrypt_stream(&mut enc, &mut out, &private_key, "v1", "", None)?;
    assert_eq!(out.into_inner(), original);
    Ok(())
}
