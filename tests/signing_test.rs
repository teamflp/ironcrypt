use ironcrypt::{
    ecc_utils, hashing, load_any_private_key, load_any_public_key,
    signing::{sign_hash_with_any_key, verify_signature_with_any_key},
};
#[cfg(feature = "rsa-algo")]
use ironcrypt::generate_rsa_keys;
use tempfile::tempdir;

#[test]
fn test_sign_and_verify_ecc() {
    let dir = tempdir().expect("Failed to create temp dir");
    let priv_path = dir.path().join("ecc_private.pem");
    let pub_path = dir.path().join("ecc_public.pem");
    let other_priv_path = dir.path().join("ecc_other_private.pem");
    let other_pub_path = dir.path().join("ecc_other_public.pem");

    let (sk, pk) = ecc_utils::generate_ecc_keys().expect("ECC key gen failed");
    ecc_utils::save_keys_to_files(
        &sk,
        &pk,
        priv_path.to_str().unwrap(),
        pub_path.to_str().unwrap(),
        None,
    )
    .expect("ECC save failed");

    let (other_sk, other_pk) = ecc_utils::generate_ecc_keys().expect("ECC key gen failed");
    ecc_utils::save_keys_to_files(
        &other_sk,
        &other_pk,
        other_priv_path.to_str().unwrap(),
        other_pub_path.to_str().unwrap(),
        None,
    )
    .expect("ECC save failed");

    let priv_key = load_any_private_key(priv_path.to_str().unwrap(), None).unwrap();
    let pub_key = load_any_public_key(pub_path.to_str().unwrap()).unwrap();
    let other_pub = load_any_public_key(other_pub_path.to_str().unwrap()).unwrap();

    let data = b"This is some important data to be signed.";
    let hash = hashing::hash_bytes(data).unwrap();
    let signature = sign_hash_with_any_key(&priv_key, &hash).unwrap();
    verify_signature_with_any_key(&pub_key, &hash, &signature).unwrap();

    let tampered_hash = hashing::hash_bytes(b"This is some important data to be signed!").unwrap();
    assert!(verify_signature_with_any_key(&pub_key, &tampered_hash, &signature).is_err());

    let mut tampered_sig = signature.clone();
    let last = tampered_sig.len() - 1;
    tampered_sig[last] ^= 0xff;
    assert!(verify_signature_with_any_key(&pub_key, &hash, &tampered_sig).is_err());

    assert!(verify_signature_with_any_key(&other_pub, &hash, &signature).is_err());
}

#[cfg(feature = "rsa-algo")]
#[test]
fn test_sign_and_verify_rsa() {
    let dir = tempdir().expect("Failed to create temp dir");
    let rsa_priv_path = dir.path().join("rsa_private.pem");
    let rsa_pub_path = dir.path().join("rsa_public.pem");

    let (rsa_priv, rsa_pub) = generate_rsa_keys(2048).expect("RSA key gen failed");
    ironcrypt::save_keys_to_files(
        &rsa_priv,
        &rsa_pub,
        rsa_priv_path.to_str().unwrap(),
        rsa_pub_path.to_str().unwrap(),
        None,
    )
    .expect("RSA save failed");

    let rsa_priv_key = load_any_private_key(rsa_priv_path.to_str().unwrap(), None).unwrap();
    let rsa_pub_key = load_any_public_key(rsa_pub_path.to_str().unwrap()).unwrap();

    let data = b"This is some important data to be signed.";
    let hash = hashing::hash_bytes(data).unwrap();
    let signature = sign_hash_with_any_key(&rsa_priv_key, &hash).unwrap();
    verify_signature_with_any_key(&rsa_pub_key, &hash, &signature).unwrap();

    let tampered_hash = hashing::hash_bytes(b"This is some important data to be signed!").unwrap();
    assert!(verify_signature_with_any_key(&rsa_pub_key, &tampered_hash, &signature).is_err());
}
