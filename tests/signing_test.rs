use ironcrypt::{
    ecc_utils, generate_rsa_keys, hashing, load_any_private_key, load_any_public_key,
    signing::{sign_hash_with_any_key, verify_signature_with_any_key},
};
use tempfile::tempdir;

#[test]
fn test_sign_and_verify_rsa_and_ecc() {
    // 1. Setup: Create temp dir and keys
    let dir = tempdir().expect("Failed to create temp dir");
    let key_dir = dir.path();

    // Generate and save RSA keys
    let (rsa_priv, rsa_pub) = generate_rsa_keys(2048).expect("RSA key gen failed");
    let rsa_priv_path = key_dir.join("rsa_private.pem");
    let rsa_pub_path = key_dir.join("rsa_public.pem");
    ironcrypt::save_keys_to_files(
        &rsa_priv,
        &rsa_pub,
        rsa_priv_path.to_str().unwrap(),
        rsa_pub_path.to_str().unwrap(),
        None,
    )
    .expect("Failed to save RSA keys");

    // Generate and save ECC keys
    let (ecc_priv, ecc_pub) = ecc_utils::generate_ecc_keys().expect("ECC key gen failed");
    let ecc_priv_path = key_dir.join("ecc_private.pem");
    let ecc_pub_path = key_dir.join("ecc_public.pem");
    ecc_utils::save_keys_to_files(
        &ecc_priv,
        &ecc_pub,
        ecc_priv_path.to_str().unwrap(),
        ecc_pub_path.to_str().unwrap(),
        None,
    )
    .expect("Failed to save ECC keys");

    // 2. Create data and hash it
    let data = b"This is some test data for signing.";
    let hash = hashing::hash_bytes(data).expect("Hashing failed");

    // 3. Sign with both keys
    let loaded_rsa_priv =
        load_any_private_key(rsa_priv_path.to_str().unwrap(), None).expect("Failed to load RSA priv key");
    let rsa_signature =
        sign_hash_with_any_key(&loaded_rsa_priv, &hash).expect("RSA signing failed");

    let loaded_ecc_priv =
        load_any_private_key(ecc_priv_path.to_str().unwrap(), None).expect("Failed to load ECC priv key");
    let ecc_signature =
        sign_hash_with_any_key(&loaded_ecc_priv, &hash).expect("ECC signing failed");

    // 4. Verify signatures
    let loaded_rsa_pub =
        load_any_public_key(rsa_pub_path.to_str().unwrap()).expect("Failed to load RSA pub key");
    let rsa_result = verify_signature_with_any_key(&loaded_rsa_pub, &hash, &rsa_signature);
    assert!(rsa_result.is_ok(), "RSA verification should succeed");

    let loaded_ecc_pub =
        load_any_public_key(ecc_pub_path.to_str().unwrap()).expect("Failed to load ECC pub key");
    let ecc_result = verify_signature_with_any_key(&loaded_ecc_pub, &hash, &ecc_signature);
    assert!(ecc_result.is_ok(), "ECC verification should succeed");

    // 5. Test failure cases
    // Tampered data
    let tampered_hash = hashing::hash_bytes(b"tampered data").unwrap();
    let tampered_data_result =
        verify_signature_with_any_key(&loaded_rsa_pub, &tampered_hash, &rsa_signature);
    assert!(
        tampered_data_result.is_err(),
        "Verification should fail for tampered data"
    );

    // Tampered signature
    let mut tampered_signature = rsa_signature.clone();
    tampered_signature[0] ^= 0xff; // Flip some bits
    let tampered_sig_result =
        verify_signature_with_any_key(&loaded_rsa_pub, &hash, &tampered_signature);
    assert!(
        tampered_sig_result.is_err(),
        "Verification should fail for tampered signature"
    );

    // Wrong key
    let wrong_key_result = verify_signature_with_any_key(&loaded_ecc_pub, &hash, &rsa_signature);
    assert!(
        wrong_key_result.is_err(),
        "Verification should fail with the wrong key"
    );
}
