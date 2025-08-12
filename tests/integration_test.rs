use ironcrypt::{IronCrypt, IronCryptConfig};
use rsa::pkcs1::EncodeRsaPublicKey;
use std::fs;
use std::io::Write;
use std::path::Path;

fn setup_test_dir(dir: &str) {
    if Path::new(dir).exists() {
        fs::remove_dir_all(dir).unwrap();
    }
    fs::create_dir_all(dir).unwrap();
}

#[test]
fn test_file_encryption_decryption() {
    let key_dir = "test_keys_file_enc";
    setup_test_dir(key_dir);

    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(key_dir, "v1", config).expect("Failed to create IronCrypt instance");

    // Create a dummy file
    let input_file = "test_input.bin";
    let output_enc_file = "test_output.enc";
    let output_dec_file = "test_output.dec.bin";
    let mut f = fs::File::create(input_file).unwrap();
    f.write_all(b"this is a test file").unwrap();

    // Encrypt
    let encrypted_json = crypt
        .encrypt_binary_data(&fs::read(input_file).unwrap(), "file_password")
        .unwrap();
    fs::write(output_enc_file, encrypted_json).unwrap();

    // Decrypt
    let decrypted_data = crypt
        .decrypt_binary_data(
            &fs::read_to_string(output_enc_file).unwrap(),
            "file_password",
        )
        .unwrap();
    fs::write(output_dec_file, &decrypted_data).unwrap();

    // Verify
    assert_eq!(fs::read(input_file).unwrap(), decrypted_data);

    // Cleanup
    fs::remove_file(input_file).unwrap();
    fs::remove_file(output_enc_file).unwrap();
    fs::remove_file(output_dec_file).unwrap();
    fs::remove_dir_all(key_dir).unwrap();
}

#[test]
fn test_directory_encryption_decryption() {
    let key_dir = "test_keys_dir_enc";
    let source_dir = "test_source_dir";
    let encrypted_file = "test_dir.enc";
    let restored_dir = "test_restored_dir";

    setup_test_dir(key_dir);
    setup_test_dir(source_dir);
    setup_test_dir(restored_dir);

    // Create some files in the source directory
    fs::write(Path::new(source_dir).join("file1.txt"), "hello").unwrap();
    fs::create_dir(Path::new(source_dir).join("subdir")).unwrap();
    fs::write(Path::new(source_dir).join("subdir/file2.txt"), "world").unwrap();

    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(key_dir, "v1", config).unwrap();

    // Encrypt directory
    let mut archive_data = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut archive_data, flate2::Compression::default());
        let mut tar_builder = tar::Builder::new(enc);
        tar_builder.append_dir_all(".", source_dir).unwrap();
        tar_builder.into_inner().unwrap();
    }
    let encrypted_json = crypt.encrypt_binary_data(&archive_data, "").unwrap();
    fs::write(encrypted_file, encrypted_json).unwrap();

    // Decrypt directory
    let encrypted_content = fs::read_to_string(encrypted_file).unwrap();
    let decrypted_data = crypt.decrypt_binary_data(&encrypted_content, "").unwrap();

    let dec = flate2::read::GzDecoder::new(decrypted_data.as_slice());
    let mut archive = tar::Archive::new(dec);
    archive.unpack(restored_dir).unwrap();

    // Verify
    let original_file1 = fs::read_to_string(Path::new(source_dir).join("file1.txt")).unwrap();
    let restored_file1 = fs::read_to_string(Path::new(restored_dir).join(source_dir).join("file1.txt")).unwrap();
    assert_eq!(original_file1, restored_file1);

    let original_file2 = fs::read_to_string(Path::new(source_dir).join("subdir/file2.txt")).unwrap();
    let restored_file2 = fs::read_to_string(Path::new(restored_dir).join(source_dir).join("subdir/file2.txt")).unwrap();
    assert_eq!(original_file2, restored_file2);


    // Cleanup
    fs::remove_dir_all(key_dir).unwrap();
    fs::remove_dir_all(source_dir).unwrap();
    fs::remove_file(encrypted_file).unwrap();
    fs::remove_dir_all(restored_dir).unwrap();
}

#[test]
fn test_key_rotation() {
    let key_dir = "test_keys_rotation";
    setup_test_dir(key_dir);

    // 1. Create initial version (v1)
    let config_v1 = IronCryptConfig::default();
    let crypt_v1 = IronCrypt::new(key_dir, "v1", config_v1).unwrap();
    let encrypted_data_v1 = crypt_v1.encrypt_password("my_password").unwrap();

    // 2. Create a new key version (v2)
    let mut config_v2 = IronCryptConfig::default();
    config_v2.rsa_key_size = 2048; // Can be different
    let _crypt_v2 = IronCrypt::new(key_dir, "v2", config_v2).unwrap();

    // 3. Load the new public key
    let new_pub_key_path = format!("{}/public_key_v2.pem", key_dir);
    let new_pub_key = ironcrypt::load_public_key(&new_pub_key_path).unwrap();

    // 4. Re-encrypt the data from v1 to v2
    let re_encrypted_data = crypt_v1
        .re_encrypt_data(&encrypted_data_v1, &new_pub_key, "v2")
        .unwrap();

    // 5. Verify with the new key
    let crypt_v2_verify = IronCrypt::new(key_dir, "v2", IronCryptConfig::default()).unwrap();
    let is_valid = crypt_v2_verify
        .verify_password(&re_encrypted_data, "my_password")
        .unwrap();
    assert!(is_valid);

    // Cleanup
    fs::remove_dir_all(key_dir).unwrap();
}

#[test]
fn test_load_pkcs1_and_pkcs8_keys() {
    let key_dir = "test_keys_format";
    setup_test_dir(key_dir);

    // Copy fixtures
    fs::copy("tests/fixtures/pkcs1_v1_private.pem", format!("{}/private_key_v1.pem", key_dir)).unwrap();
    fs::copy("tests/fixtures/pkcs8_v1_private.pem", format!("{}/private_key_v2.pem", key_dir)).unwrap();

    // Manually create public keys for them to be sure they match
    let pkcs1_priv = ironcrypt::load_private_key(&format!("{}/private_key_v1.pem", key_dir)).unwrap();
    let pkcs1_pub = rsa::RsaPublicKey::from(&pkcs1_priv);
    let pkcs1_pub_pem = pkcs1_pub.to_pkcs1_pem(Default::default()).unwrap();
    fs::write(format!("{}/public_key_v1.pem", key_dir), pkcs1_pub_pem).unwrap();

    let pkcs8_priv = ironcrypt::load_private_key(&format!("{}/private_key_v2.pem", key_dir)).unwrap();
    let pkcs8_pub = rsa::RsaPublicKey::from(&pkcs8_priv);
    let pkcs8_pub_pem = pkcs8_pub.to_pkcs1_pem(Default::default()).unwrap();
    fs::write(format!("{}/public_key_v2.pem", key_dir), pkcs8_pub_pem).unwrap();


    // Test PKCS#1
    let crypt_v1 = IronCrypt::new(key_dir, "v1", IronCryptConfig::default()).unwrap();
    let encrypted_v1 = crypt_v1.encrypt_password("test_pkcs1").unwrap();
    assert!(crypt_v1.verify_password(&encrypted_v1, "test_pkcs1").unwrap());

    // Test PKCS#8
    let crypt_v2 = IronCrypt::new(key_dir, "v2", IronCryptConfig::default()).unwrap();
    let encrypted_v2 = crypt_v2.encrypt_password("test_pkcs8").unwrap();
    assert!(crypt_v2.verify_password(&encrypted_v2, "test_pkcs8").unwrap());

    // Cleanup
    fs::remove_dir_all(key_dir).unwrap();
}
