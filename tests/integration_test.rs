// tests/integration_test.rs

use ironcrypt::{IronCrypt, IronCryptConfig, config::DataType};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::EncodePrivateKey;
use std::fs;
use std::io::Write;
use std::path::Path;
use aes_gcm::aead::OsRng;

const STRONG_PASSWORD: &str = "Str0ngP@ssw0rd42!";

fn setup_test_dir(dir: &str) {
    if Path::new(dir).exists() {
        fs::remove_dir_all(dir).unwrap();
    }
    fs::create_dir_all(dir).unwrap();
}

#[tokio::test]
async fn test_file_encryption_decryption() {
    let key_dir = "test_keys_file_enc";
    setup_test_dir(key_dir);

    let mut config = IronCryptConfig::default();
    let mut data_type_config = ironcrypt::config::DataTypeConfig::new();
    data_type_config.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v1".to_string(),
        },
    );
    config.data_type_config = Some(data_type_config);

    let crypt = IronCrypt::new(config, DataType::Generic).await.expect("Failed to create IronCrypt instance");

    // Create a dummy file
    let input_file = "test_input.bin";
    let output_enc_file = "test_output.enc";
    let output_dec_file = "test_output.dec.bin";
    let mut f = fs::File::create(input_file).unwrap();
    f.write_all(b"this is a test file").unwrap();

    // Encrypt
    let encrypted_json = crypt
        .encrypt_binary_data(&fs::read(input_file).unwrap(), STRONG_PASSWORD)
        .unwrap();
    fs::write(output_enc_file, encrypted_json).unwrap();

    // Decrypt
    let decrypted_data = crypt
        .decrypt_binary_data(
            &fs::read_to_string(output_enc_file).unwrap(),
            STRONG_PASSWORD,
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

#[tokio::test]
async fn test_directory_encryption_decryption() {
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

    let mut config = IronCryptConfig::default();
    let mut data_type_config = ironcrypt::config::DataTypeConfig::new();
    data_type_config.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v1".to_string(),
        },
    );
    config.data_type_config = Some(data_type_config);

    let crypt = IronCrypt::new(config, DataType::Generic).await.unwrap();

    // Create tar.gz archive of the directory (preserve top-level folder)
    let archive_data: Vec<u8> = {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar_builder = tar::Builder::new(&mut encoder);
            // Important: store entries under `source_dir/` instead of at the root
            tar_builder.append_dir_all(source_dir, source_dir).unwrap();
            tar_builder.finish().unwrap();
        }
        encoder.finish().unwrap()
    };

    // Encrypt directory
    let encrypted_json = crypt.encrypt_binary_data(&archive_data, STRONG_PASSWORD).unwrap();
    fs::write(encrypted_file, encrypted_json).unwrap();

    // Decrypt directory
    let encrypted_content = fs::read_to_string(encrypted_file).unwrap();
    let decrypted_data = crypt.decrypt_binary_data(&encrypted_content, STRONG_PASSWORD).unwrap();

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

#[tokio::test]
async fn test_key_rotation() {
    let key_dir = "test_keys_rotation";
    setup_test_dir(key_dir);

    // 1. Create initial version (v1)
    let mut config_v1 = IronCryptConfig::default();
    let mut data_type_config = ironcrypt::config::DataTypeConfig::new();
    data_type_config.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v1".to_string(),
        },
    );
    config_v1.data_type_config = Some(data_type_config.clone());
    let crypt_v1 = IronCrypt::new(config_v1, DataType::Generic).await.unwrap();
    let encrypted_data_v1 = crypt_v1.encrypt_password(STRONG_PASSWORD).unwrap();

    // 2. Create a new key version (v2)
    let mut config_v2 = IronCryptConfig::default();
    config_v2.rsa_key_size = 2048; // Can be different
    data_type_config.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v2".to_string(),
        },
    );
    config_v2.data_type_config = Some(data_type_config.clone());
    let _crypt_v2 = IronCrypt::new(config_v2, DataType::Generic).await.unwrap();

    // 3. Load the new public key
    let new_pub_key_path = format!("{key_dir}/public_key_v2.pem");
    let new_pub_key = ironcrypt::load_public_key(&new_pub_key_path).unwrap();

    // 4. Re-encrypt the data from v1 to v2
    let re_encrypted_data = crypt_v1
        .re_encrypt_data(&encrypted_data_v1, &new_pub_key, "v2")
        .unwrap();

    // 5. Verify with the new key
    let mut config_v2_verify = IronCryptConfig::default();
    let mut data_type_config = ironcrypt::config::DataTypeConfig::new();
    data_type_config.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v2".to_string(),
        },
    );
    config_v2_verify.data_type_config = Some(data_type_config);
    let crypt_v2_verify = IronCrypt::new(config_v2_verify, DataType::Generic).await.unwrap();
    let is_valid = crypt_v2_verify
        .verify_password(&re_encrypted_data, STRONG_PASSWORD)
        .unwrap();
    assert!(is_valid);

    // Cleanup
    fs::remove_dir_all(key_dir).unwrap();
}

use ironcrypt::{encrypt_stream, decrypt_stream, load_public_key, load_private_key, PasswordCriteria, Argon2Config};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::Read;

#[test]
fn test_stream_encryption_large_file() {
    let key_dir = "test_keys_stream";
    setup_test_dir(key_dir);

    // --- Test file setup ---
    let input_file_path = "large_input.bin";
    let encrypted_file_path = "large_input.enc";
    let decrypted_file_path = "large_input.dec.bin";
    let file_size = 5 * 1024 * 1024; // 5 MB
    let mut big_data = vec![0; file_size];
    rand::thread_rng().fill_bytes(&mut big_data);
    fs::write(input_file_path, &big_data).unwrap();

    // --- Key setup ---
    let (private_key, public_key) = ironcrypt::generate_rsa_keys(2048).unwrap();
    let private_key_path = format!("{}/private_key_v1.pem", key_dir);
    let public_key_path = format!("{}/public_key_v1.pem", key_dir);
    ironcrypt::save_keys_to_files(&private_key, &public_key, &private_key_path, &public_key_path).unwrap();


    // --- Encryption ---
    let mut source = fs::File::open(input_file_path).unwrap();
    let mut dest = fs::File::create(encrypted_file_path).unwrap();
    let loaded_public_key = load_public_key(&public_key_path).unwrap();
    let mut password = STRONG_PASSWORD.to_string();

    let criteria = PasswordCriteria::default();
    let argon_cfg = Argon2Config::default();

    encrypt_stream(
        &mut source,
        &mut dest,
        &mut password,
        &loaded_public_key,
        &criteria,
        "v1",
        argon_cfg,
        true,
    ).unwrap();

    // --- Decryption ---
    let mut encrypted_source = fs::File::open(encrypted_file_path).unwrap();
    let mut decrypted_dest = fs::File::create(decrypted_file_path).unwrap();
    let loaded_private_key = load_private_key(&private_key_path).unwrap();

    decrypt_stream(
        &mut encrypted_source,
        &mut decrypted_dest,
        &loaded_private_key,
        STRONG_PASSWORD,
    ).unwrap();

    // --- Verification ---
    let mut original_hasher = Sha256::new();
    let mut original_file = fs::File::open(input_file_path).unwrap();
    let mut buffer = [0; 8192];
    loop {
        let n = original_file.read(&mut buffer).unwrap();
        if n == 0 { break; }
        original_hasher.update(&buffer[..n]);
    }
    let original_hash = original_hasher.finalize();

    let mut decrypted_hasher = Sha256::new();
    let mut decrypted_file = fs::File::open(decrypted_file_path).unwrap();
    loop {
        let n = decrypted_file.read(&mut buffer).unwrap();
        if n == 0 { break; }
        decrypted_hasher.update(&buffer[..n]);
    }
    let decrypted_hash = decrypted_hasher.finalize();

    assert_eq!(original_hash, decrypted_hash);

    // --- Cleanup ---
    fs::remove_file(input_file_path).unwrap();
    fs::remove_file(encrypted_file_path).unwrap();
    fs::remove_file(decrypted_file_path).unwrap();
    fs::remove_dir_all(key_dir).unwrap();
}

#[tokio::test]
async fn test_load_pkcs1_and_pkcs8_keys() {
    let key_dir = "test_keys_format";
    setup_test_dir(key_dir);

    // Generate PKCS#1 (v1) private key and write to PEM
    let mut rng = OsRng;
    let pkcs1_priv = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pkcs1_priv_pem = pkcs1_priv.to_pkcs1_pem(Default::default()).unwrap();
    fs::write(format!("{key_dir}/private_key_v1.pem"), pkcs1_priv_pem.as_bytes()).unwrap();

    // Generate matching public key (PKCS#1) for v1
    let pkcs1_pub = RsaPublicKey::from(&pkcs1_priv);
    let pkcs1_pub_pem = pkcs1_pub.to_pkcs1_pem(Default::default()).unwrap();
    fs::write(format!("{key_dir}/public_key_v1.pem"), pkcs1_pub_pem.as_bytes()).unwrap();

    // Generate PKCS#8 (v2) private key and write to PEM
    let pkcs8_priv = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pkcs8_priv_pem = pkcs8_priv.to_pkcs8_pem(Default::default()).unwrap();
    fs::write(format!("{key_dir}/private_key_v2.pem"), pkcs8_priv_pem.as_bytes()).unwrap();

    // Generate matching public key (PKCS#1) for v2
    let pkcs8_pub = RsaPublicKey::from(&pkcs8_priv);
    let pkcs8_pub_pem = pkcs8_pub.to_pkcs1_pem(Default::default()).unwrap();
    fs::write(format!("{key_dir}/public_key_v2.pem"), pkcs8_pub_pem.as_bytes()).unwrap();

    // Test PKCS#1
    let mut config_v1 = IronCryptConfig::default();
    let mut data_type_config = ironcrypt::config::DataTypeConfig::new();
    data_type_config.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v1".to_string(),
        },
    );
    config_v1.data_type_config = Some(data_type_config.clone());
    let crypt_v1 = IronCrypt::new(config_v1, DataType::Generic).await.unwrap();
    let encrypted_v1 = crypt_v1.encrypt_password(STRONG_PASSWORD).unwrap();
    assert!(crypt_v1.verify_password(&encrypted_v1, STRONG_PASSWORD).unwrap());

    // Test PKCS#8
    let mut config_v2 = IronCryptConfig::default();
    data_type_config.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v2".to_string(),
        },
    );
    config_v2.data_type_config = Some(data_type_config);
    let crypt_v2 = IronCrypt::new(config_v2, DataType::Generic).await.unwrap();
    let encrypted_v2 = crypt_v2.encrypt_password(STRONG_PASSWORD).unwrap();
    assert!(crypt_v2.verify_password(&encrypted_v2, STRONG_PASSWORD).unwrap());

    // Cleanup
    fs::remove_dir_all(key_dir).unwrap();
}
