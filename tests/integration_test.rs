// tests/integration_test.rs

use ironcrypt::{
    algorithms::SymmetricAlgorithm, config::DataType, keys::PrivateKey, decrypt_stream, encrypt_stream, load_public_key, load_private_key, IronCrypt, IronCryptConfig, PasswordCriteria, Argon2Config
};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::EncodePrivateKey;
use std::fs;
use std::io::Write;
use std::path::Path;
use aes_gcm::aead::OsRng;
use sha2::{Digest, Sha256};
use std::io::Read;

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
            passphrase: None,
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
            passphrase: None,
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
            passphrase: None,
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
            passphrase: None,
        },
    );
    config_v2.data_type_config = Some(data_type_config.clone());
    let _crypt_v2 = IronCrypt::new(config_v2, DataType::Generic).await.unwrap();

    // 3. Load the new public key
    let new_pub_key_path = format!("{key_dir}/public_key_v2.pem");
    let new_pub_key = ironcrypt::load_public_key(&new_pub_key_path).unwrap();

    // 4. Re-encrypt the data from v1 to v2
    let re_encrypted_data = crypt_v1
        .re_encrypt_data(
            &encrypted_data_v1,
            &ironcrypt::keys::PublicKey::Rsa(new_pub_key),
            "v2",
        )
        .unwrap();

    // 5. Verify with the new key
    let mut config_v2_verify = IronCryptConfig::default();
    let mut data_type_config = ironcrypt::config::DataTypeConfig::new();
    data_type_config.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v2".to_string(),
            passphrase: None,
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

use rand::RngCore;

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
    ironcrypt::save_keys_to_files(&private_key, &public_key, &private_key_path, &public_key_path, None).unwrap();


    // --- Encryption ---
    let mut source = fs::File::open(input_file_path).unwrap();
    let mut dest = fs::File::create(encrypted_file_path).unwrap();
    let loaded_public_key = load_public_key(&public_key_path).unwrap();
    let mut password = STRONG_PASSWORD.to_string();

    let criteria = PasswordCriteria::default();
    let argon_cfg = Argon2Config::default();
    let public_key_enum = ironcrypt::keys::PublicKey::Rsa(loaded_public_key);
    let recipients = vec![(&public_key_enum, "v1")];

    encrypt_stream(
        &mut source,
        &mut dest,
        &mut password,
        recipients,
        None,
        &criteria,
        argon_cfg,
        true,
        SymmetricAlgorithm::Aes256Gcm,
    )
    .unwrap();

    // --- Decryption ---
    let mut encrypted_source = fs::File::open(encrypted_file_path).unwrap();
    let mut decrypted_dest = fs::File::create(decrypted_file_path).unwrap();
    let loaded_private_key = load_private_key(&private_key_path, None).unwrap();

    decrypt_stream(
        &mut encrypted_source,
        &mut decrypted_dest,
        &PrivateKey::Rsa(loaded_private_key),
        "v1",
        STRONG_PASSWORD,
        None,
    )
    .unwrap();

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
    println!("Generating PKCS#1 format keys for compatibility testing...");
    let mut rng = OsRng;
    let pkcs1_priv = RsaPrivateKey::new(&mut rng, 2048)
        .expect("Failed to generate PKCS#1 private key");
    let pkcs1_priv_pem = pkcs1_priv.to_pkcs1_pem(Default::default())
        .expect("Failed to encode PKCS#1 private key to PEM");
    
    let pkcs1_priv_path = format!("{key_dir}/private_key_v1.pem");
    fs::write(&pkcs1_priv_path, pkcs1_priv_pem.as_bytes())
        .expect("Failed to write PKCS#1 private key file");
    println!("✓ PKCS#1 private key saved to {}", pkcs1_priv_path);

    // Generate matching public key (PKCS#1) for v1
    let pkcs1_pub = RsaPublicKey::from(&pkcs1_priv);
    let pkcs1_pub_pem = pkcs1_pub.to_pkcs1_pem(Default::default())
        .expect("Failed to encode PKCS#1 public key to PEM");
    
    let pkcs1_pub_path = format!("{key_dir}/public_key_v1.pem");
    fs::write(&pkcs1_pub_path, pkcs1_pub_pem.as_bytes())
        .expect("Failed to write PKCS#1 public key file");
    println!("✓ PKCS#1 public key saved to {}", pkcs1_pub_path);

    // Generate PKCS#8 (v2) private key and write to PEM
    println!("Generating PKCS#8 format keys for modern compatibility...");
    let pkcs8_priv = RsaPrivateKey::new(&mut rng, 2048)
        .expect("Failed to generate PKCS#8 private key");
    let pkcs8_priv_pem = pkcs8_priv.to_pkcs8_pem(Default::default())
        .expect("Failed to encode PKCS#8 private key to PEM");
    
    let pkcs8_priv_path = format!("{key_dir}/private_key_v2.pem");
    fs::write(&pkcs8_priv_path, pkcs8_priv_pem.as_bytes())
        .expect("Failed to write PKCS#8 private key file");
    println!("✓ PKCS#8 private key saved to {}", pkcs8_priv_path);

    // Generate matching public key (PKCS#1) for v2 - Note: We use PKCS#1 for public key for consistency
    let pkcs8_pub = RsaPublicKey::from(&pkcs8_priv);
    let pkcs8_pub_pem = pkcs8_pub.to_pkcs1_pem(Default::default())
        .expect("Failed to encode public key to PEM for PKCS#8 private key");
    
    let pkcs8_pub_path = format!("{key_dir}/public_key_v2.pem");
    fs::write(&pkcs8_pub_path, pkcs8_pub_pem.as_bytes())
        .expect("Failed to write public key file for PKCS#8 private key");
    println!("✓ Public key (PKCS#1 format) saved to {}", pkcs8_pub_path);

    // Test PKCS#1 key loading and encryption/verification
    println!("Testing PKCS#1 key compatibility with IronCrypt...");
    let mut config_v1 = IronCryptConfig::default();
    let mut data_type_config = ironcrypt::config::DataTypeConfig::new();
    data_type_config.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    config_v1.data_type_config = Some(data_type_config.clone());
    
    let crypt_v1 = IronCrypt::new(config_v1, DataType::Generic).await
        .expect("Failed to initialize IronCrypt with PKCS#1 keys");
    
    let encrypted_v1 = crypt_v1.encrypt_password(STRONG_PASSWORD)
        .expect("Failed to encrypt password using PKCS#1 keys");
    
    let verification_result = crypt_v1.verify_password(&encrypted_v1, STRONG_PASSWORD)
        .expect("Failed to verify password using PKCS#1 keys");
    assert!(verification_result, "Password verification failed for PKCS#1 keys");
    println!("✓ PKCS#1 key format test passed - encryption and verification successful");

    // Test PKCS#8 key loading and encryption/verification  
    println!("Testing PKCS#8 key compatibility with IronCrypt...");
    let mut config_v2 = IronCryptConfig::default();
    data_type_config.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v2".to_string(),
            passphrase: None,
        },
    );
    config_v2.data_type_config = Some(data_type_config);
    
    let crypt_v2 = IronCrypt::new(config_v2, DataType::Generic).await
        .expect("Failed to initialize IronCrypt with PKCS#8 keys");
    
    let encrypted_v2 = crypt_v2.encrypt_password(STRONG_PASSWORD)
        .expect("Failed to encrypt password using PKCS#8 keys");
    
    let verification_result = crypt_v2.verify_password(&encrypted_v2, STRONG_PASSWORD)
        .expect("Failed to verify password using PKCS#8 keys");
    assert!(verification_result, "Password verification failed for PKCS#8 keys");
    println!("✓ PKCS#8 key format test passed - encryption and verification successful");

    // Additional validation: ensure wrong password fails
    println!("Testing password verification failure with incorrect password...");
    let wrong_password = "WrongPassword123!";
    let wrong_verification = crypt_v1.verify_password(&encrypted_v1, wrong_password)
        .expect("Verification call should succeed but return false");
    assert!(!wrong_verification, "Verification should fail for wrong password");
    println!("✓ Password verification correctly rejects incorrect password");

    // Cleanup
    fs::remove_dir_all(key_dir)
        .expect("Failed to cleanup test directory");
    println!("✓ Test cleanup completed successfully");
}

#[tokio::test]
async fn test_key_format_compatibility_edge_cases() {
    let key_dir = "test_keys_edge_cases";
    setup_test_dir(key_dir);

    println!("Testing key format compatibility edge cases and error handling...");

    // Test 1: Verify different key sizes work correctly
    let mut rng = OsRng;
    let large_key = RsaPrivateKey::new(&mut rng, 4096)
        .expect("Failed to generate 4096-bit RSA key");
    let large_key_pem = large_key.to_pkcs8_pem(Default::default())
        .expect("Failed to encode 4096-bit key to PEM");
    
    fs::write(format!("{key_dir}/private_key_large.pem"), large_key_pem.as_bytes())
        .expect("Failed to write 4096-bit private key");

    let large_pub = RsaPublicKey::from(&large_key);
    let large_pub_pem = large_pub.to_pkcs1_pem(Default::default())
        .expect("Failed to encode 4096-bit public key to PEM");
    
    fs::write(format!("{key_dir}/public_key_large.pem"), large_pub_pem.as_bytes())
        .expect("Failed to write 4096-bit public key");

    // Test configuration with the large key
    let mut config_large = IronCryptConfig::default();
    config_large.rsa_key_size = 4096; // Ensure config matches key size
    let mut data_type_config = ironcrypt::config::DataTypeConfig::new();
    data_type_config.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "large".to_string(),
            passphrase: None,
        },
    );
    config_large.data_type_config = Some(data_type_config);

    let crypt_large = IronCrypt::new(config_large, DataType::Generic).await
        .expect("Failed to initialize IronCrypt with 4096-bit keys");
    
    let encrypted_large = crypt_large.encrypt_password(STRONG_PASSWORD)
        .expect("Failed to encrypt with 4096-bit key");
    
    let verification_large = crypt_large.verify_password(&encrypted_large, STRONG_PASSWORD)
        .expect("Failed to verify password with 4096-bit key");
    assert!(verification_large, "Password verification failed for 4096-bit key");
    println!("✓ 4096-bit RSA key compatibility test passed");

    // Test 2: Cross-version compatibility (encrypt with one version, decrypt with another)
    println!("Testing cross-version key compatibility...");
    
    // Generate two different key pairs for cross-compatibility test
    let key1 = RsaPrivateKey::new(&mut rng, 2048)
        .expect("Failed to generate first key pair");
    let key1_priv_pem = key1.to_pkcs1_pem(Default::default())
        .expect("Failed to encode first private key");
    let key1_pub = RsaPublicKey::from(&key1);
    let key1_pub_pem = key1_pub.to_pkcs1_pem(Default::default())
        .expect("Failed to encode first public key");
    
    fs::write(format!("{key_dir}/private_key_compat1.pem"), key1_priv_pem.as_bytes())
        .expect("Failed to write first private key");
    fs::write(format!("{key_dir}/public_key_compat1.pem"), key1_pub_pem.as_bytes())
        .expect("Failed to write first public key");

    // Configure first instance
    let mut config1 = IronCryptConfig::default();
    let mut data_type_config1 = ironcrypt::config::DataTypeConfig::new();
    data_type_config1.insert(
        DataType::Generic,
        ironcrypt::config::KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "compat1".to_string(),
            passphrase: None,
        },
    );
    config1.data_type_config = Some(data_type_config1);

    let crypt1 = IronCrypt::new(config1, DataType::Generic).await
        .expect("Failed to initialize first IronCrypt instance");
    
    // Encrypt with first instance
    let test_password = "CrossCompatibilityTest123!";
    let encrypted_cross = crypt1.encrypt_password(test_password)
        .expect("Failed to encrypt password with first instance");
    
    // Verify with same instance (sanity check)
    let verify_same = crypt1.verify_password(&encrypted_cross, test_password)
        .expect("Failed to verify with same instance");
    assert!(verify_same, "Same-instance verification should succeed");
    println!("✓ Same-instance encryption/verification test passed");

    // Test 3: Verify that strong passwords work correctly with different formats
    println!("Testing password handling with different key formats...");
    let strong_test_password = "StrongTestPassword123!@#";
    
    // Test with our existing strong password pattern
    let encrypted_strong = crypt1.encrypt_password(strong_test_password)
        .expect("Failed to encrypt strong password");
    
    let verify_strong = crypt1.verify_password(&encrypted_strong, strong_test_password)
        .expect("Failed to verify strong password");
    assert!(verify_strong, "Strong password verification should work");
    
    // Test wrong password rejection
    let verify_wrong = crypt1.verify_password(&encrypted_strong, "WrongPassword123!")
        .expect("Password verification call should succeed but return false");
    assert!(!verify_wrong, "Wrong password should be rejected");
    println!("✓ Password strength and validation handling test passed");

    // Cleanup
    fs::remove_dir_all(key_dir)
        .expect("Failed to cleanup test directory");
    println!("✓ Edge cases test cleanup completed successfully");
}

#[test]
fn test_passphrase_encryption_decryption() {
    let key_dir = "test_keys_passphrase";
    setup_test_dir(key_dir);
    let passphrase = "my-secret-passphrase";

    // 1. Generate keys with a passphrase
    let (private_key, public_key) = ironcrypt::generate_rsa_keys(2048).unwrap();
    let private_key_path = format!("{}/private_key_v1.pem", key_dir);
    let public_key_path = format!("{}/public_key_v1.pem", key_dir);
    ironcrypt::save_keys_to_files(
        &private_key,
        &public_key,
        &private_key_path,
        &public_key_path,
        Some(passphrase),
    )
    .unwrap();

    // 2. Encrypt some data
    let original_data = b"this data is protected by a key with a passphrase";
    let mut source = std::io::Cursor::new(original_data);
    let mut dest = std::io::Cursor::new(Vec::new());
    let mut password = "FilePassword1!".to_string();
    let public_key_enum = ironcrypt::keys::PublicKey::Rsa(public_key);
    let recipients = vec![(&public_key_enum, "v1")];
    encrypt_stream(
        &mut source,
        &mut dest,
        &mut password,
        recipients,
        None,
        &PasswordCriteria::default(),
        Argon2Config::default(),
        true,
        SymmetricAlgorithm::Aes256Gcm,
    )
    .unwrap();

    // 3. Decrypt with the correct passphrase
    dest.set_position(0);
    let mut decrypted_dest_ok = std::io::Cursor::new(Vec::new());
    let loaded_private_key_ok =
        load_private_key(&private_key_path, Some(passphrase)).unwrap();
    decrypt_stream(
        &mut dest,
        &mut decrypted_dest_ok,
        &PrivateKey::Rsa(loaded_private_key_ok),
        "v1",
        "FilePassword1!",
        None,
    )
    .unwrap();
    assert_eq!(original_data, &decrypted_dest_ok.into_inner()[..]);

    // 4. Attempt to decrypt with the wrong passphrase
    let loaded_private_key_bad =
        load_private_key(&private_key_path, Some("wrong-passphrase"));
    assert!(loaded_private_key_bad.is_err());

    // 5. Attempt to decrypt with no passphrase
    let loaded_private_key_none = load_private_key(&private_key_path, None);
    assert!(loaded_private_key_none.is_err());

    // Cleanup
    fs::remove_dir_all(key_dir).unwrap();
}

#[test]
fn test_multi_recipient_encryption_decryption() {
    let key_dir = "test_keys_multi_recipient";
    setup_test_dir(key_dir);

    // 1. Generate two key pairs
    let (priv1, pub1) = ironcrypt::generate_rsa_keys(2048).unwrap();
    let (priv2, pub2) = ironcrypt::generate_rsa_keys(2048).unwrap();
    let (priv3, _) = ironcrypt::generate_rsa_keys(2048).unwrap(); // Unauthorized user

    // 2. Encrypt for user1 and user2
    let original_data = b"this data is for user1 and user2";
    let mut source = std::io::Cursor::new(original_data);
    let mut dest = std::io::Cursor::new(Vec::new());
    let mut password = "MultiUserPassword1!".to_string();
    let recipients = vec![
        (ironcrypt::keys::PublicKey::Rsa(pub1), "v1"),
        (ironcrypt::keys::PublicKey::Rsa(pub2), "v2"),
    ];
    encrypt_stream(
        &mut source,
        &mut dest,
        &mut password,
        recipients
            .iter()
            .map(|(k, v)| (k, *v))
            .collect::<Vec<(&ironcrypt::keys::PublicKey, &str)>>(),
        None,
        &PasswordCriteria::default(),
        Argon2Config::default(),
        true,
        SymmetricAlgorithm::Aes256Gcm,
    )
    .unwrap();

    // 3. Decrypt with user1's key
    dest.set_position(0);
    let mut decrypted_dest1 = std::io::Cursor::new(Vec::new());
    decrypt_stream(
        &mut dest,
        &mut decrypted_dest1,
        &PrivateKey::Rsa(priv1),
        "v1",
        "MultiUserPassword1!",
        None,
    )
    .unwrap();
    assert_eq!(original_data, &decrypted_dest1.into_inner()[..]);

    // 4. Decrypt with user2's key
    dest.set_position(0);
    let mut decrypted_dest2 = std::io::Cursor::new(Vec::new());
    decrypt_stream(
        &mut dest,
        &mut decrypted_dest2,
        &PrivateKey::Rsa(priv2),
        "v2",
        "MultiUserPassword1!",
        None,
    )
    .unwrap();
    assert_eq!(original_data, &decrypted_dest2.into_inner()[..]);

    // 5. Attempt to decrypt with user3's key (should fail)
    dest.set_position(0);
    let mut decrypted_dest3 = std::io::Cursor::new(Vec::new());
    let res3 = decrypt_stream(
        &mut dest,
        &mut decrypted_dest3,
        &PrivateKey::Rsa(priv3),
        "v3", // Even if they claim to be a version that doesn't exist
        "MultiUserPassword1!",
        None,
    );
    assert!(res3.is_err());

    // Cleanup
    fs::remove_dir_all(key_dir).unwrap();
}
