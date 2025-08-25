// tests/data_type_test.rs

use ironcrypt::{
    config::{DataType, DataTypeConfig, IronCryptConfig, KeyManagementConfig},
    IronCrypt,
};
use std::fs;
use std::path::Path;

const STRONG_PASSWORD: &str = "Str0ngP@ssw0rd42!";

fn setup_test_dir(dir: &str) {
    if Path::new(dir).exists() {
        fs::remove_dir_all(dir).unwrap();
    }
    fs::create_dir_all(dir).unwrap();
}

#[tokio::test]
async fn test_data_type_key_segregation() {
    let generic_key_dir = "test_keys_generic";
    let pii_key_dir = "test_keys_pii";
    let biometric_key_dir = "test_keys_bio";

    setup_test_dir(generic_key_dir);
    setup_test_dir(pii_key_dir);
    setup_test_dir(biometric_key_dir);

    let mut data_type_config = DataTypeConfig::new();
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: generic_key_dir.to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    data_type_config.insert(
        DataType::Pii,
        KeyManagementConfig {
            key_directory: pii_key_dir.to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    data_type_config.insert(
        DataType::Biometric,
        KeyManagementConfig {
            key_directory: biometric_key_dir.to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );

    let config = IronCryptConfig {
        data_type_config: Some(data_type_config),
        ..Default::default()
    };

    // Test Generic
    let crypt_generic = IronCrypt::new(config.clone(), DataType::Generic)
        .await
        .unwrap();
    let encrypted_generic = crypt_generic
        .encrypt_password(STRONG_PASSWORD)
        .unwrap();
    assert!(crypt_generic
        .verify_password(&encrypted_generic, STRONG_PASSWORD)
        .unwrap());
    assert!(Path::new(&format!("{}/private_key_v1.pem", generic_key_dir)).exists());
    assert!(!Path::new(&format!("{}/private_key_v1.pem", pii_key_dir)).exists());
    assert!(!Path::new(&format!("{}/private_key_v1.pem", biometric_key_dir)).exists());

    // Test Pii
    let crypt_pii = IronCrypt::new(config.clone(), DataType::Pii).await.unwrap();
    let encrypted_pii = crypt_pii.encrypt_password(STRONG_PASSWORD).unwrap();
    assert!(crypt_pii
        .verify_password(&encrypted_pii, STRONG_PASSWORD)
        .unwrap());
    assert!(Path::new(&format!("{}/private_key_v1.pem", pii_key_dir)).exists());

    // Test Biometric
    let crypt_bio = IronCrypt::new(config.clone(), DataType::Biometric)
        .await
        .unwrap();
    let encrypted_bio = crypt_bio.encrypt_password(STRONG_PASSWORD).unwrap();
    assert!(crypt_bio
        .verify_password(&encrypted_bio, STRONG_PASSWORD)
        .unwrap());
    assert!(Path::new(&format!("{}/private_key_v1.pem", biometric_key_dir)).exists());

    // Cleanup
    fs::remove_dir_all(generic_key_dir).unwrap();
    fs::remove_dir_all(pii_key_dir).unwrap();
    fs::remove_dir_all(biometric_key_dir).unwrap();
}
