// tests/data_type_test.rs

use ironcrypt::{
    algorithms::AsymmetricAlgorithm,
    config::{DataType, DataTypeConfig, IronCryptConfig, KeyManagementConfig},
    standards::CryptoStandard,
    IronCrypt,
};
use std::path::Path;
use tempfile::tempdir;

const STRONG_PASSWORD: &str = "Str0ngP@ssw0rd42!";

#[tokio::test]
async fn test_data_type_key_segregation() {
    let generic_dir = tempdir().unwrap();
    let pii_dir = tempdir().unwrap();
    let biometric_dir = tempdir().unwrap();

    let generic_key_dir = generic_dir.path().to_str().unwrap();
    let pii_key_dir = pii_dir.path().to_str().unwrap();
    let biometric_key_dir = biometric_dir.path().to_str().unwrap();

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
        // Avoid NIST's 3072-bit RSA in tests (very slow); keep segregation coverage.
        standard: CryptoStandard::Custom,
        asymmetric_algorithm: AsymmetricAlgorithm::Rsa,
        rsa_key_size: 2048,
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
}
