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

    // Payment refuses recoverable password ciphertext. The roundtrip still
    // has to exercise the data-type key, so that profile uses encrypt_secret.
    async fn roundtrip(crypt: &IronCrypt, record: &str) {
        #[cfg(feature = "payment")]
        {
            let ctx = ironcrypt::EncryptionContext::new("tenant", "secret", record);
            let encrypted = crypt
                .encrypt_secret(b"opaque-record-payload", STRONG_PASSWORD, Some(&ctx))
                .await
                .unwrap();
            let plain = crypt
                .decrypt_secret(&encrypted, STRONG_PASSWORD, Some(&ctx))
                .await
                .unwrap();
            assert_eq!(plain, b"opaque-record-payload");
        }
        #[cfg(not(feature = "payment"))]
        {
            let _ = record;
            let encrypted = crypt.encrypt_password(STRONG_PASSWORD).unwrap();
            assert!(crypt.verify_password(&encrypted, STRONG_PASSWORD).unwrap());
        }
    }

    // Test Generic
    let crypt_generic = IronCrypt::new(config.clone(), DataType::Generic)
        .await
        .unwrap();
    roundtrip(&crypt_generic, "generic").await;
    assert!(Path::new(&format!("{}/private_key_v1.pem", generic_key_dir)).exists());
    assert!(!Path::new(&format!("{}/private_key_v1.pem", pii_key_dir)).exists());
    assert!(!Path::new(&format!("{}/private_key_v1.pem", biometric_key_dir)).exists());

    // Test Pii
    let crypt_pii = IronCrypt::new(config.clone(), DataType::Pii).await.unwrap();
    roundtrip(&crypt_pii, "pii").await;
    assert!(Path::new(&format!("{}/private_key_v1.pem", pii_key_dir)).exists());

    // Test Biometric
    let crypt_bio = IronCrypt::new(config.clone(), DataType::Biometric)
        .await
        .unwrap();
    roundtrip(&crypt_bio, "bio").await;
    assert!(Path::new(&format!("{}/private_key_v1.pem", biometric_key_dir)).exists());
}
