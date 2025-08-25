use ironcrypt::{CryptoStandard, IronCrypt, IronCryptConfig, DataType, config::KeyManagementConfig};
use std::collections::HashMap;

#[tokio::test]
async fn test_nist_standard_applies_correct_params() {
    // Arrange
    let temp_dir = tempfile::tempdir().unwrap();
    let key_dir = temp_dir.path().to_str().unwrap();
    let mut config = IronCryptConfig::default();
    config.standard = CryptoStandard::Nist;

    let mut data_type_config = HashMap::new();
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    config.data_type_config = Some(data_type_config);

    // Act
    let crypt = IronCrypt::new(config, DataType::Generic).await.unwrap();

    // Assert
    let expected_params = CryptoStandard::Nist.get_params().unwrap();
    assert_eq!(crypt.config.symmetric_algorithm, expected_params.symmetric_algorithm);
    assert_eq!(crypt.config.asymmetric_algorithm, expected_params.asymmetric_algorithm);
    assert_eq!(crypt.config.rsa_key_size, expected_params.rsa_key_size);
}

#[tokio::test]
async fn test_fips_standard_applies_correct_params() {
    // Arrange
    let temp_dir = tempfile::tempdir().unwrap();
    let key_dir = temp_dir.path().to_str().unwrap();
    let mut config = IronCryptConfig::default();
    config.standard = CryptoStandard::Fips140_2;

    let mut data_type_config = HashMap::new();
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    config.data_type_config = Some(data_type_config);

    // Act
    let crypt = IronCrypt::new(config, DataType::Generic).await.unwrap();

    // Assert
    let expected_params = CryptoStandard::Fips140_2.get_params().unwrap();
    assert_eq!(crypt.config.symmetric_algorithm, expected_params.symmetric_algorithm);
    assert_eq!(crypt.config.asymmetric_algorithm, expected_params.asymmetric_algorithm);
    assert_eq!(crypt.config.rsa_key_size, expected_params.rsa_key_size);
}

#[tokio::test]
async fn test_custom_standard_retains_user_params() {
    // Arrange
    let temp_dir = tempfile::tempdir().unwrap();
    let key_dir = temp_dir.path().to_str().unwrap();
    let mut config = IronCryptConfig {
        standard: CryptoStandard::Custom,
        symmetric_algorithm: ironcrypt::algorithms::SymmetricAlgorithm::ChaCha20Poly1305,
        asymmetric_algorithm: ironcrypt::algorithms::AsymmetricAlgorithm::Ecc,
        rsa_key_size: 4096, // This will be ignored for ECC, but we test it's not overwritten
        ..Default::default()
    };

    let mut data_type_config = HashMap::new();
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: key_dir.to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    config.data_type_config = Some(data_type_config);

    // Act
    let crypt = IronCrypt::new(config.clone(), DataType::Generic).await.unwrap();

    // Assert
    assert_eq!(crypt.config.standard, CryptoStandard::Custom);
    assert_eq!(crypt.config.symmetric_algorithm, config.symmetric_algorithm);
    assert_eq!(crypt.config.asymmetric_algorithm, config.asymmetric_algorithm);
    assert_eq!(crypt.config.rsa_key_size, config.rsa_key_size);
}
