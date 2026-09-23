use ironcrypt::{
    CryptoStandard, IronCrypt, IronCryptConfig, DataType, PaymentSecurityProfile,
    config::KeyManagementConfig,
};
use std::collections::HashMap;

#[tokio::test]
async fn test_nist_standard_applies_correct_params() {
    let temp_dir = tempfile::tempdir().unwrap();
    let key_dir = temp_dir.path().to_str().unwrap();
    let mut config = IronCryptConfig {
        standard: CryptoStandard::Nist,
        ..IronCryptConfig::default()
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

    let crypt = IronCrypt::new(config, DataType::Generic).await.unwrap();

    let expected_params = CryptoStandard::Nist.get_params().unwrap();
    assert_eq!(crypt.config.symmetric_algorithm, expected_params.symmetric_algorithm);
    assert_eq!(crypt.config.asymmetric_algorithm, expected_params.asymmetric_algorithm);
    assert_eq!(crypt.config.rsa_key_size, expected_params.rsa_key_size);
}

#[tokio::test]
async fn test_fips_compatible_profile_applies_correct_params() {
    let temp_dir = tempfile::tempdir().unwrap();
    let key_dir = temp_dir.path().to_str().unwrap();
    let mut config = IronCryptConfig {
        standard: CryptoStandard::FipsCompatibleProfile,
        ..IronCryptConfig::default()
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

    let crypt = IronCrypt::new(config, DataType::Generic).await.unwrap();

    let expected_params = CryptoStandard::FipsCompatibleProfile.get_params().unwrap();
    assert_eq!(crypt.config.symmetric_algorithm, expected_params.symmetric_algorithm);
    assert_eq!(crypt.config.asymmetric_algorithm, expected_params.asymmetric_algorithm);
    assert_eq!(crypt.config.rsa_key_size, expected_params.rsa_key_size);
}

#[tokio::test]
async fn test_custom_standard_retains_user_params() {
    let temp_dir = tempfile::tempdir().unwrap();
    let key_dir = temp_dir.path().to_str().unwrap();
    let mut config = IronCryptConfig {
        standard: CryptoStandard::Custom,
        symmetric_algorithm: ironcrypt::algorithms::SymmetricAlgorithm::ChaCha20Poly1305,
        asymmetric_algorithm: ironcrypt::algorithms::AsymmetricAlgorithm::Ecc,
        rsa_key_size: 4096,
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

    let crypt = IronCrypt::new(config.clone(), DataType::Generic).await.unwrap();

    assert_eq!(crypt.config.standard, CryptoStandard::Custom);
    assert_eq!(crypt.config.symmetric_algorithm, config.symmetric_algorithm);
    assert_eq!(crypt.config.asymmetric_algorithm, config.asymmetric_algorithm);
    assert_eq!(crypt.config.rsa_key_size, config.rsa_key_size);
}

#[tokio::test]
async fn test_anssi_compatible_profile_applies_correct_params() {
    let temp_dir = tempfile::tempdir().unwrap();
    let key_dir = temp_dir.path().to_str().unwrap();
    let mut config = IronCryptConfig {
        standard: CryptoStandard::AnssiCompatibleProfile,
        ..IronCryptConfig::default()
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

    let crypt = IronCrypt::new(config, DataType::Generic).await.unwrap();

    let expected_params = CryptoStandard::AnssiCompatibleProfile.get_params().unwrap();
    assert_eq!(crypt.config.symmetric_algorithm, expected_params.symmetric_algorithm);
    assert_eq!(crypt.config.asymmetric_algorithm, expected_params.asymmetric_algorithm);
    assert_eq!(crypt.config.rsa_key_size, expected_params.rsa_key_size);
}

#[test]
fn payment_profile_rejects_custom() {
    let mut config = IronCryptConfig::default();
    config.standard = CryptoStandard::Custom;
    assert!(PaymentSecurityProfile::validate(&config).is_err());
}

#[test]
fn payment_profile_enforce_locks_ecc() {
    let mut config = IronCryptConfig::default();
    PaymentSecurityProfile::enforce(&mut config).unwrap();
    assert_eq!(
        config.asymmetric_algorithm,
        ironcrypt::algorithms::AsymmetricAlgorithm::Ecc
    );
    assert_eq!(config.standard, CryptoStandard::PaymentCompatible);
}

#[test]
fn historical_fips140_2_toml_alias_deserializes() {
    let toml = r#"
standard = "Fips140_2"
rsa_key_size = 3072
buffer_size = 4096
argon2_memory_cost = 65536
argon2_time_cost = 3
argon2_parallelism = 1
"#;
    // Minimal parse via serde on the enum alone
    #[derive(serde::Deserialize)]
    struct Wrap {
        standard: CryptoStandard,
    }
    let w: Wrap = toml::from_str(toml).unwrap();
    assert_eq!(w.standard, CryptoStandard::FipsCompatibleProfile);
}
