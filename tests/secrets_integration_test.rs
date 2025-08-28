use ironcrypt::{
    config::{AwsConfig, AzureConfig, KeyManagementConfig, SecretsConfig},
    DataType, IronCrypt, IronCryptConfig, SecretStore,
};
#[cfg(feature = "gcp")]
use ironcrypt::GoogleConfig;
use mockall::mock;
use std::collections::HashMap;
use std::error::Error;

mock! {
    pub SecretStore {}

    #[async_trait::async_trait]
    impl SecretStore for SecretStore {
        async fn get_secret(&self, key: &str) -> Result<String, Box<dyn Error + Send + Sync>>;
        async fn set_secret(&self, key: &str, value: &str) -> Result<(), Box<dyn Error + Send + Sync>>;
    }
}

#[tokio::test]
async fn test_secret_store_integration_with_mock() {
    let key_dir = tempfile::tempdir().unwrap();
    let config = IronCryptConfig::default();

    let secret_key = "my-test-secret";
    let secret_value = "this is a very secret value";

    let mut mock_store = MockSecretStore::new();

    // Expect `set_secret` to be called once with the correct arguments.
    mock_store
        .expect_set_secret()
        .withf(move |key, value| key == secret_key && value == secret_value)
        .times(1)
        .returning(|_, _| Ok(()));

    // Expect `get_secret` to be called once and return the secret value.
    mock_store
        .expect_get_secret()
        .withf(move |key| key == secret_key)
        .times(1)
        .returning(move |_| Ok(secret_value.to_string()));

    // Create an IronCrypt instance with the mock store.
    let ironcrypt = IronCrypt::with_store(
        config,
        DataType::Generic,
        Box::new(mock_store),
        key_dir.path().to_str().unwrap().to_string(),
        "v1".to_string(),
    );
    let ironcrypt = ironcrypt.expect("Failed to create IronCrypt instance with mock store");

    // Store the secret.
    ironcrypt
        .store_secret(secret_key, secret_value)
        .await
        .unwrap();

    // Retrieve the secret.
    let retrieved_secret = ironcrypt.retrieve_secret(secret_key).await.unwrap();

    // Assert that the retrieved secret is correct.
    assert_eq!(secret_value, retrieved_secret);
}

#[tokio::test]
async fn test_aws_provider_initialization() {
    let key_dir = tempfile::tempdir().unwrap();
    let mut data_type_config = HashMap::new();
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: key_dir.path().to_str().unwrap().to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );

    let config = IronCryptConfig {
        secrets: Some(SecretsConfig {
            provider: "aws".to_string(),
            vault: None,
            aws: Some(AwsConfig {
                region: "us-east-1".to_string(),
            }),
            azure: None,
            google: None,
        }),
        data_type_config: Some(data_type_config),
        ..Default::default()
    };

    // This test just checks that the AWS client can be initialized without panicking.
    // It doesn't make any real calls to AWS.
    let ironcrypt = IronCrypt::new(config, DataType::Generic)
        .await;

    assert!(ironcrypt.is_ok());
}

#[cfg(feature = "gcp")]
#[tokio::test]
async fn test_google_provider_initialization() {
    let key_dir = tempfile::tempdir().unwrap();
    let mut data_type_config = HashMap::new();
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: key_dir.path().to_str().unwrap().to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );

    let config = IronCryptConfig {
        secrets: Some(SecretsConfig {
            provider: "google".to_string(),
            vault: None,
            aws: None,
            azure: None,
            google: Some(GoogleConfig {
                project_id: "dummy-project".to_string(),
            }),
        }),
        data_type_config: Some(data_type_config),
        ..Default::default()
    };

    // This test just checks that the Google client can be initialized without panicking.
    // It doesn't make any real calls to Google Cloud.
    let ironcrypt = IronCrypt::new(config, DataType::Generic)
        .await;

    assert!(ironcrypt.is_ok());
}

#[tokio::test]
async fn test_azure_provider_initialization() {
    let key_dir = tempfile::tempdir().unwrap();
    let mut data_type_config = HashMap::new();
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: key_dir.path().to_str().unwrap().to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );

    let config = IronCryptConfig {
        secrets: Some(SecretsConfig {
            provider: "azure".to_string(),
            vault: None,
            aws: None,
            azure: Some(AzureConfig {
                vault_uri: "https://dummy.vault.azure.net".to_string(),
            }),
            google: None,
        }),
        data_type_config: Some(data_type_config),
        ..Default::default()
    };

    // This test just checks that the Azure client can be initialized without panicking.
    // It doesn't make any real calls to Azure.
    let ironcrypt = IronCrypt::new(config, DataType::Generic)
        .await;

    assert!(ironcrypt.is_ok());
}
