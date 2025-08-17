use ironcrypt::{IronCrypt, IronCryptConfig, SecretStore};
use mockall::mock;
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
        key_dir.path().to_str().unwrap(),
        "v1",
        config,
        Box::new(mock_store),
    );

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
