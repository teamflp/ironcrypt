//! Multi-tenant EncryptionContext isolation.

use ironcrypt::{
    algorithms::AsymmetricAlgorithm,
    config::{DataType, DataTypeConfig, IronCryptConfig, KeyManagementConfig},
    EncryptionContext, IronCrypt, IronCryptError,
};
use tempfile::tempdir;

const STRONG_PASSWORD: &str = "Str0ngP@ssw0rd42!";

#[tokio::test]
async fn tenant_a_ciphertext_not_decryptable_as_tenant_b() {
    let dir = tempdir().unwrap();
    let mut config = IronCryptConfig::default();
    config.asymmetric_algorithm = AsymmetricAlgorithm::Ecc;
    let mut dt = DataTypeConfig::new();
    dt.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: dir.path().to_str().unwrap().to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    config.data_type_config = Some(dt);
    let crypt = IronCrypt::new(config, DataType::Generic).await.unwrap();

    let ctx_a = EncryptionContext::new("merchant-a", "card-pan", "txn-1");
    let enc = crypt
        .encrypt_with_context(b"4111111111111111", STRONG_PASSWORD, Some(&ctx_a))
        .await
        .unwrap();

    let ctx_b = EncryptionContext::new("merchant-b", "card-pan", "txn-1");
    let err = crypt
        .decrypt_with_context(&enc, STRONG_PASSWORD, Some(&ctx_b))
        .await
        .unwrap_err();
    assert!(matches!(err, IronCryptError::DecryptionError(_)));

    let plain = crypt
        .decrypt_with_context(&enc, STRONG_PASSWORD, Some(&ctx_a))
        .await
        .unwrap();
    assert_eq!(plain, b"4111111111111111");
}
