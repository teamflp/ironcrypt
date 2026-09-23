//! AAD substitution and ciphertext corruption tests (Lot 5).

use ironcrypt::{
    algorithms::AsymmetricAlgorithm,
    config::{DataType, DataTypeConfig, IronCryptConfig, KeyManagementConfig},
    EncryptionContext, IronCrypt, IronCryptError,
};
use tempfile::tempdir;

const STRONG_PASSWORD: &str = "Str0ngP@ssw0rd42!";

async fn crypt_with_keys(dir: &str) -> IronCrypt {
    let mut config = IronCryptConfig::default();
    config.asymmetric_algorithm = AsymmetricAlgorithm::Ecc;
    let mut dt = DataTypeConfig::new();
    dt.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: dir.to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    config.data_type_config = Some(dt);
    IronCrypt::new(config, DataType::Generic)
        .await
        .expect("IronCrypt")
}

#[tokio::test]
async fn decrypt_rejects_substituted_encryption_context() {
    let dir = tempdir().unwrap();
    let crypt = crypt_with_keys(dir.path().to_str().unwrap()).await;
    let ctx = EncryptionContext::new("tenant-a", "card-pan", "rec-1");
    let enc = crypt
        .encrypt_with_context(b"4111111111111111", STRONG_PASSWORD, Some(&ctx))
        .await
        .unwrap();

    let wrong = EncryptionContext::new("tenant-b", "card-pan", "rec-1");
    let err = crypt
        .decrypt_with_context(&enc, STRONG_PASSWORD, Some(&wrong))
        .await
        .unwrap_err();
    assert!(
        matches!(err, IronCryptError::DecryptionError(_)),
        "expected context mismatch, got {err:?}"
    );
}

#[tokio::test]
async fn decrypt_rejects_bit_flipped_ciphertext() {
    let dir = tempdir().unwrap();
    let crypt = crypt_with_keys(dir.path().to_str().unwrap()).await;
    let ctx = EncryptionContext::new("t", "p", "r");
    let enc = crypt
        .encrypt_with_context(b"secret-payload", STRONG_PASSWORD, Some(&ctx))
        .await
        .unwrap();

    let mut value: serde_json::Value = serde_json::from_str(&enc).unwrap();
    let ct = value["ciphertext"].as_str().unwrap().to_string();
    let mut bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        ct.as_bytes(),
    )
    .unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    value["ciphertext"] = serde_json::Value::String(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &bytes,
    ));
    let tampered = serde_json::to_string(&value).unwrap();

    assert!(crypt
        .decrypt_with_context(&tampered, STRONG_PASSWORD, Some(&ctx))
        .await
        .is_err());
}

#[tokio::test]
async fn decrypt_rejects_truncated_ciphertext() {
    let dir = tempdir().unwrap();
    let crypt = crypt_with_keys(dir.path().to_str().unwrap()).await;
    let ctx = EncryptionContext::new("t", "p", "r");
    let enc = crypt
        .encrypt_with_context(b"secret-payload", STRONG_PASSWORD, Some(&ctx))
        .await
        .unwrap();

    let mut value: serde_json::Value = serde_json::from_str(&enc).unwrap();
    let ct = value["ciphertext"].as_str().unwrap().to_string();
    let mut bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        ct.as_bytes(),
    )
    .unwrap();
    bytes.truncate(bytes.len().saturating_sub(4));
    value["ciphertext"] = serde_json::Value::String(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &bytes,
    ));
    let truncated = serde_json::to_string(&value).unwrap();

    assert!(crypt
        .decrypt_with_context(&truncated, STRONG_PASSWORD, Some(&ctx))
        .await
        .is_err());
}

#[tokio::test]
async fn provider_rewrap_preserves_plaintext() {
    use ironcrypt::{
        ecc_utils,
        keys::{PrivateKey, PublicKey},
        CryptoProvider, LocalKeyProvider,
    };
    use std::sync::Arc;

    let (sk, pk) = ecc_utils::generate_ecc_keys().unwrap();
    let provider = Arc::new(
        LocalKeyProvider::new("v1", PublicKey::Ecc(pk), PrivateKey::Ecc(sk)).unwrap(),
    ) as Arc<dyn CryptoProvider>;

    let mut config = IronCryptConfig::default();
    config.asymmetric_algorithm = AsymmetricAlgorithm::Ecc;
    let crypt = IronCrypt::with_crypto_provider(
        config,
        DataType::Generic,
        provider,
        "unused".into(),
        "v1".into(),
    );

    let ctx = EncryptionContext::new("t", "p", "r");
    let enc = crypt
        .encrypt_with_context(b"pan-data", STRONG_PASSWORD, Some(&ctx))
        .await
        .unwrap();

    let rewrapped = crypt
        .rewrap_data(&enc, "v1", None, Some("v1"))
        .await
        .unwrap();

    let plain = crypt
        .decrypt_with_context(&rewrapped, STRONG_PASSWORD, Some(&ctx))
        .await
        .unwrap();
    assert_eq!(plain, b"pan-data");

    // Payload ciphertext field must be unchanged (DEK-only rewrap).
    let a: serde_json::Value = serde_json::from_str(&enc).unwrap();
    let b: serde_json::Value = serde_json::from_str(&rewrapped).unwrap();
    assert_eq!(a["ciphertext"], b["ciphertext"]);
    assert_eq!(a["nonce"], b["nonce"]);
}
