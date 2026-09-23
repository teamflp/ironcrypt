//! Unit tests for CryptoProvider configuration (no live AWS/Vault calls).

use ironcrypt::config::{AwsKmsConfig, CryptoProviderConfig};
use ironcrypt::crypto_provider::validate_provider_config;
use ironcrypt::{IronCryptConfig, PaymentSecurityProfile};

#[test]
fn accepts_aws_kms_and_vault_transit() {
    let aws = CryptoProviderConfig {
        provider: "aws-kms".into(),
        aws_kms: Some(AwsKmsConfig {
            region: "eu-west-1".into(),
            default_key_id: "alias/ironcrypt".into(),
        }),
        ..Default::default()
    };
    assert!(validate_provider_config(&aws, true).is_ok());

    let vault = CryptoProviderConfig {
        provider: "vault-transit".into(),
        ..Default::default()
    };
    assert!(validate_provider_config(&vault, true).is_ok());

    let hsm = CryptoProviderConfig {
        provider: "hsm".into(),
        ..Default::default()
    };
    assert!(validate_provider_config(&hsm, true).is_ok());
}

#[test]
fn payment_rejects_local_provider() {
    let local = CryptoProviderConfig {
        provider: "local".into(),
        ..Default::default()
    };
    assert!(validate_provider_config(&local, true).is_err());
    assert!(validate_provider_config(&local, false).is_ok());
}

#[test]
fn payment_profile_validate_rejects_local_in_config() {
    let mut config = IronCryptConfig::default();
    PaymentSecurityProfile::apply(&mut config);
    config.crypto_provider = Some(CryptoProviderConfig {
        provider: "local".into(),
        ..Default::default()
    });
    assert!(PaymentSecurityProfile::validate(&config).is_err());
}

#[test]
fn aws_kms_config_deserializes_from_toml() {
    let toml = r#"
provider = "aws-kms"
[aws_kms]
region = "eu-west-1"
default_key_id = "alias/payment"
"#;
    let cfg: CryptoProviderConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.provider, "aws-kms");
    let kms = cfg.aws_kms.unwrap();
    assert_eq!(kms.region, "eu-west-1");
    assert_eq!(kms.default_key_id, "alias/payment");
}

#[test]
fn failover_list_deserializes_and_validates() {
    let toml = r#"
provider = "aws-kms"
[aws_kms]
region = "eu-west-1"
default_key_id = "alias/payment"

[[failover]]
provider = "azure-kms"
[failover.azure_kms]
vault_uri = "https://dr.vault.azure.net/"
default_key_name = "payment"
"#;
    let cfg: CryptoProviderConfig = toml::from_str(toml).unwrap();
    assert_eq!(cfg.failover.len(), 1);
    assert_eq!(cfg.failover[0].provider, "azure-kms");
    assert!(validate_provider_config(&cfg, true).is_ok());
}

#[test]
fn nested_failover_rejected() {
    let mut inner = CryptoProviderConfig {
        provider: "aws-kms".into(),
        aws_kms: Some(AwsKmsConfig {
            region: "eu-west-1".into(),
            default_key_id: "alias/a".into(),
        }),
        ..Default::default()
    };
    inner.failover.push(CryptoProviderConfig {
        provider: "azure-kms".into(),
        ..Default::default()
    });
    let outer = CryptoProviderConfig {
        provider: "aws-kms".into(),
        aws_kms: Some(AwsKmsConfig {
            region: "eu-west-1".into(),
            default_key_id: "alias/a".into(),
        }),
        failover: vec![inner],
        ..Default::default()
    };
    assert!(validate_provider_config(&outer, true).is_err());
}
