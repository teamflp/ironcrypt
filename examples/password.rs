//! README: "Encrypting and Verifying a Password"
use ironcrypt::{config::KeyManagementConfig, DataType, IronCrypt, IronCryptConfig};
use std::collections::HashMap;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Use a temporary directory for keys to keep tests isolated.
    let temp_dir = tempfile::tempdir()?;
    let key_dir = temp_dir.path().to_str().unwrap();

    // 2. Configure IronCrypt to use the temporary directory.
    let mut config = IronCryptConfig::default();
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

    // 3. Initialize IronCrypt.
    let crypt = IronCrypt::new(config, DataType::Generic).await?;

    // 4. Encrypt a password.
    let password = "MySecurePassword123!";
    let encrypted_json = crypt.encrypt_password(password)?;
    println!("Encrypted password: {}", encrypted_json);

    // 5. Verify the password.
    let is_valid = crypt.verify_password(&encrypted_json, password)?;
    assert!(is_valid);
    println!("Password verification successful!");

    Ok(())
}
