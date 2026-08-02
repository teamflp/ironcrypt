//! Same flow as `examples/password.rs` (kept for discoverability).
use ironcrypt::{config::KeyManagementConfig, DataType, IronCrypt, IronCryptConfig};
use std::collections::HashMap;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let temp_dir = tempfile::tempdir()?;
    let key_dir = temp_dir.path().to_str().unwrap();

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

    let crypt = IronCrypt::new(config, DataType::Generic).await?;
    println!("IronCrypt initialized for key version 'v1'.");

    let password = "MySecurePassword123!";
    println!("Encrypting password...");
    let encrypted_json = crypt.encrypt_password(password)?;
    println!("Password encrypted successfully.");

    println!("\nVerifying correct password...");
    assert!(crypt.verify_password(&encrypted_json, password)?);
    println!("Verification successful: The password is correct.");

    println!("\nVerifying incorrect password...");
    match crypt.verify_password(&encrypted_json, "WrongPassword!") {
        Err(e) => println!("Verification failed as expected: {}", e),
        Ok(true) => println!("Verification succeeded unexpectedly!"),
        Ok(false) => println!("Verification failed as expected (mismatch)."),
    }

    Ok(())
}
