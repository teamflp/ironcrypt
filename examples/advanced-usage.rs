//! Example: Advanced Library Usage
//! 
//! This example demonstrates various IronCrypt library features including:
//! - Key generation and saving
//! - Stream encryption and decryption
//! - Custom configuration
//! - Multi-recipient encryption

use ironcrypt::{generate_rsa_keys, save_keys_to_files};
use ironcrypt::{encrypt_stream, decrypt_stream, PrivateKey, PublicKey};
use ironcrypt::{PasswordCriteria, Argon2Config};
use ironcrypt::algorithms::SymmetricAlgorithm;
use ironcrypt::{IronCrypt, IronCryptConfig, DataType, config::KeyManagementConfig};
use ironcrypt::CryptoStandard;
use ironcrypt::algorithms::{SymmetricAlgorithm as SA, AsymmetricAlgorithm};
use std::collections::HashMap;
use std::io::Cursor;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("=== IronCrypt Library Examples ===\n");
    
    // Example 1: Key Generation and File Operations
    println!("1. Generating RSA keys...");
    let (private_key, public_key) = generate_rsa_keys(2048)?;
    
    // Save keys to temporary directory
    std::fs::create_dir_all("/tmp/example_keys")?;
    save_keys_to_files(
        &private_key,
        &public_key,
        "/tmp/example_keys/private_key.pem",
        "/tmp/example_keys/public_key.pem",
        None,
    )?;
    println!("   ✓ Keys generated and saved to /tmp/example_keys/");
    
    // Example 2: Stream Encryption/Decryption
    println!("\n2. Stream encryption/decryption...");
    let original_data = "This is confidential information that needs to be encrypted!";
    let mut source = Cursor::new(original_data.as_bytes());
    let mut encrypted_dest = Cursor::new(Vec::new());
    
    // Encrypt the stream
    let mut password = "SecurePassword123!".to_string();
    let pk_enum = PublicKey::Rsa(public_key.clone());
    let recipients = vec![(&pk_enum, "v1")];
    
    encrypt_stream(
        &mut source,
        &mut encrypted_dest,
        &mut password,
        recipients,
        None, // No signing key
        &PasswordCriteria::default(),
        Argon2Config::default(),
        true, // Hash password
        SymmetricAlgorithm::Aes256Gcm,
    )?;
    println!("   ✓ Data encrypted successfully");
    
    // Decrypt the stream
    encrypted_dest.set_position(0);
    let mut decrypted_dest = Cursor::new(Vec::new());
    let sk_enum = PrivateKey::Rsa(private_key);
    
    decrypt_stream(
        &mut encrypted_dest,
        &mut decrypted_dest,
        &sk_enum,
        "v1",
        "SecurePassword123!",
        None, // No signature verification
    )?;
    
    let decrypted_data = String::from_utf8(decrypted_dest.into_inner())?;
    println!("   ✓ Data decrypted successfully");
    println!("   Original:  '{}'", original_data);
    println!("   Decrypted: '{}'", decrypted_data);
    println!("   Match: {}", original_data == decrypted_data);
    
    // Example 3: Password Encryption with Custom Configuration
    println!("\n3. Password encryption with custom config...");
    
    // Create custom configuration
    let mut config = IronCryptConfig {
        standard: CryptoStandard::Custom,
        symmetric_algorithm: SA::ChaCha20Poly1305,
        asymmetric_algorithm: AsymmetricAlgorithm::Rsa,
        rsa_key_size: 2048,
        argon2_memory_cost: 32768, // 32 MiB for faster example
        argon2_time_cost: 2,
        argon2_parallelism: 1,
        password_criteria: PasswordCriteria {
            min_length: 12,
            max_length: Some(128),
            uppercase: Some(1),
            lowercase: Some(1),
            digits: Some(1),
            special_chars: Some(1),
            disallowed_patterns: vec!["password".to_string(), "123456".to_string()],
        },
        buffer_size: 4096,
        secrets: None,
        data_type_config: None,
        audit: None,
    };
    
    // Set up key management 
    let mut data_type_config = HashMap::new();
    data_type_config.insert(
        DataType::Generic,
        KeyManagementConfig {
            key_directory: "/tmp/example_keys".to_string(),
            key_version: "v1".to_string(),
            passphrase: None,
        },
    );
    config.data_type_config = Some(data_type_config);
    
    // Initialize IronCrypt
    let crypt = IronCrypt::new(config, DataType::Generic).await?;
    
    // Encrypt a password
    let test_password = "MyTestPassword123!";
    let encrypted_password = crypt.encrypt_password(test_password)?;
    println!("   ✓ Password encrypted with custom configuration");
    
    // Verify the password
    let is_valid = crypt.verify_password(&encrypted_password, test_password)?;
    println!("   ✓ Password verification: {}", if is_valid { "SUCCESS" } else { "FAILED" });
    
    // Test with wrong password
    let wrong_is_valid = crypt.verify_password(&encrypted_password, "WrongPassword")?;
    println!("   ✓ Wrong password verification: {}", if wrong_is_valid { "SUCCESS" } else { "FAILED" });
    
    println!("\n=== All examples completed successfully! ===");
    
    Ok(())
}