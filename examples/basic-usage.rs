//! examples/basic-usage.rs
use ironcrypt::{IronCrypt, IronCryptConfig};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // 1. Configure IronCrypt
    let mut config = IronCryptConfig::default();
    config.rsa_key_size = 2048; // Example: Use 2048-bit keys
    config.argon2_memory_cost = 32768; // Lower memory cost for example

    // 2. Initialize IronCrypt
    // This will create the 'keys/' directory and 'private_key_v1.pem' / 'public_key_v1.pem' if they don't exist.
    let crypt = IronCrypt::new("keys", "v1", config)?;
    println!("IronCrypt initialized for key version 'v1'.");

    // 3. Define a password
    let password = "MySecurePassword123!";

    // 4. Encrypt the password
    // This hashes the password with Argon2 and encrypts it.
    // The result is a JSON string containing all necessary info.
    println!("Encrypting password...");
    let encrypted_json = crypt.encrypt_password(password)?;
    println!("Password encrypted successfully.");
    println!("Encrypted JSON: {}", encrypted_json);

    // 5. Verify the password
    println!("\nVerifying correct password...");
    let is_valid = crypt.verify_password(&encrypted_json, password)?;

    if is_valid {
        println!("Verification successful: The password is correct.");
    } else {
        println!("Verification failed: The password is NOT correct.");
    }

    // 6. Verify an incorrect password
    println!("\nVerifying incorrect password...");
    let is_valid_bad = crypt.verify_password(&encrypted_json, "WrongPassword!");

    match is_valid_bad {
        Err(e) => println!("Verification failed as expected: {}", e),
        Ok(_) => println!("Verification succeeded unexpectedly!"),
    }

    Ok(())
}
