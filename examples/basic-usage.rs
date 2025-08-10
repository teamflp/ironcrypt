//! # IronCrypt Comprehensive Usage Example
//!
//! This example demonstrates a more complete workflow of using the `ironcrypt` library, including:
//! 1. Simulating a user database with a HashMap.
//! 2. Registering a user by encrypting their password and storing it.
//! 3. Verifying a user's password from the simulated database.
//! 4. Encrypting and decrypting a binary file.

use ironcrypt::{IronCrypt, IronCryptConfig, IronCryptError};
use std::collections::HashMap;
use std::fs;
use std::io::Write;

// A type alias for our simulated database (maps username to encrypted password data).
type UserDatabase = HashMap<String, String>;

fn main() {
    println!("--- Running IronCrypt Comprehensive Usage Example ---");

    if let Err(e) = run_example() {
        eprintln!("\nAn error occurred during the example run: {}", e);
        std::process::exit(1);
    }

    println!("\n--- Example finished successfully! ---");
}

fn run_example() -> Result<(), IronCryptError> {
    // === Setup ===
    let key_directory = "example_keys";
    let key_version = "v1";
    let config = IronCryptConfig::default();
    let crypt = IronCrypt::new(key_directory, key_version, config)?;
    let mut db: UserDatabase = HashMap::new();

    // === Part 1: Password Management with a Simulated Database ===
    println!("\n[Part 1: Password Management]");

    // 1. Register a new user "alice"
    let username = "alice";
    let password = "My$up3rS3cureP@ssw0rd!";
    println!("Registering user '{}'...", username);
    let encrypted_data_json = crypt.encrypt_password(password)?;
    db.insert(username.to_string(), encrypted_data_json);
    println!("User '{}' registered and password stored securely.", username);

    // 2. Verify the user with the correct password
    println!("\nAttempting to log in user '{}' with the correct password...", username);
    if let Some(stored_data) = db.get(username) {
        let is_valid = crypt.verify_password(stored_data, password)?;
        if is_valid {
            println!(" -> SUCCESS: Password verification successful for '{}'!", username);
        } else {
            println!(" -> FAILURE: Password verification failed for '{}'!", username);
            return Err(IronCryptError::InvalidPassword);
        }
    } else {
        println!(" -> FAILURE: User '{}' not found in database.", username);
        return Err(IronCryptError::DecryptionError("User not found".to_string()));
    }

    // 3. Verify with an incorrect password
    println!("\nAttempting to log in user '{}' with an incorrect password...", username);
    let wrong_password = "thisIsTheWrongPassword";
    if let Some(stored_data) = db.get(username) {
        match crypt.verify_password(stored_data, wrong_password) {
            Err(IronCryptError::InvalidPassword) => {
                println!(" -> SUCCESS: Verification with incorrect password failed as expected.");
            }
            _ => {
                 println!(" -> FAILURE: Verification with incorrect password unexpectedly succeeded or threw a different error.");
            }
        }
    }

    // === Part 2: File Encryption ===
    println!("\n[Part 2: File Encryption]");

    // 1. Create a dummy file to encrypt
    let file_to_encrypt = "secret_data.txt";
    let file_content = "This is some secret information that needs to be encrypted.";
    let mut file = fs::File::create(file_to_encrypt)?;
    file.write_all(file_content.as_bytes())?;
    println!("Created a dummy file '{}' with content: \"{}\"", file_to_encrypt, file_content);

    // 2. Encrypt the file's content
    let file_bytes = fs::read(file_to_encrypt)?;
    println!("\nEncrypting file content...");
    // For file encryption, we can pass an empty password if we don't need password-based key derivation for the file itself.
    let encrypted_file_json = crypt.encrypt_binary_data(&file_bytes, "")?;
    println!(" -> SUCCESS: File content encrypted.");

    // 3. Decrypt the file's content
    println!("\nDecrypting file content...");
    let decrypted_bytes = crypt.decrypt_binary_data(&encrypted_file_json, "")?;
    let decrypted_content = String::from_utf8(decrypted_bytes).expect("Failed to convert bytes to string");
    println!(" -> SUCCESS: File content decrypted.");

    // 4. Verify the content
    assert_eq!(file_content, decrypted_content);
    println!(" -> SUCCESS: Decrypted content matches the original content!");

    // === Cleanup ===
    // In a real application, you would not delete your keys or dummy files.
    println!("\nCleaning up generated files and keys...");
    fs::remove_file(file_to_encrypt)?;
    fs::remove_dir_all(key_directory)?;

    Ok(())
}
