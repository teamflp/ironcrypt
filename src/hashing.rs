use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{self, Argon2, PasswordHasher};
use sha2::{Digest, Sha256};
use std::io;

/// Hashes a stream of data using SHA-256.
///
/// This function reads data from the provided reader in chunks and computes
/// a SHA-256 hash of the entire stream. It's memory-efficient as it doesn't
/// load the whole stream into memory.
///
/// # Arguments
///
/// * `reader` - A mutable reference to a type implementing `Read`, such as a `File` or `Cursor`.
///
/// # Returns
///
/// Returns a `Result` containing:
/// - `Ok(Vec<u8>)`: The 32-byte SHA-256 hash of the stream.
/// - `Err(std::io::Error)`: An I/O error if reading from the stream fails.
pub fn hash_stream<R: io::Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    io::copy(reader, &mut hasher).map(|_| hasher.finalize().to_vec())
}

/// Hashes a byte slice using SHA-256.
pub fn hash_bytes(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

/// Hashes a password with Argon2id.
///
/// This function takes a password as a string slice and hashes it
/// using the Argon2 algorithm, which is considered one of the most secure for password storage.
/// A random salt is generated for each hash to enhance security and ensure
/// that even two identical passwords will have different hashes.
///
/// # Arguments
///
/// * `password` - A reference to a string slice representing the password to be hashed.
///
/// # Returns
///
/// Returns a `Result` containing:
/// - `Ok(String)`: The hashed password encoded as a string on success.
/// - `Err(String)`: An error message detailing the reason for failure if hashing fails.
///
/// # Example
///
/// ```rust
/// use ironcrypt::hash_password;
///
/// let password = "MySecureP@ssw0rd";
/// match hash_password(password) {
///     Ok(hashed) => println!("Hashed password: {}", hashed),
///     Err(e) => println!("Error: {}", e),
/// }
/// ```
///
/// # Remarks
///
/// - The salt is automatically generated using `SaltString::generate` and is incorporated
///   into the final hash, making it ready for future verification.
/// - Use this function to securely store passwords in your database
///   by using the resulting hash instead of the plaintext password.
///
/// # Errors
///
/// The function may return an `Err` if:
/// - The salt generation or the hashing process fails.
/// - An internal error occurs during the call to `hash_password` from the Argon2 library.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("Error while hashing password: {e:?}"))
}
