use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{self, Argon2, PasswordHasher};

/// Hashes a password with Argon2id.
/// Hashes a password using the Argon2 algorithm.
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
/// In this example, the password "MySecureP@ssw0rd" is hashed, and the result is displayed
/// if the operation is successful. In case of failure, an error message is displayed.
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
