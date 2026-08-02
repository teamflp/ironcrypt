#ifndef IRONCRYPT_H
#define IRONCRYPT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generates a new RSA key pair of the specified bit size.
 *
 * The generated keys are returned as PEM-encoded strings. The memory for these strings
 * is allocated by Rust and must be freed by the caller using `ironcrypt_free_string`.
 *
 * @param bits The number of bits for the RSA key (e.g., 2048, 4096).
 * @param private_key_pem A pointer that will be filled with the address of the
 *   null-terminated string containing the private key in PKCS#8 PEM format.
 * @param public_key_pem A pointer that will be filled with the address of the
 *   null-terminated string containing the public key in SubjectPublicKeyInfo PEM format.
 * @return 0 on success, -1 on failure.
 */
int32_t ironcrypt_generate_rsa_keys(
    uint32_t bits,
    char** private_key_pem,
    char** public_key_pem
);

/**
 * @brief Frees a C string that was allocated by the Rust library.
 *
 * This function should be called on any string pointer returned by other functions
 * in this library to prevent memory leaks.
 *
 * @param s A pointer to a null-terminated string that was allocated by Rust.
 */
void ironcrypt_free_string(char* s);

/**
 * @brief Encrypts a password using a public key according to the IronCrypt password workflow.
 *
 * @param password The plaintext password to encrypt.
 * @param public_key_pem The RSA public key in PEM format.
 * @param key_version A version string for the key used.
 * @param encrypted_output A pointer that will be filled with the address of the
 *   null-terminated string containing the encrypted JSON data.
 * @return 0 on success, -1 on error.
 */
int32_t ironcrypt_password_encrypt(
    const char* password,
    const char* public_key_pem,
    const char* key_version,
    char** encrypted_output
);

/**
 * @brief Verifies a password against an encrypted JSON payload.
 *
 * @param encrypted_json The encrypted JSON data from `ironcrypt_password_encrypt`.
 * @param password The plaintext password to verify.
 * @param private_key_pem The RSA private key in PEM format corresponding to the public key used for encryption.
 * @param passphrase The passphrase for the private key, or NULL if the key is not encrypted.
 * @return 1 if the password is valid, 0 if it is invalid, and -1 on error (e.g., parsing error, decryption failure).
 */
int32_t ironcrypt_password_verify(
    const char* encrypted_json,
    const char* password,
    const char* private_key_pem,
    const char* passphrase
);


#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRONCRYPT_H
